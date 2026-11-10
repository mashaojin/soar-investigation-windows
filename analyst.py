from contextlib import closing
"""One isolated direct Gemma assessment per incident revision; Python owns evidence."""
import argparse
import http.client
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
from ollama_analyst import ollama_report, assessment_payload, make_prompt, validate_assessment
from assessment_providers import provider_report,freeze
from assessment_facts import VERSION, has_observations



def validate_report(text):
    if not isinstance(text, str) or len(text.encode()) > 4096:
        raise ValueError("Report missing or oversized")
    report = json.loads(text)
    if not isinstance(report, dict) or set(report) != {"verdict", "reason", "recommendations"}:
        raise ValueError("Invalid report schema")
    if not isinstance(report["verdict"],str) or report["verdict"] not in {"BENIGN", "SUSPICIOUS", "INSUFFICIENT_EVIDENCE"}:
        raise ValueError("Invalid verdict")
    if not isinstance(report["reason"], str) or not 1 <= len(report["reason"]) <= 400:
        raise ValueError("Invalid reason")
    recommendations = report["recommendations"]
    if not isinstance(recommendations, list) or len(recommendations) != 2 or any(
        not isinstance(item, str) or not 1 <= len(item) <= 200 for item in recommendations
    ):
        raise ValueError("Invalid recommendations")
    return report


def recover_interrupted_analyses(db_path):
    """Call only after the monitor's exclusive DB lock is held; never retry inference."""
    with closing(sqlite3.connect(db_path)) as db, db:
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'analyses','incidents'}<=tables: return 0
        rows=db.execute("SELECT incident_id,revision FROM analyses WHERE status='running'").fetchall()
        for incident,revision in rows:
            db.execute("UPDATE analyses SET status='manual_review',error=? WHERE incident_id=? AND revision=?",
                       ('Manual review required: prior worker interrupted. No automatic retry.',incident,revision))
            db.execute("UPDATE incidents SET status='manual_review' WHERE incident_id=? AND revision=?",(incident,revision))
        return len(rows)


def initialize(db_path):
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                incident_id TEXT NOT NULL, revision INTEGER NOT NULL,
                status TEXT NOT NULL, report TEXT, error TEXT, prompt_hash TEXT NOT NULL,
                metadata TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (incident_id, revision)
            );
        """)


def analyze_next(db_path, settings, *, now=None, runner=provider_report):
    now = now or datetime.now(timezone.utc)
    initialize(db_path)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute("""
            SELECT i.incident_id, i.revision, i.evidence, i.alert_count FROM incidents i
            LEFT JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
            WHERE a.incident_id IS NULL ORDER BY i.incident_id
        """).fetchall()
        chosen = None
        eligible = []
        for row in rows:
            evidence = json.loads(row[2])
            start = datetime.fromisoformat(evidence['window_start'])
            ready = start+timedelta(seconds=90)  # Historical minute incidents only.
            if evidence.get('correlation'):
                from ssh_correlation import ready_at
                ready = ready_at(evidence)
            if settings.get('ssh_enrichment') and evidence.get('signature_id') == 9001001:
                from ssh_live_investigation import ready_after
                try:
                    ready = ready_after(evidence, settings['approved_plans'])
                except (ValueError, KeyError, OSError, TypeError):
                    pass  # Claim once, then persist configuration failure below.
            if now >= ready:
                eligible.append((ready, start, row[0], row))
        if eligible:
            chosen = min(eligible, key=lambda item: item[:3])[3]
        if chosen is None:
            return {"status": "idle", "model_calls": 0}
        incident_id, revision, encoded, count = chosen
        evidence = json.loads(encoded)
        evidence["alert_count"] = count
        settings = dict(settings)
        settings['_provider_root']=str(Path(db_path).resolve().parent)
        settings['_incident_id']=incident_id
        settings['_incident_window_start']=evidence.get('window_start')
        if settings.get('lab_profile'):
            from lab_config import load_profile
            settings['lab_profile']=load_profile(settings,Path(db_path).resolve().parent)
        from experimental_assessment import qualification
        settings=freeze(settings)
        from provider_state import effective,stamp
        route=effective(settings)
        experiment=qualification(settings)
        from human_approved_live import authorization
        try:live_acceptance=authorization(settings)
        except ValueError:
            if route['selection_id']=='default':raise
            live_acceptance=dict(provider_reauthorization_required=True)
        prompt = json.dumps(evidence, sort_keys=True)
        digest = hashlib.sha256((prompt + json.dumps(settings.get("investigation"), sort_keys=True)).encode()).hexdigest()
        db.execute("INSERT INTO analyses(incident_id,revision,status,prompt_hash) VALUES(?,?,?,?)",
                   (incident_id, revision, "running", digest))
        db.commit()  # Claim revision before expensive analysis; concurrent workers cannot repeat it.
    status, report, error, metadata = "manual_review", None, None, None
    try:
        investigation = None
        if settings.get("ssh_enrichment") and evidence.get("signature_id") == 9001001:
            from ssh_live_investigation import prepare_live_job
            profile_args={}
            if settings.get('lab_profile'):
                from lab_config import load_profile
                profile_args['lab_profile']=load_profile(settings,Path(db_path).resolve().parent)
            _, investigation = prepare_live_job(incident_id, evidence, settings["approved_plans"],**profile_args)
            settings["investigation"] = investigation
        payload = assessment_payload(evidence, investigation)
        from advisory_report import FORMAT as ADVISORY_FORMAT, assessment_label, validate as validate_advisory
        advisory = (isinstance(settings.get('lab_profile'), dict)
                    and settings['lab_profile'].get('platform') == 'windows-hyperv'
                    and evidence.get('signature_id') == 9001001)
        settings['_advisory_report'] = advisory
        from experiment_store import active_instruction, python_context, rule_provenance
        prompt_version=active_instruction(Path(db_path).resolve().parent)
        knowledge, retrieval = {}, None
        if advisory and route['provider'] == 'ollama' and settings.get('attack_retrieval', True):
            from attack_knowledge import retrieve
            try:
                knowledge = retrieve(payload)
                if knowledge:
                    prompt = make_prompt(payload, instruction=prompt_version['text'], advisory=True,
                                         knowledge=knowledge)
                retrieval = {'status': 'included' if knowledge else 'no_match'}
            except (OSError, ValueError, KeyError, TypeError) as exc:
                knowledge = {}
                retrieval = {'status': 'unavailable', 'error': type(exc).__name__}
        if not knowledge:
            prompt = make_prompt(payload, instruction=prompt_version['text'], advisory=advisory)
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        prepared = {"engine": "ollama_direct", "assessment_version":VERSION,"assessment_data": payload,
                    "investigation": investigation, "request_count": 0, "request_attempts": 0,
                    "prompt_version":prompt_version,"python_context":python_context(),
                    "rule_provenance":rule_provenance(Path(db_path).resolve().parent,evidence)}
        prepared.update(experiment)
        prepared.update(live_acceptance)
        if retrieval is not None:
            prepared['attack_retrieval'] = retrieval
        if knowledge:
            prepared['assessment_knowledge'] = knowledge
        prepared.update(stamp(route))
        prepared['engine']=route['provider']+'_direct'
        if advisory:
            prepared['assessment_format'] = ADVISORY_FORMAT
        # Persist the immutable authorization/evidence snapshot before inference,
        # including failed/partial assessments. Legacy tool traces are untouched.
        with closing(sqlite3.connect(db_path)) as audit_db, audit_db:
            audit_db.execute("UPDATE analyses SET prompt_hash=?,metadata=? WHERE incident_id=? AND revision=?",
                             (digest, json.dumps(prepared), incident_id, revision))
        metadata = json.dumps(prepared)
        if investigation and not advisory:
            auth = investigation['authentication']
            if auth.get('coverage') not in ('complete_for_fixture', 'observed_window'):
                raise ValueError('Incomplete authentication coverage requires review before inference')
            if not has_observations(auth):
                raise ValueError('No authentication outcomes or protection observations; manual review before inference')
        prepared.update(request_count=None, request_attempts=1)
        metadata=json.dumps(prepared)
        with closing(sqlite3.connect(db_path)) as audit_db, audit_db:
            audit_db.execute("UPDATE analyses SET metadata=? WHERE incident_id=? AND revision=?",
                             (metadata,incident_id,revision))
        envelope = runner(prompt, settings)
        combined=dict(prepared, **{key: value for key, value in envelope.items() if key != "text"})
        combined.update(experiment)  # Trusted qualification cannot be cleared by response text/metadata.
        combined.update(live_acceptance)
        combined.update(stamp(route))
        metadata=json.dumps(combined)
        try:
            validated = (validate_advisory(envelope["text"], payload, knowledge=knowledge) if advisory else
                         validate_assessment(envelope["text"], payload, investigation))
            if investigation and not advisory:
                validated["scenario"] = "ssh_investigation"
                validated["coverage"] = investigation["authentication"]["coverage"]
            report = json.dumps(validated, sort_keys=True)
        except ValueError:
            metadata = json.dumps(dict(json.loads(metadata),
                                       rejected_output=str(envelope.get("text", ""))[:4096]))
            raise
        if advisory:
            status = "complete" if assessment_label(validated) == 'BENIGN' else "manual_review"
        else:
            status = "manual_review" if validated["verdict"] == "INSUFFICIENT_EVIDENCE" or validated.get('recommended_action')=='REQUEST_MORE_EVIDENCE' else "complete"
            if experiment:status='manual_review'
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.SubprocessError, http.client.HTTPException) as exc:
        error = ("Manual review required. No automatic retry. " + type(exc).__name__ + ": " + str(exc))[:3500]
    with closing(sqlite3.connect(db_path)) as db, db:
        current = db.execute("SELECT revision FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if current[0] != revision:
            status = "stale"
        db.execute("UPDATE analyses SET status=?,report=?,error=?,metadata=? WHERE incident_id=? AND revision=?",
                   (status, report, error, metadata, incident_id, revision))
        db.execute("UPDATE incidents SET status=? WHERE incident_id=? AND revision=?",
                   (status, incident_id, revision))
    return {"status": status, "incident_id": incident_id, "revision": revision}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--runtime", default=str(Path(__file__).with_name("runtime.ssh.live.local.json")))
    args = parser.parse_args()
    settings = json.loads(Path(args.runtime).read_text())
    print(json.dumps(analyze_next(args.db, settings), sort_keys=True))
