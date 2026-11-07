"""Single Telegram decision handler; execution is delegated to bounded workers."""
import argparse
from contextlib import closing
from incident_labels import header as incident_header,display as incident_display,time_display as incident_time_display,attach as attach_incident_label
from datetime import datetime, timezone
import hashlib
from html import escape
import ipaddress
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time

from telegram_client import TelegramClient, TelegramError, bot_lock, load_credentials
from assessment_facts import VERSION
from report_language import present_report
from advisory_report import FORMAT as ADVISORY_FORMAT, assessment_label


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def initialize(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS approval_requests (
            request_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, revision INTEGER NOT NULL,
            report TEXT NOT NULL, plan TEXT, plan_hash TEXT, status TEXT NOT NULL,
            bot_key TEXT NOT NULL, chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            message_id INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            approved_by INTEGER, UNIQUE(incident_id,revision)
        );
        CREATE TABLE IF NOT EXISTS response_audit (
            request_id TEXT, kind TEXT NOT NULL, detail TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS telegram_offsets (
            bot_key TEXT PRIMARY KEY, next_update INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS telegram_updates (
            bot_key TEXT NOT NULL, update_id INTEGER NOT NULL, outcome TEXT NOT NULL,
            PRIMARY KEY(bot_key,update_id)
        );
        CREATE TABLE IF NOT EXISTS dry_run_actions (
            request_id TEXT PRIMARY KEY, action_key TEXT NOT NULL,
            plan TEXT NOT NULL, recorded_at INTEGER NOT NULL, valid_until INTEGER NOT NULL
        );
    """)
    columns={r[1] for r in db.execute('PRAGMA table_info(approval_requests)')}
    if 'context' not in columns:
        db.execute('ALTER TABLE approval_requests ADD COLUMN context TEXT')
    if 'status_notified' not in columns:
        # Completed historical messages are not rewritten on deployment.
        db.execute("ALTER TABLE approval_requests ADD COLUMN status_notified TEXT NOT NULL DEFAULT 'legacy'")


def audit(db, request_id, kind, detail, now):
    db.execute("INSERT INTO response_audit VALUES(?,?,?,?)",
               (request_id, kind, detail, now))


def plan_for(evidence, policy):
    if policy.get('experimental_assessment'):
        raise ValueError('Experimental AI requires human review; response plans are disabled')
    if policy["mode"] not in ('dry_run', 'live'):
        raise ValueError("Unsupported response mode")
    source = str(ipaddress.ip_address(evidence["source_ip"]))
    destination = str(ipaddress.ip_address(evidence["destination_ip"]))
    if source in policy["protected_ips"] or source == destination:
        raise ValueError("Protected or victim address")
    if source not in policy["allowed_attacker_ips"]:
        raise ValueError("Source is outside the explicitly permitted lab targets")
    if (destination != policy["victim_ip"] or evidence["destination_port"] != 22
            or policy["destination_port"] != 22 or evidence["signature_id"] != 9001001):
        raise ValueError("Incident does not match the SSH lab response policy")
    duration = policy["duration_seconds"]
    if type(duration) is not int or not 1 <= duration <= 3600:
        raise ValueError("Invalid proposed block duration")
    if policy['mode']=='live':
        from lab_config import load_profile,sources
        lab=load_profile(policy)
        if lab['platform']=='windows-hyperv':
            from windows_response import check_policy
            check_policy(policy,lab)
        if source not in sources(lab) or destination!=lab['victim']['ip'] or duration!=60:
            raise ValueError('Live guard supports only the explicitly allowed SSH lab clients and 60-second rollback')
    rule = ["deny", "from", source, "to", destination, "port", "22", "proto", "tcp"]
    if policy['mode']=='live' and lab['platform']=='windows-hyperv':
        return dict(mode='live',source_ip=source,destination_ip=destination,port=22,protocol='tcp',duration_seconds=60,
                    transport='windows-ssh-helper',helper_config_hash=policy['windows_response']['config_hash'],
                    helper_hash=policy['windows_response']['helper_hash'],apply_operation='apply',rollback_operation='rollback')
    return {"mode": policy['mode'], "source_ip": source, "destination_ip": destination,
            "port": 22, "protocol": "tcp", "duration_seconds": duration,
            "apply_argv": ["sudo", "-n", "/usr/sbin/ufw", "insert", "1"] + rule,
            "rollback_argv": ["sudo", "-n", "/usr/sbin/ufw", "--force", "delete"] + rule}


def bound_plan(evidence, report, metadata, policy, now):
    if report.get('format') == 'advisory_text':
        raise ValueError('Advisory reports cannot authorize a response plan')
    from experimental_assessment import experimental_metadata
    if experimental_metadata(metadata):raise ValueError('Unverified experimental assessment cannot authorize a response plan')
    from provider_state import effective,validate_binding
    if effective(policy)['selection_id']!='default' or metadata.get('provider_binding'):
        validate_binding(metadata,policy)
    plan=plan_for(evidence,policy)
    if policy['mode']=='live':
        from live_response import validate_live_evidence
        validate_live_evidence(evidence,report,metadata,policy,now)
        plan['assessment_hash']=fingerprint(dict(evidence=evidence,report=report,metadata=metadata))
        plan['live_enabled_after']=policy['live_enabled_after']
    return plan


def evidence_context(metadata, evidence):
    """Snapshot facts from successful scoped tools, never from model prose."""
    context={'source_ip':evidence.get('source_ip'), 'target_ip':evidence.get('destination_ip'),
             'target_port':evidence.get('destination_port')}
    try:
        saved=json.loads(metadata or '{}')
        from experimental_assessment import experimental_metadata
        if experimental_metadata(saved):context['model_qualification']='experimental_unverified'
        if saved.get('human_approved_live'):context['model_qualification']='operator_accepted_unqualified'
        traces=saved.get('tool_trace',[])
        direct=saved.get('investigation')
        if saved.get('engine') in ('ollama_direct','gemini_direct') and direct:
            traces=[{'tool':'get_ssh_auth_summary','result':direct['authentication']},
                    {'tool':'get_approved_test_plan','result':direct['plan_evidence']}]
        for call in traces:
            result=call.get('result',{})
            if call.get('tool')=='get_ssh_auth_summary':
                failures=result.get('failed_password_count')
                accounts=result.get('failed_accounts')
                successes=result.get('successful_login_count')
                if (result.get('source_ip')==context['source_ip']
                        and result.get('target_ip')==context['target_ip']
                        and type(failures) is int and failures>=0
                        and type(successes) is int and successes>=0
                        and isinstance(accounts,dict) and len(accounts)<=32
                        and all(isinstance(k,str) and len(k)<=64 and type(v) is int and v>=0 for k,v in accounts.items())
                        and sum(accounts.values())==failures):
                    context.update(failed_password_count=failures, failed_accounts=accounts,
                                   successful_login_count=successes, coverage=result.get('coverage'))
            elif call.get('tool')=='get_approved_test_plan' and 'plan' in result:
                context['matching_plan']=result['plan'] is not None
                context['unexpected_accounts']=result.get('scope_comparison',{}).get('unexpected_accounts',[])
                if result['plan'] is not None:
                    context['plan_id']=result['plan'].get('id')
    except (ValueError,TypeError,AttributeError):
        pass  # Missing evidence is stated as unavailable, never invented.
    return context


def queue_reports(db_path, policy, identity, *, now=None):
    now = int(time.time()) if now is None else now
    if policy["mode"] not in ('dry_run','live'):
        raise ValueError("Unsupported response mode")
    ttl = policy["approval_ttl_seconds"]
    if type(ttl) is not int or not 30 <= ttl <= 3600:
        raise ValueError("Approval TTL must be 30–3600 seconds")
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        initialize(db)
        db.execute("BEGIN IMMEDIATE")
        for request,encoded in db.execute("SELECT request_id,plan FROM approval_requests WHERE status IN ('queued','sending','pending','approved') AND plan IS NOT NULL").fetchall():
            saved=json.loads(encoded)
            if saved.get('mode')!=policy['mode'] or (policy['mode']=='live' and saved.get('live_enabled_after')!=policy.get('live_enabled_after')):
                db.execute("UPDATE approval_requests SET status='stale',status_notified='' WHERE request_id=?",(request,))
                audit(db,request,'stale','Response mode or activation changed; a new incident-bound approval is required',now)
        metadata='a.metadata' if any(r[1]=='metadata' for r in db.execute('PRAGMA table_info(analyses)')) else 'NULL'
        rows = db.execute("""SELECT i.incident_id,i.revision,i.evidence,a.report,"""+metadata+"""
            FROM incidents i JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
            LEFT JOIN approval_requests r ON r.incident_id=i.incident_id AND r.revision=i.revision
            WHERE ((a.status='complete' AND i.status='complete') OR
                   (a.status='manual_review' AND i.status='manual_review' AND a.report IS NOT NULL
                    AND json_extract("""+metadata+""",'$.assessment_version')=?))
            AND (json_extract(a.report,'$.format') IS NOT 'advisory_text' OR a.status='complete')
            AND r.request_id IS NULL""",(VERSION,)).fetchall()
        queued = 0
        for incident, revision, evidence, report, metadata in rows:
            parsed=json.loads(report)
            advisory_only = parsed.get('format') == ADVISORY_FORMAT
            if advisory_only and assessment_label(parsed) != 'BENIGN': continue
            if not advisory_only and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='human_reviews'").fetchone():
                from human_review import attach,load_incident
                reviewed=attach(db,load_incident(db,incident))['human_review']
                if reviewed and reviewed['conclusion']!='NEEDS_MORE_EVIDENCE': continue
            request_id = secrets.token_hex(12)
            plan = None
            wants_response=parsed.get('assessment_version')!=VERSION or parsed.get('recommended_action')=='REQUEST_BLOCK_APPROVAL'
            if not advisory_only and parsed["verdict"] == "SUSPICIOUS" and wants_response and json.loads(evidence).get("scenario") != "dvwa_sqli":
                try:
                    plan = bound_plan(json.loads(evidence),json.loads(report),json.loads(metadata or '{}'),policy,now)
                except (ValueError, KeyError, TypeError) as exc:
                    audit(db, request_id, "policy_rejected", str(exc), now)
            db.execute("""INSERT INTO approval_requests
                (request_id,incident_id,revision,report,plan,plan_hash,status,bot_key,chat_id,user_id,created_at,expires_at,context,status_notified)
                VALUES(?,?,?,?,?,?,'queued',?,?,?,?,?,?,'')""",
                (request_id, incident, revision, report, canonical(plan) if plan else None,
                 fingerprint(plan) if plan else None, identity["bot_key"], identity["chat_id"],
                 identity["user_id"], now, now + ttl,
                 canonical(evidence_context(metadata,json.loads(evidence)))))
            queued += 1
        return queued


def refresh_requests(db, now):
    stale=db.execute("""SELECT request_id FROM approval_requests
        WHERE status IN ('queued','sending','pending','approved') AND NOT EXISTS
        (SELECT 1 FROM incidents i JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
         WHERE i.incident_id=approval_requests.incident_id AND i.revision=approval_requests.revision
         AND ((approval_requests.plan IS NOT NULL AND a.status='complete' AND i.status='complete')
              OR (approval_requests.plan IS NULL AND a.report IS NOT NULL AND a.status IN ('complete','manual_review')
                  AND i.status IN ('complete','manual_review'))))""").fetchall()
    for (request,) in stale:
        db.execute("UPDATE approval_requests SET status='stale',status_notified='' WHERE request_id=?",(request,))
        audit(db,request,'stale','Incident revision or analysis changed; no response executed',now)
    expired=db.execute("SELECT request_id FROM approval_requests WHERE status IN ('queued','sending','pending','approved') AND expires_at<=?",(now,)).fetchall()
    for (request,) in expired:
        db.execute("UPDATE approval_requests SET status='expired',status_notified='' WHERE request_id=?",(request,))
        audit(db,request,'expired','Approval window elapsed without response execution',now)


def verdict_display(verdict):
    icon={'SUSPICIOUS':'🔴','BENIGN':'🟢','INSUFFICIENT_EVIDENCE':'🟡'}.get(verdict,'🟡')
    return f'{icon} {verdict}'


def message_for(row):
    row=dict(row)
    experimental=json.loads(row.get('context') or '{}').get('model_qualification')=='experimental_unverified'
    report = present_report(json.loads(row["report"]))
    if report.get('format') == ADVISORY_FORMAT:
        prose = report['reason']
        return dict(chat_id=row['chat_id'], text='🟢 AI assessment: Benign — Report only\n'
                    +incident_header(row)+'No decision required.\n\n'
                    +prose[:600]+('…' if len(prose)>600 else ''))
    if row['plan'] and (report.get('scenario')=='ssh_investigation' or json.loads(row['plan']).get('mode')=='live'):
        return ssh_action_message(row,report)
    expiry = datetime.fromtimestamp(row["expires_at"], timezone.utc).isoformat()
    heading = "SOC LAB — DVWA REPORT ONLY" if report.get("scenario") == "dvwa_sqli" else "SOC LAB — EVIDENCE REVIEW" if report.get('recommended_action')=='REQUEST_MORE_EVIDENCE' else "SOC LAB — REPORT ONLY"
    text = (f"{heading}\n"+incident_header(row)+
            f"Request: {row['request_id']}\nVerdict: {verdict_display(report['verdict'])}\n")
    markup = None
    if row["plan"]:
        plan = json.loads(row["plan"])
        text += (f"Proposed simulation: deny {plan['source_ip']} → {plan['destination_ip']}:22/TCP "
                 f"for {plan['duration_seconds']} seconds.\nExpires: {expiry}\n"
                 "Approve records a simulation only. No firewall rules will change.\n")
        markup = {"inline_keyboard": [[
            {"text": "YES — Approve temporary block (dry run)", "callback_data": "soc5:a:" + row["request_id"]}], [
            {"text": "NO — Report only", "callback_data": "soc5:d:" + row["request_id"]}]]}
    else:
        text += "Report only — no action eligible under the lab policy.\n"
        if report.get('recommended_action')=='REQUEST_MORE_EVIDENCE':
            text += 'AI requests more evidence. No additional collection or firewall action runs automatically.\n'
    if not row['plan'] and (experimental or report.get('recommended_action')=='REQUEST_MORE_EVIDENCE' or report.get('verdict')=='INSUFFICIENT_EVIDENCE'):
        return dict(chat_id=row['chat_id'],text='🟡 Manual review needed on the dashboard.\n'
            +('Experimental AI — unverified; response actions disabled.\n' if experimental else '')
            +incident_header(row)
            +'Reason: '+report['reason']+'\nhttp://127.0.0.1:8765/#incident='+row['incident_id'])
    analyst_label = "AI explanation"
    text += f"\n{analyst_label}:\n{report['reason']}\n"
    if report.get('next_step'): text+='Suggested next step: '+report['next_step']+'\n'
    if report.get("outcome"):
        text += report["outcome"] + "\n"
    text += "\n".join("• " + item for item in report["recommendations"])
    closing=decision_text(row['status'])
    if closing and row['plan']:
        text+='\n\nStatus: '+closing
        markup={'inline_keyboard':[]}
    payload = {"chat_id": row["chat_id"], "text": text}
    if markup:
        payload["reply_markup"] = markup
    return payload


def decision_text(status):
    return {'dry_run_complete':'YES approved. Dry-run block recorded; no firewall command executed.',
            'denied':'NO selected. Report retained; no response action taken.',
            'expired':'Request expired without response execution. No action taken.',
            'stale':'Incident changed. This request is no longer valid; no action taken.',
            'policy_rejected':'Final response validation failed. No action taken.',
            'duplicate_action':'An equivalent response is already recorded; no duplicate action taken.',
            'live_preparing':'LIVE approved. Validating connectivity and preparing the guarded response.',
            'live_executing':'LIVE response dispatched once; waiting for the victim receipt.',
            'live_blocked':'LIVE SSH block verified. Ubuntu rollback timer is active.',
            'live_complete':'LIVE response complete. Temporary deny removed and source SSH connectivity restored.',
            'live_failed':'LIVE response failed verification. Inspect the dashboard response details.',
            'live_recovery_required':'LIVE response state needs operator review. Do not repeat the action.'}.get(status)


def ssh_action_message(row,report):
    plan=json.loads(row['plan'])
    live=plan.get('mode')=='live'
    context=json.loads(row['context'] or '{}')
    unapproved=context.get('matching_plan') is False and context.get('failed_password_count',0)>0
    title=('🚨 SSH test scope violation detected' if context.get('unexpected_accounts') else
           '🚨 Unapproved SSH activity detected' if unapproved else '🚨 Suspicious SSH activity detected')
    facts=[]
    if 'failed_password_count' in context:
        facts.append(str(context['failed_password_count'])+' failed logins')
        facts.append(str(context['successful_login_count'])+' successful logins')
    else:
        facts.append('SSH connection alert; authentication counts unavailable')
    if context.get('matching_plan') is False: facts.append('no matching approved test plan')
    elif context.get('matching_plan') is True: facts.append('matching plan: '+str(context.get('plan_id','available')))
    if context.get('unexpected_accounts'):
        facts.append('accounts outside approved scope: '+', '.join(context['unexpected_accounts']))
    minutes=plan['duration_seconds']/60
    duration=('1 minute' if minutes==1 else str(int(minutes))+' minutes' if minutes.is_integer() else str(plan['duration_seconds'])+' seconds')
    expiry=datetime.fromtimestamp(row['expires_at'],timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    text=(f'<b>{title}</b>\n\nSource: <code>{escape(plan["source_ip"])}</code>\n'
          f'Target: <code>{escape(plan["destination_ip"])}:{plan["port"]}</code>\n'
          f'Evidence: {escape("; ".join(facts))}\n')
    if context.get('failed_accounts'):
        text+='Failed accounts: '+escape(', '.join(f'{k}: {v}' for k,v in context['failed_accounts'].items()))+'\n'
    if context.get('model_qualification')=='operator_accepted_unqualified':
        text+='Model quality unqualified — operator accepted; verify the evidence before approving.\n'
    text+=(f'AI assessment: <b>{escape(verdict_display(report["verdict"]))}</b>\n\n'
           f'<b>Do you authorize blocking this source from accessing the victim’s SSH service for {duration}?</b>\n\n'
           + ('<b>LIVE FIREWALL ACTION — approval will automatically apply a real 60-second SSH block. Ubuntu arms rollback before applying the deny. Keep the victim running.</b>\n' if live else '<b>DRY RUN — approval records a simulation only. No firewall rules will change.</b>\n') +
           f'Incident: <code>{escape(incident_display(dict(row)))}</code> / revision {row["revision"]}\n'
           f'Incident time: {escape(incident_time_display(dict(row)))}\n'
           f'Request: <code>{escape(row["request_id"])}</code>\nApproval expires: {expiry}\n'
           'No response: request expires without taking action.\n'
           'The full incident report is retained in the dashboard.')
    if context.get('unexpected_accounts'):
        text+='\nThis source-IP block also interrupts permitted SSH testing from the same client for the stated duration.'
    closing=decision_text(row['status'])
    payload={'chat_id':row['chat_id'],'text':text,'parse_mode':'HTML'}
    if closing:
        payload['text']+='\n\n<b>Status:</b> '+escape(closing)
        payload['reply_markup']={'inline_keyboard':[]}
    else:
        payload['reply_markup']={'inline_keyboard':[
            [{'text':'YES — Approve LIVE 60s block' if live else 'YES — Approve temporary block (dry run)','callback_data':'soc5:a:'+row['request_id']}],
            [{'text':'NO — Deny block / report only','callback_data':'soc5:d:'+row['request_id']}]]}
    return payload


def deliver_one(db_path, client, identity, *, now=None):
    now = int(time.time()) if now is None else now
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        db.row_factory = sqlite3.Row
        initialize(db)
        from human_review import initialize as initialize_reviews,load_incident,attach,binding,timestamp,notification_message
        initialize_reviews(db)
        db.execute("BEGIN IMMEDIATE")
        refresh_requests(db, now)
        row = db.execute("SELECT * FROM approval_requests WHERE status='queued' AND bot_key=? ORDER BY created_at LIMIT 1",
                         (identity["bot_key"],)).fetchone()
        if row is None:
            return "idle"
        row=attach_incident_label(db,row)
        payload=message_for(row);review_notice=None
        report=json.loads(row['report'])
        experimental=json.loads(row['context'] or '{}').get('model_qualification')=='experimental_unverified'
        if not row['plan'] and (experimental or report.get('recommended_action')=='REQUEST_MORE_EVIDENCE' or report.get('verdict')=='INSUFFICIENT_EVIDENCE'):
            incident=attach(db,load_incident(db,row['incident_id']))
            if incident.get('analysis_status')=='manual_review':
                token=secrets.token_hex(12)
                db.execute("INSERT OR IGNORE INTO review_notifications VALUES(?,?,?,?,'queued',?,NULL,'Model requested manual review')",
                    (token,row['incident_id'],row['revision'],binding(incident),timestamp()))
                notice=db.execute('SELECT * FROM review_notifications WHERE incident_id=? AND revision=?',(row['incident_id'],row['revision'])).fetchone()
                if notice['status']=='queued' and notice['snapshot_hash']==binding(incident):
                    review_notice=notice['notification_id']
                    db.execute('INSERT OR REPLACE INTO review_choices VALUES(?,?,?,?,?,?,0)',
                        (review_notice,identity['bot_key'],identity['chat_id'],identity['user_id'],incident['review_context']['expected_review_id'],now+86400))
                    db.execute("UPDATE review_notifications SET status='sending' WHERE notification_id=?",(review_notice,))
                    payload=notification_message(incident,identity,review_notice)
        db.execute("UPDATE approval_requests SET status='sending' WHERE request_id=?", (row["request_id"],))
        db.commit()
    try:
        sent = client.call("sendMessage", payload)
        if type(sent.get("message_id")) is not int or sent.get("chat", {}).get("id") != row["chat_id"]:
            raise TelegramError("Delivery response does not match the request")
    except TelegramError:
        with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
            db.execute("UPDATE approval_requests SET status='delivery_unknown' WHERE request_id=? AND status='sending'",
                       (row["request_id"],))
            if review_notice:db.execute("UPDATE review_notifications SET status='delivery_unknown',detail='Uncertain send; no automatic resend' WHERE notification_id=?",(review_notice,))
            audit(db, row["request_id"], "delivery_unknown", "No automatic resend; operator review required", now)
        return "delivery_unknown"
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        db.execute("UPDATE approval_requests SET status=?,message_id=? WHERE request_id=? AND status='sending'",
                   ("pending" if row["plan"] else "notified", sent["message_id"], row["request_id"]))
        if review_notice:db.execute("UPDATE review_notifications SET status='sent',message_id=?,detail='Review notice delivered' WHERE notification_id=?",(sent['message_id'],review_notice))
        refresh_requests(db, now)
    return "sent"


def handle_update(db_path, update, identity, *, now=None):
    now = int(time.time()) if now is None else now
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        db.row_factory = sqlite3.Row
        initialize(db)
        from human_review import initialize as initialize_reviews,handle_review_callback
        initialize_reviews(db)
        db.execute("BEGIN IMMEDIATE")
        refresh_requests(db, now)
        update_id = update.get("update_id")
        if type(update_id) is not int:
            return "invalid_update"
        if db.execute("SELECT 1 FROM telegram_updates WHERE bot_key=? AND update_id=?",
                      (identity["bot_key"], update_id)).fetchone():
            return "duplicate_update"
        query = update.get("callback_query") or {}
        outcome = handle_review_callback(db,query,identity,now)
        match = re.fullmatch(r"soc5:([ad]):([0-9a-f]{24})", query.get("data", ""))
        if match:
            decision, request_id = match.groups()
            row = db.execute("SELECT * FROM approval_requests WHERE request_id=?", (request_id,)).fetchone()
            message = query.get("message") or {}
            if row is None:
                outcome = "unknown_request"
            elif (row["bot_key"] != identity["bot_key"] or row["chat_id"] != identity["chat_id"]
                  or row["user_id"] != identity["user_id"]
                  or query.get("from", {}).get("id") != row["user_id"]
                  or query.get("from", {}).get("is_bot", False)
                  or message.get("chat", {}).get("id") != row["chat_id"]
                  or message.get("chat", {}).get("type") != "private"
                  or message.get("message_id") != row["message_id"]):
                outcome = "unauthorized"
            elif row["status"] != "pending" or row["plan"] is None:
                outcome = "not_pending"
            else:
                outcome = "approved" if decision == "a" else "denied"
                db.execute("UPDATE approval_requests SET status=?,approved_by=?,status_notified='' WHERE request_id=?",
                           (outcome, row["user_id"] if decision == "a" else None, request_id))
            audit(db, request_id, "callback", outcome, now)
        db.execute("INSERT INTO telegram_updates VALUES(?,?,?)", (identity["bot_key"], update_id, outcome))
        db.execute("""INSERT INTO telegram_offsets VALUES(?,?) ON CONFLICT(bot_key)
                      DO UPDATE SET next_update=max(next_update,excluded.next_update)""",
                   (identity["bot_key"], update_id + 1))
        return outcome


def execute_dry_run(db_path, policy, *, now=None):
    now = int(time.time()) if now is None else now
    if policy["mode"] != "dry_run":
        raise ValueError("Live enforcement is not implemented")
    completed = 0
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        db.row_factory = sqlite3.Row
        initialize(db)
        db.execute("BEGIN IMMEDIATE")
        refresh_requests(db, now)
        for row in db.execute("SELECT * FROM approval_requests WHERE status='approved'").fetchall():
            evidence = db.execute("SELECT evidence FROM incidents WHERE incident_id=? AND revision=?",
                                  (row["incident_id"], row["revision"])).fetchone()
            try:
                current = db.execute("SELECT report FROM analyses WHERE incident_id=? AND revision=? AND status='complete'",
                                     (row["incident_id"], row["revision"])).fetchone()
                if current is None or current[0] != row["report"] or json.loads(current[0])["verdict"] != "SUSPICIOUS":
                    raise ValueError("Analyst report changed or no longer recommends review")
                expected = plan_for(json.loads(evidence[0]), policy)
                if (row["approved_by"] != row["user_id"] or not row["plan"]
                        or fingerprint(expected) != row["plan_hash"] or canonical(expected) != row["plan"]):
                    raise ValueError("Approval or exact action binding no longer valid")
                prior = db.execute("SELECT 1 FROM dry_run_actions WHERE action_key=? AND valid_until>?",
                                   (row["plan_hash"], now)).fetchone()
                state = "duplicate_action" if prior else "dry_run_complete"
                if not prior:
                    db.execute("INSERT INTO dry_run_actions VALUES(?,?,?,?,?)",
                               (row["request_id"], row["plan_hash"], row["plan"], now,
                                now + expected["duration_seconds"]))
                    completed += 1
                audit(db, row["request_id"], state, "Simulation recorded; no command was executed", now)
            except (ValueError, KeyError, TypeError):
                state = "policy_rejected"
                audit(db, row["request_id"], state, "Action failed final validation", now)
            db.execute("UPDATE approval_requests SET status=?,status_notified='' WHERE request_id=?", (state, row["request_id"]))
    return completed


def prime_updates(db_path, client, identity):
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        initialize(db)
        existing = db.execute("SELECT next_update FROM telegram_offsets WHERE bot_key=?",
                              (identity["bot_key"],)).fetchone()
    if existing:
        return
    updates = client.call("getUpdates", {"timeout": 0, "limit": 100,
                                         "allowed_updates": ["message", "callback_query"]})
    high = max((u["update_id"] for u in updates), default=-1) + 1
    with closing(sqlite3.connect(db_path, timeout=10)) as db, db:
        db.execute("INSERT OR IGNORE INTO telegram_offsets VALUES(?,?)", (identity["bot_key"], high))


def update_terminal_messages(db_path,client,identity,*,now=None):
    """Close buttons and show the outcome on the original incident message."""
    now=int(time.time()) if now is None else now
    statuses=('dry_run_complete','denied','expired','stale','policy_rejected','duplicate_action',
              'live_preparing','live_executing','live_blocked','live_complete','live_failed','live_recovery_required')
    with closing(sqlite3.connect(db_path,timeout=10)) as db, db:
        db.row_factory=sqlite3.Row
        initialize(db)
        db.execute('BEGIN IMMEDIATE')
        placeholders=','.join('?' for _ in statuses)
        rows=db.execute("SELECT * FROM approval_requests WHERE bot_key=? AND message_id IS NOT NULL AND plan IS NOT NULL AND status_notified='' AND status IN ("+placeholders+")",
                        (identity['bot_key'],*statuses)).fetchall()
        for row in rows:
            db.execute("UPDATE approval_requests SET status_notified='updating' WHERE request_id=?",(row['request_id'],))
    updated=0
    for row in rows:
        with closing(sqlite3.connect(db_path)) as label_db:row=attach_incident_label(label_db,row)
        payload=message_for(row)
        payload['message_id']=row['message_id']
        payload['reply_markup']={'inline_keyboard':[]}
        try:
            client.call('editMessageText',payload)
        except TelegramError:
            state='unknown'
        else:
            state=row['status'];updated+=1
        with closing(sqlite3.connect(db_path,timeout=10)) as db, db:
            db.execute('UPDATE approval_requests SET status_notified=? WHERE request_id=? AND status=?',
                       (state,row['request_id'],row['status']))
            audit(db,row['request_id'],'telegram_status_updated' if state!='unknown' else 'telegram_status_unknown',
                  row['status'] if state!='unknown' else 'No automatic resend of uncertain message edit',now)
    return updated


def tick(db_path, policy, client, identity):
    if policy.get("exclusive_polling_confirmed") is not True:
        raise ValueError("Confirm exclusive use of this bot before polling")
    prime_updates(db_path, client, identity)
    queued = queue_reports(db_path, policy, identity)
    delivery = deliver_one(db_path, client, identity)
    with closing(sqlite3.connect(db_path, timeout=10)) as db:
        offset = db.execute("SELECT next_update FROM telegram_offsets WHERE bot_key=?",
                            (identity["bot_key"],)).fetchone()[0]
    updates = client.call("getUpdates", {"offset": offset, "timeout": 0, "limit": 100,
                                         "allowed_updates": ["message", "callback_query"]})
    decisions = []
    for update in updates:
        outcome = handle_update(db_path, update, identity)
        if outcome != "ignored":
            decisions.append(outcome)
        query = update.get("callback_query") or {}
        if query.get("id"):
            try:
                client.call("answerCallbackQuery", {"callback_query_id": query["id"],
                    "text": {"approved":"YES recorded — see the incident response status", "denied":"NO recorded — report only", "review_benign":"Benign review saved — no firewall action", "review_suspicious":"Suspicious review saved — no firewall action", "review_needs_more_evidence":"More evidence needed — case remains open", "review_changed":"Incident or review changed — use dashboard", "review_expired":"Review buttons expired — use dashboard", "review_unavailable":"Review already recorded — see dashboard", "live_block_denied":"Block denied — report only. Human conclusion unchanged.", "live_block_unavailable":"Live block unavailable: review-only mode. Separate live setup and authorization required."}.get(outcome,"Request unavailable or invalid")})
            except TelegramError:
                pass
    actions = execute_dry_run(db_path, policy) if policy['mode']=='dry_run' else 0
    status_updates=update_terminal_messages(db_path,client,identity)
    from human_review import deliver_notifications
    review_notification=deliver_notifications(db_path,policy,client,identity)
    return dict(queued=queued, delivery=delivery, decisions=decisions, dry_run_actions=actions,
                telegram_status_updates=status_updates,review_notification=review_notification)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="response.local.json")
    parser.add_argument("--db", default="ssh-live.sqlite3")
    parser.add_argument("--check", action="store_true", help="Check Telegram identity only; no messages or polling")
    args = parser.parse_args()
    policy = json.loads(Path(args.config).read_text())
    credentials = load_credentials(policy)
    client = TelegramClient(credentials)
    if args.check:
        print(json.dumps(client.check()))
    else:
        with bot_lock(credentials.bot_key):
            client.check()
            print(json.dumps(tick(args.db, policy, client, credentials.identity)))
