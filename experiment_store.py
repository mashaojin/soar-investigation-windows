"""Versioned prompts and isolated saved-evidence experiments. No response imports."""
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import fcntl
import json
from pathlib import Path
import secrets
import sqlite3
import threading


def encode(value): return json.dumps(value,sort_keys=True,separators=(',',':'))
def sha(text): return hashlib.sha256(text.encode()).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat()


def validate_instruction(text):
    if not isinstance(text,str) or not 200 <= len(text.encode()) <= 12000 or '\x00' in text:
        raise ValueError('Use 200–12000 UTF-8 bytes of instruction text, without NUL characters.')
    return text


def python_context():
    from ssh_correlation import VERSION, WINDOW_SECONDS, ARRIVAL_SECONDS, PRE_ALERT_SECONDS
    root=Path(__file__).parent
    files=('incidents.py','ssh_correlation.py','ssh_live_investigation.py','ssh_auth_reader.py',
           'assessment_facts.py','ollama_analyst.py','analyst.py','response.py','live_response.py')
    hashes={name:sha((root/name).read_text()) for name in files}
    return dict(code_hash=sha(encode(hashes)),files=hashes,correlation_version=VERSION,
        unapproved_window_seconds=WINDOW_SECONDS,arrival_allowance_seconds=ARRIVAL_SECONDS,
        unapproved_pre_alert_context_seconds=PRE_ALERT_SECONDS,
        approved_evidence_scope='Entire approved plan only; no separate before/after evidence is currently collected.',
        classification='Gemma selects the verdict; Python supplies and checks facts.',
        safeguards='Structured schema and fact checks, coverage checks, source allowlist, operator approval, 60-second rollback.')


def initialize(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS prompts(
        id TEXT PRIMARY KEY,text TEXT NOT NULL,created_at TEXT NOT NULL,label TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS prompt_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS comparisons(id TEXT PRIMARY KEY,status TEXT NOT NULL,
        created_at TEXT NOT NULL,updated_at TEXT NOT NULL,snapshot TEXT NOT NULL,result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rule_cache(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rule_versions(hash TEXT PRIMARY KEY,revision INTEGER NOT NULL,text TEXT NOT NULL,activated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS rule_drafts(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,
        text TEXT NOT NULL,base_hash TEXT NOT NULL,token TEXT,status TEXT NOT NULL,result TEXT NOT NULL);''')
    from ollama_analyst import INSTRUCTION
    identifier=sha(INSTRUCTION)
    db.execute('INSERT OR IGNORE INTO prompts VALUES(?,?,?,?)',(identifier,INSTRUCTION,now(),'Default instruction'))
    db.execute('INSERT OR IGNORE INTO prompt_active VALUES(1,?)',(identifier,))


def active_instruction(root):
    """Read once per assessment; absence of editor storage preserves the default."""
    from ollama_analyst import INSTRUCTION
    path=Path(root)/'lab-experiments.sqlite3'
    if not path.exists(): return dict(id=sha(INSTRUCTION),text=INSTRUCTION,label='Default instruction')
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
        row=db.execute('SELECT p.id,p.text,p.label FROM prompts p JOIN prompt_active a ON a.id=p.id').fetchone()
    if not row: raise ValueError('Active prompt version unavailable; no fallback assessment')
    validate_instruction(row[1])
    if sha(row[1])!=row[0]: raise ValueError('Active prompt hash mismatch')
    return dict(zip(('id','text','label'),row))


def rule_provenance(root,evidence):
    provenance=dict(evidence.get('rule_provenance') or {})
    revisions=provenance.get('observed_revisions',[])
    path=Path(root)/'lab-experiments.sqlite3'
    known=[]
    if path.exists() and revisions:
        with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
            for rev in revisions:
                rows=db.execute('SELECT hash,text,activated_at FROM rule_versions WHERE revision=?',(rev,)).fetchall()
                event_time=datetime.fromisoformat(evidence['window_start'].replace('Z','+00:00')).timestamp()
                if len(rows)==1 and rows[0][2]<=event_time:
                    known.append(dict(revision=rev,hash=rows[0][0],text=rows[0][1],activated_at=rows[0][2]))
    provenance['captured_editor_versions']=known
    provenance['limitation']='Versions map EVE revisions to verified editor activations; external edits or missing historical hashes cannot be reconstructed.'
    return provenance


class ExperimentStore:
    def __init__(self,root,runner=None):
        self.root=Path(root); self.path=self.root/'lab-experiments.sqlite3'
        self.controller_lock=(self.root/'lab-experiments.lock').open('a')
        try: fcntl.flock(self.controller_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.controller_lock.close()
            raise RuntimeError('Another dashboard controls this experiment store') from None
        self.closed=False
        self.pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='saved-evidence')
        self.lock=threading.Lock(); self.runner=runner
        with closing(sqlite3.connect(self.path)) as db,db:
            initialize(db)
            db.execute("UPDATE comparisons SET status='interrupted',updated_at=? WHERE status IN ('queued','running')",(now(),))

    def state(self):
        from provider_state import effective
        from lab_config import runtime_settings
        configured=effective(runtime_settings(self.root));options={k:configured[k] for k in ('num_ctx','num_predict')}
        with closing(sqlite3.connect(self.path)) as db:
            prompts=[dict(id=i,text=t,created_at=c,label=l) for i,t,c,l in db.execute('SELECT * FROM prompts ORDER BY created_at DESC LIMIT 50')]
            jobs=[dict(id=i,status=s,created_at=c,result=json.loads(r)) for i,s,c,r in db.execute('SELECT id,status,created_at,result FROM comparisons ORDER BY created_at DESC LIMIT 20')]
            cached=db.execute('SELECT value FROM rule_cache').fetchone()
        from report_language import present_report
        for job in jobs:
            for arm in job['result'].get('arms',[]):
                arm['display_report']=present_report(arm.get('report'))
        return dict(active=active_instruction(self.root),prompts=prompts,comparisons=jobs,
            python=python_context(),model=dict(name=configured['model'],options=options),
            rule=json.loads(cached[0]) if cached else None,
            provider=__import__('provider_service').ProviderService(self.root).state())

    def save_prompt(self,values):
        if not isinstance(values,dict) or set(values)!={'text','label'}: raise ValueError('Supply prompt text and version label.')
        text=validate_instruction(values['text']); label=values['label']
        if not isinstance(label,str) or not 1<=len(label.strip())<=80: raise ValueError('Use a version label of 1–80 characters.')
        # Reject a prompt that already exceeds the budget with the selected/latest evidence.
        from ollama_analyst import make_prompt
        samples=self.saved_samples()
        if samples: make_prompt(samples[0]['payload'],instruction=text)
        i=sha(text)
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('INSERT OR IGNORE INTO prompts VALUES(?,?,?,?)',(i,text,now(),label.strip()))
        return dict(id=i,status='saved',note='Saved version only; live instruction is unchanged until Activate.')

    def activate(self,values):
        if not isinstance(values,dict) or set(values)!={'id','expected_active'}: raise ValueError('Activate a saved version against the current active version.')
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT id FROM prompt_active').fetchone()[0]
            if values['expected_active']!=current: raise ValueError('Active prompt changed. Refresh and review again.')
            row=db.execute('SELECT text FROM prompts WHERE id=?',(values['id'],)).fetchone()
            if not row: raise ValueError('Saved prompt not found.')
            validate_instruction(row[0]);db.execute('UPDATE prompt_active SET id=?',(values['id'],))
        return dict(active=active_instruction(self.root),note='Applies to new assessment requests. In-flight and historical assessments keep their original prompt.')

    def saved_samples(self):
        path=self.root/'ssh-live.sqlite3'
        if not path.exists(): return []
        with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
            rows=db.execute('''SELECT i.incident_id,i.revision,i.evidence,a.metadata,a.prompt_hash,a.report
                FROM incidents i JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
                ORDER BY i.rowid DESC LIMIT 50''').fetchall()
        samples=[]
        for i,rev,e,m,h,r in rows:
            m=json.loads(m or '{}');payload=m.get('assessment_data');job=m.get('investigation')
            if not payload or not job or job.get('kind')!='ssh': continue
            samples.append(dict(incident_id=i,revision=rev,evidence=json.loads(e),payload=payload,
                                investigation=job,metadata=m,original_prompt_hash=h,original_report=json.loads(r or 'null')))
        return samples

    def start_comparison(self,values):
        if not isinstance(values,dict) or set(values)!={'incident_id','prompt_id'}: raise ValueError('Choose a saved incident and candidate prompt version.')
        from ollama_analyst import INSTRUCTION,make_prompt
        from assessment_providers import freeze
        from provider_state import effective
        from lab_config import runtime_settings
        settings=freeze(runtime_settings(self.root));configured=effective(settings);options={k:configured[k] for k in ('num_ctx','num_predict')}
        settings['_advisory_report'] = settings['lab_profile']['platform'] == 'windows-hyperv'
        if configured['provider']=='gemini':
            from gemini_provider import api_key,access
            access(configured,api_key(configured.get('_root')),False)
        sample=next((s for s in self.saved_samples() if s['incident_id']==values['incident_id']),None)
        if sample is None: raise ValueError('No complete saved SSH evidence snapshot for this incident.')
        with closing(sqlite3.connect(self.path)) as db:
            row=db.execute('SELECT text,label FROM prompts WHERE id=?',(values['prompt_id'],)).fetchone()
        if row is None: raise ValueError('Candidate prompt version not found.')
        baseline=sample['metadata'].get('prompt_version') or dict(id=sha(INSTRUCTION),text=INSTRUCTION,label='Original default')
        original_advisory = sample['metadata'].get('assessment_format') == 'advisory_text'
        original = make_prompt(sample['payload'],instruction=baseline['text'],advisory=original_advisory)
        original_hash = sample['original_prompt_hash']
        if original_advisory and sha(original)!=original_hash:
            original = make_prompt(sample['payload'],instruction=baseline['text'],advisory=True,advisory_routing=False)
        if sha(original)!=original_hash:
            raise ValueError('The original instruction cannot be reconstructed exactly; use an incident with recorded prompt provenance.')
        make_prompt(sample['payload'],instruction=row[0],advisory=settings['_advisory_report'])
        snapshot=dict(sample,baseline=baseline,candidate=dict(id=values['prompt_id'],text=row[0],label=row[1]),
                      evidence_hash=sha(encode(sample['payload'])),python=python_context(),model=configured['model'],options=options,
                      model_settings=settings,
                      rule_provenance=sample['metadata'].get('rule_provenance',{'status':'Historical rule hash unavailable; original alert signature/revision only.'}))
        i=secrets.token_hex(12)
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT count(*) FROM comparisons WHERE status IN ('queued','running')").fetchone()[0]>=3:
                raise ValueError('Comparison queue is full (three jobs). Wait for a result.')
            db.execute('INSERT INTO comparisons VALUES(?,?,?,?,?,?)',(i,'queued',now(),now(),encode(snapshot),encode({})))
        self.pool.submit(self.run_comparison,i)
        return dict(id=i,status='queued',note='Two fresh model calls on the same saved evidence. No Telegram or response actions.')

    def run_comparison(self,identifier):
        from ollama_analyst import make_prompt,validate_assessment
        from advisory_report import validate as validate_advisory
        from assessment_providers import provider_report
        # One comparison at a time, additionally serialized with production inference.
        with closing(sqlite3.connect(self.path)) as db,db:
            snapshot=json.loads(db.execute('SELECT snapshot FROM comparisons WHERE id=?',(identifier,)).fetchone()[0])
            db.execute("UPDATE comparisons SET status='running',updated_at=? WHERE id=?",(now(),identifier))
        results=dict(evidence_hash=snapshot['evidence_hash'],incident_id=snapshot['incident_id'],revision=snapshot['revision'],
            python=snapshot['python'],original_python=snapshot['metadata'].get('python_context',{'status':'Historical code/settings snapshot unavailable'}),model=snapshot['model'],options=snapshot['options'],rule_provenance=snapshot['rule_provenance'],
            original_report=snapshot['original_report'],responses_disabled=True,arms=[])
        try:
            advisory = snapshot.get('model_settings', {}).get('_advisory_report') is True
            for name in ('baseline','candidate'):
                prompt=make_prompt(snapshot['payload'],instruction=snapshot[name]['text'],advisory=advisory)
                arm=dict(name=name,prompt_id=snapshot[name]['id'],prompt_label=snapshot[name]['label'])
                try:
                    envelope=(self.runner or provider_report)(prompt,dict(snapshot.get('model_settings',{}),investigation=snapshot['investigation']))
                    arm['raw_output']=envelope['text']
                    arm['metadata']={k:v for k,v in envelope.items() if k!='text'}
                    arm['report'] = (validate_advisory(envelope['text'],snapshot['payload']) if advisory else
                                     validate_assessment(envelope['text'],snapshot['payload'],snapshot['investigation']))
                    arm['status']='valid'
                except Exception as exc:
                    arm.update(status='invalid_or_failed',error=type(exc).__name__+': '+str(exc)[:1500])
                results['arms'].append(arm)
                with closing(sqlite3.connect(self.path)) as db,db:
                    db.execute('UPDATE comparisons SET result=?,updated_at=? WHERE id=?',(encode(results),now(),identifier))
            status='complete' if all(a['status']=='valid' for a in results['arms']) else 'needs_review'
        except Exception as exc:
            results['error']=type(exc).__name__+': '+str(exc)[:1500];status='needs_review'
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('UPDATE comparisons SET status=?,result=?,updated_at=? WHERE id=?',(status,encode(results),now(),identifier))

    def close(self):
        if self.closed: return
        self.closed=True
        self.pool.shutdown(wait=True,cancel_futures=True)
        self.controller_lock.close()
