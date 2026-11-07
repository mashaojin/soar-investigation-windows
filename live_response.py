"""Guarded live worker. No Telegram polling; no model-generated commands."""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time

from response import initialize as response_initialize, audit, current_live_plan, canonical, fingerprint, refresh_requests
from assessment_facts import VERSION, has_observations, observed_claims, validate_claims


def validate_live_evidence(evidence, report, metadata, policy, now, *, reviewed=False):
    from experimental_assessment import experimental_metadata
    if policy.get('experimental_assessment') or experimental_metadata(metadata):
        raise ValueError('Experimental unverified AI cannot enter live response')
    from lab_config import load_profile
    lab=load_profile(policy)
    from provider_state import validate_binding
    route=validate_binding(metadata,policy)
    model_matches=metadata.get('engine')==route['provider']+'_direct' and metadata.get('model')==route['model']
    if policy.get('human_approved_live'):
        from human_approved_live import authorization
        authorization(policy,policy)
        if metadata.get('human_approved_live')!=policy['human_approved_live']:
            raise ValueError('Assessment is not bound to the current operator-accepted model activation')
    start=datetime.fromisoformat(evidence['window_start'].replace('Z','+00:00'))
    enabled=datetime.fromisoformat(policy['live_enabled_after'].replace('Z','+00:00'))
    if start.tzinfo is None or enabled.tzinfo is None or start<enabled or not 0<=now-start.timestamp()<=1800:
        raise ValueError('Live responses require a new incident after live-mode activation, under 30 minutes old')
    job=metadata.get('investigation',{}); auth=job.get('authentication',{})
    checks=auth.get('coverage_checks',{})
    if (not model_matches
        or job.get('origin')!='live_read_only' or auth.get('coverage')!='observed_window'
        or auth.get('limited') is not False
        or any(checks.get(k) is not True for k in ('query_not_limited','retained_entry_before_start','root_service_records','window_elapsed'))
        or auth.get('source_ip') not in policy['allowed_attacker_ips'] or auth.get('source_ip')!=evidence.get('source_ip') or auth.get('target_ip')!=lab['victim']['ip']
        or metadata.get('assessment_version')!=VERSION
        or type(auth.get('failed_password_count')) is not int or auth['failed_password_count']<0 or not has_observations(auth)
        or auth.get('successful_login_count')!=0 or 'plan' not in job.get('plan_evidence',{})):
        raise ValueError('Live response requires current scoped SSH observations and no successful logins')
    if reviewed:
        if not metadata.get('provider_binding'):
            raise ValueError('Live response requires the assessment provider binding')
        claims=observed_claims(job)
    else:
        if (report.get('verdict')!='SUSPICIOUS' or report.get('coverage')!='observed_window'
                or report.get('assessment_version')!=VERSION
                or report.get('recommended_action')!='REQUEST_BLOCK_APPROVAL'):
            raise ValueError('Structured response requires an evidence-checked block recommendation')
        claims=report.get('claims')
        validate_claims(claims,job)
    # A plan permits only its listed accounts; it does not exempt out-of-scope attempts.
    if job['plan_evidence']['plan'] is not None and not claims['unexpected_accounts']:
        raise ValueError('Matching approved plan without verified account-scope violation; report only')


def initialize(db):
    response_initialize(db)
    db.execute('''CREATE TABLE IF NOT EXISTS live_actions (
        request_id TEXT PRIMARY KEY, run_id TEXT UNIQUE NOT NULL, action_key TEXT NOT NULL,
        status TEXT NOT NULL, started_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        rollback_due_at REAL, result TEXT NOT NULL)''')


def save(db_path, request, status, result, now=None):
    now=int(time.time()) if now is None else now
    due=result.get('applied_state',{}).get('rollback_due_at')
    with closing(sqlite3.connect(db_path,timeout=10)) as db,db:
        previous=db.execute('SELECT status,result FROM live_actions WHERE request_id=?',(request,)).fetchone()
        if previous==(status,canonical(result)): return
        db.execute('UPDATE live_actions SET status=?,updated_at=?,rollback_due_at=?,result=? WHERE request_id=?',
                   (status,now,due,canonical(result),request))
        db.execute("UPDATE approval_requests SET status_notified=CASE WHEN status<>? THEN '' ELSE status_notified END,status=? WHERE request_id=?",(status,status,request))
        audit(db,request,status,'Guarded live response state updated; inspect live_actions result',now)


def claim(db_path,policy,identity,now=None):
    policy={'_provider_root':str(Path(db_path).resolve().parent), **policy}
    now=int(time.time()) if now is None else now
    with closing(sqlite3.connect(db_path,timeout=10)) as db,db:
        db.row_factory=sqlite3.Row; initialize(db); db.execute('BEGIN IMMEDIATE')
        refresh_requests(db,now)
        # An uncertain earlier dispatch must be reconciled before any new action.
        if db.execute("SELECT 1 FROM live_actions WHERE status NOT IN ('live_complete','live_failed') LIMIT 1").fetchone():
            return None
        rows=db.execute("SELECT * FROM approval_requests WHERE status='approved' AND bot_key=? ORDER BY created_at",(identity['bot_key'],)).fetchall()
        for row in rows:
            try:
                expected=current_live_plan(db,row,policy,now)
                if (row['approved_by']!=row['user_id'] or row['user_id']!=identity['user_id']
                    or row['chat_id']!=identity['chat_id'] or not row['plan']
                    or canonical(expected)!=row['plan'] or fingerprint(expected)!=row['plan_hash']):
                    raise ValueError('Exact action, policy or identity binding changed')
                # Fingerprint only the immutable firewall scope for cross-incident deduplication.
                key=fingerprint({k:expected[k] for k in ('source_ip','destination_ip','port','protocol','duration_seconds')})
                if db.execute('SELECT 1 FROM live_actions WHERE action_key=? AND started_at>?',(key,now-90)).fetchone():
                    db.execute("UPDATE approval_requests SET status='duplicate_action',status_notified='' WHERE request_id=?",(row['request_id'],))
                    continue
                run_id=secrets.token_hex(12)
                result={'run_id':run_id,'incident_id':row['incident_id'],'revision':row['revision'],'plan':expected}
                db.execute('INSERT INTO live_actions VALUES(?,?,?,?,?,?,NULL,?)',
                           (row['request_id'],run_id,key,'live_preparing',now,now,canonical(result)))
                db.execute("UPDATE approval_requests SET status='live_preparing',status_notified='' WHERE request_id=?",(row['request_id'],))
                audit(db,row['request_id'],'live_claimed','Single worker claimed approved live response',now)
                return dict(row),result
            except (ValueError,KeyError,TypeError):
                db.execute("UPDATE approval_requests SET status='policy_rejected',status_notified='' WHERE request_id=?",(row['request_id'],))
                audit(db,row['request_id'],'policy_rejected','Live final validation failed; no dispatch',now)
    return None


class LabExecutor:
    def __init__(self, source='192.168.64.4'):
        if source not in ('192.168.64.4','192.168.64.8'):
            raise ValueError('Unsupported lab client')
        self.source=source

    def probe(self):
        from live_lab import client_probe
        return client_probe(secrets.token_hex(12),self.source)

    def read(self,run_id):
        if not re.fullmatch('[0-9a-f]{24}',run_id): raise ValueError('Invalid guard ID')
        return self.remote("import json; from pathlib import Path; print(Path("+repr('/run/soc-lab-tests/'+run_id+'/state.json')+").read_text())")

    def remote(self,code):
        from live import ssh_command
        r=subprocess.run(ssh_command({'ssh_target':'victim@192.168.64.6'},code),capture_output=True,text=True,timeout=15,check=True)
        if len(r.stdout)>65536: raise ValueError('Guard receipt too large')
        return json.loads(r.stdout)

    def management(self):
        return self.remote("import json,os; print(json.dumps({'reachable':True,'connection':os.environ.get('SSH_CONNECTION')}))")

    def dispatch(self,run_id):
        source=Path(__file__).with_name('live_lab_guard.py').read_text()
        subprocess.run(['/Applications/UTM.app/Contents/MacOS/utmctl','exec','Victim','--cmd','/usr/bin/python3','-c',source,run_id,self.source],
                       capture_output=True,timeout=15,check=True)


def executor_for(source,policy,recovery=False):
    from lab_config import load_profile
    if load_profile(policy)['platform']=='windows-hyperv':
        from windows_response import WindowsExecutor
        return WindowsExecutor(source,policy,recovery=recovery)
    return LabExecutor(source)


def verify_receipt(state,run_id,source='192.168.64.4',destination='192.168.64.6'):
    if (state.get('run_id')!=run_id or state.get('source')!=source
        or state.get('destination')!=destination or state.get('port')!=22 or state.get('duration_seconds')!=60):
        raise ValueError('Guest receipt does not match approved guard scope')
    tag='soc-lab-'+run_id
    if state.get('stage')=='rolled_back' and (not state.get('firewall_after') or tag in state['firewall_after']):
        raise ValueError('Guest receipt does not confirm tagged-rule removal')


def run_one(db_path,policy,identity,executor=None,*,wait=time.sleep):
    policy={'_provider_root':str(Path(db_path).resolve().parent), **policy}
    if policy['mode']!='live': return False
    work=claim(db_path,policy,identity)
    if work is None: return False
    row,result=work; request=row['request_id']; run_id=result['run_id']; source=result['plan']['source_ip']; executor=executor or executor_for(source,policy)
    dispatched=False
    try:
        result['baseline']=executor.probe()
        if result['baseline'].get('reachable') is not True or result['baseline'].get('actual_source')!=source:
            raise ValueError('Source baseline connectivity not verified; no dispatch')
        result['management_baseline']=executor.management()
        if result['management_baseline'].get('reachable') is not True:
            raise ValueError('Protected management access not verified before dispatch')
        # Revalidate immediately before the one irreversible dispatch boundary.
        with closing(sqlite3.connect(db_path,timeout=10)) as db:
            now=int(time.time())
            if now>=row['expires_at'] or canonical(current_live_plan(db,row,policy,now))!=row['plan']:
                raise ValueError('Approval expired or assessment changed; no dispatch')
        save(db_path,request,'live_executing',result)
        dispatched=True
        # Never resend after this point, even on timeout or restart.
        executor.dispatch(run_id)
        deadline=time.monotonic()+100
        blocked_checked=False
        while time.monotonic()<deadline:
            try: state=executor.read(run_id)
            except (OSError,ValueError,subprocess.SubprocessError):
                wait(2); continue
            verify_receipt(state,run_id,source,result['plan']['destination_ip'])
            if state['stage']=='applied' and not blocked_checked:
                result['applied_state']=state
                result['blocked_probe']=executor.probe()
                result['management_check']=executor.management()
                save(db_path,request,'live_blocked' if result['blocked_probe'].get('reachable') is False else 'live_executing',result)
                blocked_checked=True
            if state['stage']=='rolled_back':
                result['rollback_state']=state
                result['recovery_probe']=executor.probe()
                result['passed']=(blocked_checked and result['blocked_probe'].get('reachable') is False
                                  and result['management_check'].get('reachable') is True
                                  and result['recovery_probe'].get('reachable') is True
                                  and result['recovery_probe'].get('actual_source')==source)
                save(db_path,request,'live_complete' if result['passed'] else 'live_failed',result)
                return True
            if state['stage'] in ('apply_failed','rollback_failed'):
                raise RuntimeError('Guest guard reported '+state['stage'])
            wait(2)
        raise RuntimeError('Rollback not confirmed within verification deadline')
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,subprocess.SubprocessError) as exc:
        result['error']=str(exc)[:1500]
        save(db_path,request,'live_recovery_required' if dispatched else 'live_failed',result)
    return True


def reconcile(db_path,executor=None,policy=None):
    """After interruption, inspect victim state; never redispatch an action."""
    supplied_executor=executor
    with closing(sqlite3.connect(db_path,timeout=10)) as db,db:
        db.row_factory=sqlite3.Row; initialize(db)
        rows=db.execute("SELECT * FROM live_actions WHERE status NOT IN ('live_complete','live_failed')").fetchall()
    for row in rows:
        result=json.loads(row['result'])
        source=result['plan']['source_ip']
        executor=supplied_executor or executor_for(source,policy or {},recovery=True)
        try:
            if row['status']=='live_preparing':
                result['error']='Interrupted before dispatch; action not resumed'
                save(db_path,row['request_id'],'live_failed',result); continue
            state=executor.read(row['run_id']); verify_receipt(state,row['run_id'],source,result['plan']['destination_ip'])
            result['reconciled_state']=state
            if state['stage']=='rolled_back':
                result['recovery_probe']=executor.probe()
                # Missing in-block observations cannot be invented after restart.
                result['passed']=False
                result['note']='Rollback reconciled after interruption; full live verification incomplete'
                save(db_path,row['request_id'],'live_failed',result)
            else:
                save(db_path,row['request_id'],'live_recovery_required',result)
        except (OSError,ValueError,KeyError,RuntimeError,subprocess.SubprocessError) as exc:
            result['error']='Inspect victim guard state; no redispatch: '+str(exc)[:1000]
            save(db_path,row['request_id'],'live_recovery_required',result)
