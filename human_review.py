"""Append-only operator conclusions; no inference or firewall execution."""
from advisory_report import FORMAT as ADVISORY_FORMAT, assessment_label, is_report_only
from contextlib import closing
from datetime import datetime,timezone
import hashlib
from contextlib import nullcontext
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time

CONCLUSIONS={'BENIGN':'Benign / authorized activity','SUSPICIOUS':'Suspicious / unauthorized activity',
             'NEEDS_MORE_EVIDENCE':'Need more evidence — keep open'}

class ReviewConflict(ValueError): pass

def encode(value): return json.dumps(value,sort_keys=True,separators=(',',':'))
def timestamp(): return datetime.now(timezone.utc).isoformat()

def initialize(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS human_reviews(
        review_id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,revision INTEGER NOT NULL,
        snapshot_hash TEXT NOT NULL,reviewer TEXT NOT NULL,conclusion TEXT NOT NULL,
        notes TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS human_review_incident ON human_reviews(incident_id,revision);
        CREATE TRIGGER IF NOT EXISTS human_review_no_update BEFORE UPDATE ON human_reviews
          BEGIN SELECT RAISE(ABORT,'Human reviews are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS human_review_no_delete BEFORE DELETE ON human_reviews
          BEGIN SELECT RAISE(ABORT,'Human reviews are append-only'); END;
        CREATE TABLE IF NOT EXISTS review_notifications(
        notification_id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,revision INTEGER NOT NULL,
        snapshot_hash TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,
        message_id INTEGER,detail TEXT NOT NULL,UNIQUE(incident_id,revision));
        CREATE TABLE IF NOT EXISTS review_choices(
        notification_id TEXT PRIMARY KEY,bot_key TEXT NOT NULL,chat_id INTEGER NOT NULL,user_id INTEGER NOT NULL,
        expected_review_id TEXT,expires_at INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS review_response_decisions(
        notification_id TEXT PRIMARY KEY,decision TEXT NOT NULL,operator_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL);''')


def binding(incident):
    value={k:incident.get(k) for k in ('incident_id','revision','evidence','alert_count','analysis_status','report','metadata','error')}
    return hashlib.sha256(encode(value).encode()).hexdigest()


def load_incident(db,identifier):
    db.row_factory=sqlite3.Row
    columns={r[1] for r in db.execute('PRAGMA table_info(analyses)')}
    extra=','.join('a.'+name if name in columns else 'NULL AS '+name for name in ('error','metadata'))
    row=db.execute('''SELECT i.*,a.status AS analysis_status,a.report,'''+extra+'''
        FROM incidents i LEFT JOIN analyses a ON a.incident_id=i.incident_id AND a.revision=i.revision
        WHERE i.incident_id=?''',(identifier,)).fetchone()
    if not row: raise ValueError('Incident not found.')
    result=dict(row)
    for name in ('evidence','report','metadata'):
        result[name]=json.loads(result[name]) if result.get(name) else ({} if name!='report' else None)
    from incident_labels import attach as attach_label
    return attach_label(db,result)


def attach(db,incident,tables=None):
    tables=tables if tables is not None else {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    history=[];notice=None
    if 'human_reviews' in tables:
        db.row_factory=sqlite3.Row
        history=[dict(r) for r in db.execute('SELECT * FROM human_reviews WHERE incident_id=? ORDER BY rowid DESC LIMIT 30',(incident['incident_id'],))]
    if 'review_notifications' in tables:
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT notification_id,status,created_at,message_id FROM review_notifications WHERE incident_id=? AND revision=?',
                       (incident['incident_id'],incident['revision'])).fetchone()
        notice=dict(row) if row else None
    digest=binding(incident)
    current_rows=[r for r in history if r['revision']==incident['revision']]
    current=current_rows[0] if current_rows and current_rows[0]['snapshot_hash']==digest else None
    for r in history: r['applies_to_current_snapshot']=r['revision']==incident['revision'] and r['snapshot_hash']==digest
    incident['human_review']=current
    incident['human_review_history']=history
    report_only=is_report_only(incident.get('analysis_status'),incident.get('report'))
    incident['review_context']=dict(can_review=incident.get('analysis_status')=='manual_review' or report_only,
        review_optional=report_only,snapshot_hash=digest,
        expected_review_id=current_rows[0]['review_id'] if current_rows else None,
        notification=notice,conclusions=CONCLUSIONS)
    return incident


def check_snapshot(incident,values,*,allow_optional=False):
    if values['revision']!=incident['revision'] or values['snapshot_hash']!=binding(incident):
        raise ReviewConflict('Incident evidence or analysis changed. Refresh and review the current revision.')
    if incident.get('analysis_status')!='manual_review' and not (allow_optional and incident['review_context']['review_optional']):
        raise ValueError('This revision is not awaiting human review.')


class ReviewService:
    def __init__(self,root): self.path=Path(root)/'ssh-live.sqlite3'

    def connect(self):
        if not self.path.exists(): raise ValueError('Incident storage is unavailable.')
        return sqlite3.connect(self.path.resolve().as_uri()+'?mode=rw',uri=True,timeout=10)

    def save(self,values,*,connection=None):
        fields={'incident_id','revision','snapshot_hash','expected_review_id','reviewer','conclusion','notes'}
        if not isinstance(values,dict) or set(values)!=fields: raise ValueError('Complete the review fields for the exact incident revision.')
        validate_identity(values)
        if not isinstance(values['reviewer'],str) or not 1<=len(values['reviewer'].strip())<=80 or any(ord(c)<32 for c in values['reviewer']):
            raise ValueError('Enter a reviewer name (1–80 characters).')
        if not isinstance(values['notes'],str) or any(ord(c)<32 and c not in '\n\t' for c in values['notes']):
            raise ValueError('Review notes must be text without control characters.')
        if values['conclusion'] not in CONCLUSIONS: raise ValueError('Choose one of the displayed review conclusions.')
        with (closing(self.connect()) if connection is None else nullcontext(connection)) as db, (db if connection is None else nullcontext()):
            if connection is None: initialize(db);db.execute('BEGIN IMMEDIATE')
            incident=attach(db,load_incident(db,values['incident_id']))
            check_snapshot(incident,values,allow_optional=connection is None)
            if values['expected_review_id']!=incident['review_context']['expected_review_id']:
                raise ReviewConflict('Another review was saved. Refresh before adding a follow-up review.')
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'approval_requests' in tables and db.execute('''SELECT 1 FROM approval_requests WHERE incident_id=? AND revision=?
                AND plan IS NOT NULL AND status IN ('queued','sending','pending','approved','live_preparing','live_executing','live_blocked','live_recovery_required')''',
                (incident['incident_id'],incident['revision'])).fetchone():
                raise ReviewConflict('An action request is still active. Resolve that request before closing this investigation.')
            identifier=secrets.token_hex(12);created=timestamp()
            db.execute('INSERT INTO human_reviews VALUES(?,?,?,?,?,?,?,?)',(identifier,incident['incident_id'],incident['revision'],
                binding(incident),values['reviewer'].strip(),values['conclusion'],values['notes'].strip(),created))
            if values['conclusion']!='NEEDS_MORE_EVIDENCE':
                db.execute("UPDATE review_notifications SET status='cancelled',detail='Resolved before notification delivery' WHERE incident_id=? AND revision=? AND status='queued'",
                           (incident['incident_id'],incident['revision']))
        return dict(review_id=identifier,created_at=created,conclusion=values['conclusion'],
            resolved=values['conclusion']!='NEEDS_MORE_EVIDENCE',note='Human conclusion saved separately. An eligible Suspicious review may prompt for separate live block approval.')

    def notify(self,values):
        if not isinstance(values,dict) or set(values)!={'incident_id','revision','snapshot_hash'}:
            raise ValueError('Choose an exact incident revision for notification.')
        validate_identity(values)
        with closing(self.connect()) as db,db:
            initialize(db);db.execute('BEGIN IMMEDIATE')
            incident=attach(db,load_incident(db,values['incident_id']))
            check_snapshot(incident,values)
            if incident['human_review'] and incident['human_review']['conclusion']!='NEEDS_MORE_EVIDENCE':
                raise ValueError('This revision already has a resolved human review.')
            identifier=secrets.token_hex(12)
            db.execute("INSERT OR IGNORE INTO review_notifications VALUES(?,?,?,?,'queued',?,NULL,'Requested from dashboard')",
                (identifier,incident['incident_id'],incident['revision'],binding(incident),timestamp()))
            row=db.execute('SELECT notification_id,status FROM review_notifications WHERE incident_id=? AND revision=?',
                (incident['incident_id'],incident['revision'])).fetchone()
        return dict(notification_id=row[0],status=row[1],note='The monitor’s existing Telegram handler delivers this notification. No response action is requested.')


def validate_identity(values):
    if not isinstance(values.get('incident_id'),str) or not re.fullmatch('[a-f0-9]{64}',values['incident_id']): raise ValueError('Invalid incident ID.')
    if type(values.get('revision')) is not int or values['revision']<1: raise ValueError('Invalid incident revision.')
    if not isinstance(values.get('snapshot_hash'),str) or not re.fullmatch('[a-f0-9]{64}',values['snapshot_hash']): raise ValueError('Invalid evidence snapshot.')


def reason_for_review(incident):
    report=incident.get('report') or {};error=incident.get('error') or ''
    if report.get('format')==ADVISORY_FORMAT:
        return {'SUSPICIOUS':'The AI assessment is suspicious.', 'INSUFFICIENT_EVIDENCE':'The AI assessment found insufficient evidence.'}.get(assessment_label(report),'The report needs operator review.')
    from experimental_assessment import experimental_metadata
    if report and experimental_metadata(incident.get('metadata')):return 'The AI assessment is unverified and requires an independent human conclusion.'
    if report.get('recommended_action')=='REQUEST_MORE_EVIDENCE':return 'The AI requested more evidence before a response decision.'
    if report.get('verdict')=='INSUFFICIENT_EVIDENCE':return 'The AI could not reach a conclusive assessment from the available evidence.'
    if 'No authentication outcomes' in error:return 'A network alert was detected, but no matching SSH authentication outcomes were found in the retained evidence window.'
    if 'Authorization changed' in error or 'plan changed' in error:return 'The test-plan scope changed during the investigation and needs an operator check.'
    if 'unknown evidence ID' in error: return 'The AI report cited an ID that was not in the supplied evidence.'
    if '4096 UTF-8 bytes' in error: return 'The AI report was empty or exceeded the text limit.'
    if 'coverage' in error.lower():return 'The available authentication evidence did not establish the required log coverage.'
    return 'The automated investigation could not finish with a valid assessment. Review the saved evidence and error details.'


def notification_message(incident,identity,notification_id=None):
    from incident_labels import header
    from experimental_assessment import experimental_metadata
    report = incident.get('report') or {}
    assessment = (report.get('reason') or '').strip()
    if assessment:
        excerpt = assessment if len(assessment) <= 600 else assessment[:600].rstrip() + '…'
        reason = f'Reason: {reason_for_review(incident)}\n' if report.get('format')==ADVISORY_FORMAT else ''
        summary = reason + f"AI assessment:\n{excerpt}\n\n"
        heading = '🟡 Human review requested.\n'
    else:
        summary = f"Reason: {reason_for_review(incident)}\n"
        heading = '🟡 Manual review needed on the dashboard.\n'
    text=(heading
        +('Experimental AI — unverified; response actions disabled.\n' if experimental_metadata(incident.get('metadata')) else '')
        +header(incident)+summary+
        f"Full incident: http://127.0.0.1:8765/#incident={incident['incident_id']}")
    payload=dict(chat_id=identity['chat_id'],text=text)
    if notification_id:
        payload['reply_markup']={'inline_keyboard':[
            [{'text':'🟢 Benign','callback_data':'hr:b:'+notification_id},
             {'text':'🔴 Suspicious','callback_data':'hr:s:'+notification_id}],
            [{'text':'🟡 Need more evidence','callback_data':'hr:e:'+notification_id}]]}
    return payload


def handle_review_callback(db,query,identity,now):
    """Uses the poller's transaction; never creates response requests or executes actions."""
    match=re.fullmatch(r'hr:([bseld]):([a-f0-9]{24})',query.get('data',''))
    if not match:return 'ignored'
    choice,identifier=match.groups()
    # Tables are initialized before the poller begins its transaction.
    row=db.execute('SELECT n.*,c.bot_key,c.chat_id,c.user_id,c.expected_review_id,c.expires_at,c.used '
        'FROM review_notifications n JOIN review_choices c USING(notification_id) WHERE notification_id=?',(identifier,)).fetchone()
    if row is None:return 'unknown_review'
    message=query.get('message') or {};operator=query.get('from') or {}
    if (row['bot_key']!=identity['bot_key'] or row['chat_id']!=identity['chat_id'] or row['user_id']!=identity['user_id']
        or operator.get('id')!=row['user_id'] or operator.get('is_bot',False)
        or message.get('chat',{}).get('id')!=row['chat_id'] or message.get('chat',{}).get('type')!='private'
        or message.get('message_id')!=row['message_id']):return 'unauthorized'
    if row['used'] or row['status']!='sent':return 'review_unavailable'
    if now>=row['expires_at']:return 'review_expired'
    if choice in ('l','d'):
        try:
            incident=attach(db,load_incident(db,row['incident_id']))
            if (incident['revision']!=row['revision'] or binding(incident)!=row['snapshot_hash']
                    or incident['review_context']['expected_review_id']!=row['expected_review_id']):
                return 'review_changed'
        except (ValueError,KeyError):return 'review_changed'
        if (incident.get('report') or {}).get('verdict')!='SUSPICIOUS':return 'review_unavailable'
        if db.execute('SELECT 1 FROM review_response_decisions WHERE notification_id=?',(identifier,)).fetchone():
            return 'live_block_denied'
        if choice=='d':
            db.execute('INSERT INTO review_response_decisions VALUES(?,?,?,?)',
                (identifier,'denied',operator['id'],now))
            return 'live_block_denied'
        # Informational only: never consumes review, creates approval or dispatches.
        return 'live_block_unavailable'
    conclusion={'b':'BENIGN','s':'SUSPICIOUS','e':'NEEDS_MORE_EVIDENCE'}[choice]
    try:
        ReviewService('.').save(dict(incident_id=row['incident_id'],revision=row['revision'],snapshot_hash=row['snapshot_hash'],
            expected_review_id=row['expected_review_id'],reviewer='Telegram operator '+str(operator['id']),
            conclusion=conclusion,notes=''),connection=db)
    except ValueError:return 'review_changed'
    db.execute('UPDATE review_choices SET used=1 WHERE notification_id=?',(identifier,))
    return 'review_'+conclusion.lower()


def deliver_notifications(db_path,policy,client,identity):
    """Called only by the existing bot-lock owner; no polling or response calls."""
    from telegram_client import TelegramError
    with closing(sqlite3.connect(db_path,timeout=10)) as db,db:
        initialize(db);db.row_factory=sqlite3.Row;db.execute('BEGIN IMMEDIATE')
        db.execute("UPDATE review_notifications SET status='delivery_unknown',detail='Interrupted send; no automatic resend' WHERE status='sending'")
        enabled=policy.get('review_notifications_enabled_after')
        if enabled:
            rows=db.execute('''SELECT i.incident_id FROM incidents i JOIN analyses a
                ON a.incident_id=i.incident_id AND a.revision=i.revision
                WHERE i.status='manual_review' AND a.status='manual_review'
                AND (a.report IS NULL OR json_extract(a.report,'$.format')='advisory_text')
                AND datetime(a.created_at)>=datetime(?)''',(enabled,)).fetchall()
            for row in rows:
                incident=attach(db,load_incident(db,row['incident_id']))
                if incident['human_review'] and incident['human_review']['conclusion']!='NEEDS_MORE_EVIDENCE':continue
                db.execute("INSERT OR IGNORE INTO review_notifications VALUES(?,?,?,?,'queued',?,NULL,'Automatic new manual-review notice')",
                    (secrets.token_hex(12),incident['incident_id'],incident['revision'],binding(incident),timestamp()))
        queued=db.execute("SELECT * FROM review_notifications WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
        if not queued:return 'idle'
        incident=attach(db,load_incident(db,queued['incident_id']))
        resolved=incident['human_review'] and incident['human_review']['conclusion']!='NEEDS_MORE_EVIDENCE'
        if queued['revision']!=incident['revision'] or queued['snapshot_hash']!=binding(incident) or resolved:
            db.execute("UPDATE review_notifications SET status='stale',detail='Incident changed or review resolved before delivery' WHERE notification_id=?",(queued['notification_id'],))
            return 'stale'
        db.execute('INSERT OR REPLACE INTO review_choices VALUES(?,?,?,?,?,?,0)',
            (queued['notification_id'],identity['bot_key'],identity['chat_id'],identity['user_id'],
             incident['review_context']['expected_review_id'],int(time.time())+86400))
        db.execute("UPDATE review_notifications SET status='sending' WHERE notification_id=?",(queued['notification_id'],))
    try:
        sent=client.call('sendMessage',notification_message(incident,identity,queued['notification_id']));state='sent';message=sent['message_id'];detail='Review notice delivered'
    except (TelegramError,KeyError,TypeError):
        state='delivery_unknown';message=None;detail='Uncertain send; no automatic resend'
    with closing(sqlite3.connect(db_path,timeout=10)) as db,db:
        db.execute('UPDATE review_notifications SET status=?,message_id=?,detail=? WHERE notification_id=?',
                   (state,message,detail,queued['notification_id']))
    return state
