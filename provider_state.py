"""Trusted provider selection, independent of the VM platform; no network or secrets."""
from contextlib import closing
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import urlsplit


def root_for(settings):
    if settings.get('_provider_root'):return Path(settings['_provider_root']).resolve()
    lab=settings.get('lab_profile')
    if isinstance(lab,dict) and lab.get('_path'):return Path(lab['_path']).resolve().parent
    if isinstance(lab,(str,Path)):return Path(lab).resolve().parent
    return None


def selection(root):
    path=Path(root)/'ssh-live.sqlite3' if root else None
    if not path or not path.exists():return None
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='model_provider_selection'").fetchone():return None
        row=db.execute('SELECT value FROM model_provider_selection WHERE singleton=1').fetchone()
    return json.loads(row[0]) if row else None


def validate_choice(value):
    if not isinstance(value,dict) or set(value)!={'provider','model','expected_model_version'}:
        raise ValueError('Supply provider, model and expected returned model version only')
    if value['provider'] not in ('ollama','gemini'):raise ValueError('Unsupported model provider')
    for key in ('model','expected_model_version'):
        if not isinstance(value[key],str) or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',value[key]):
            raise ValueError('Invalid model identity')
    if value['provider']=='gemini' and any(not re.fullmatch(r'gemini-[A-Za-z0-9_.-]+',value[k]) for k in ('model','expected_model_version')):
        raise ValueError('Use an explicit Gemini model ID and pinned returned version')
    if value['provider']=='ollama' and (value['model']!=value['expected_model_version'] or 'cloud' in value['model'].lower()):
        raise ValueError('Ollama requires an exact local model identity; cloud aliases are not enabled here')
    return dict(value)


def effective(settings,override=None):
    if override is None and settings.get('_provider_snapshot'):return deepcopy(settings['_provider_snapshot'])
    from ollama_analyst import model_config
    base,options=model_config(settings)
    root=root_for(settings);saved=selection(root) if override is None else None
    choice=validate_choice(override) if override is not None else validate_choice({k:saved[k] for k in ('provider','model','expected_model_version')}) if saved else dict(provider='ollama',model=base['model'],expected_model_version=base['model'])
    config=dict(base,**choice,num_ctx=options['num_ctx'],num_predict=options['num_predict'],selection_id='candidate' if override is not None else saved['id'] if saved else 'default')
    if choice['provider']=='gemini':config.update(endpoint='https://generativelanguage.googleapis.com',transport='https',route='cloud')
    else:config['route']='local' if urlsplit(config['endpoint']).hostname in ('localhost','127.0.0.1','::1') and 'cloud' not in config['model'].lower() else 'remote'
    bound={k:config.get(k) for k in ('provider','model','expected_model_version','endpoint','transport','route','num_ctx','num_predict','selection_id')}
    config['binding']=hashlib.sha256(json.dumps(bound,sort_keys=True).encode()).hexdigest()
    config['_root']=str(root) if root else None
    return config


def stamp(config):
    return dict(provider=config['provider'],configured_model=config['model'],expected_model_version=config['expected_model_version'],
                model_route=config['route'],provider_binding=config['binding'],provider_selection_id=config['selection_id'])


def validate_binding(metadata,settings):
    config=effective(settings)
    if metadata.get('provider_binding'):
        if metadata['provider_binding']!=config['binding'] or metadata.get('provider')!=config['provider']:
            raise ValueError('Provider/model selection changed; a fresh assessment and approval are required')
    elif config['selection_id']!='default' or config['provider']!='ollama':
        raise ValueError('Historical assessment is not bound to the active provider/model')
    if metadata.get('model')!=config['model']:raise ValueError('Returned model differs from active configured identity')
    if config['provider']=='gemini' and metadata.get('model_version')!=config['expected_model_version']:
        raise ValueError('Returned Gemini model version differs from the trusted pin')
    return config


def activate(root,values):
    root=Path(root).resolve()
    if not isinstance(values,dict) or set(values)!={'provider','model','expected_model_version','expected_selection'}:
        raise ValueError('Activate an exact provider/model selection with its current revision')
    choice=validate_choice({k:values[k] for k in ('provider','model','expected_model_version')})
    with closing(sqlite3.connect(root/'ssh-live.sqlite3',timeout=5)) as db,db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE IF NOT EXISTS model_provider_selection(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value TEXT NOT NULL)')
        row=db.execute('SELECT value FROM model_provider_selection WHERE singleton=1').fetchone()
        current=json.loads(row[0]) if row else None
        if values['expected_selection']!=(current['id'] if current else 'default'):raise ValueError('Provider selection changed; refresh before activating')
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'live_actions' in tables and db.execute("SELECT 1 FROM live_actions WHERE status NOT IN ('live_complete','live_failed') LIMIT 1").fetchone():
            raise ValueError('A live response needs completion or reconciliation before switching provider')
        invalidated=0
        if 'approval_requests' in tables:
            columns={r[1] for r in db.execute('PRAGMA table_info(approval_requests)')}
            extra=",status_notified=''" if 'status_notified' in columns else ''
            invalidated=db.execute("UPDATE approval_requests SET status='stale'"+extra+" WHERE plan IS NOT NULL AND status IN ('queued','sending','pending','approved')").rowcount
        value=dict(choice,id=secrets.token_hex(16),activated_at=datetime.now(timezone.utc).isoformat())
        db.execute('INSERT INTO model_provider_selection VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET value=excluded.value',(json.dumps(value),))
    return dict(selection=value,invalidated_approvals=invalidated,note='Provider/model selected for future assessments. Pending response approvals invalidated; no request sent, consent granted or response authorized.')
