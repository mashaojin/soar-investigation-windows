"""Fixed-origin Gemini REST transport. No tools, fallback, retries or credential logging."""
import ast
from contextlib import closing
from datetime import datetime,timezone,timedelta
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import time

HOST='generativelanguage.googleapis.com'


def api_key(root):
    value=os.environ.get('GEMINI_API_KEY')
    if not value and root:
        path=Path(root)/'.env.gemini'
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_size>2048:raise ValueError('Unsafe local Gemini key file')
            lines=[line.strip() for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
            if len(lines)!=1 or not lines[0].startswith('GEMINI_API_KEY='):raise ValueError('Gemini key file must contain one quoted GEMINI_API_KEY assignment; contents withheld')
            try:value=ast.literal_eval(lines[0].split('=',1)[1])
            except (ValueError,SyntaxError):raise ValueError('Invalid Gemini credential data; contents withheld') from None
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{20,256}',value):
        raise ValueError('Gemini API key is missing or invalid; configure it locally, never in the dashboard or Git')
    return value


def access(config,key,synthetic,context=None):
    root=config.get('_root')
    live_path = Path(root)/'.gemini-live-access.local.json' if root else None
    if not synthetic and live_path and (live_path.exists() or live_path.is_symlink()):
        record = live_access(config,key,live_path)
        context = context or {}
        try:
            start = datetime.fromisoformat(context['_incident_window_start'].replace('Z','+00:00'))
            if (context.get('_advisory_report') is not True or not context.get('_incident_id')
                    or not datetime.fromisoformat(record['live_since']) <= start <= datetime.now(timezone.utc)):
                raise ValueError()
        except (KeyError,ValueError,TypeError,AttributeError):
            raise ValueError('Ongoing Gemini access covers new advisory incidents only') from None
        return record
    path=Path(root)/'.gemini-access.local.json' if root else None
    if not path or not path.is_file() or path.is_symlink() or path.stat().st_size>4096:
        raise ValueError('Verify project/model free quota or applicable redeemed credits locally before Gemini API calls')
    try:record=json.loads(path.read_text())
    except ValueError:raise ValueError('Invalid local Gemini access receipt; contents withheld') from None
    required={'model','expected_model_version','key_sha256','quota_kind','quota_verified_at','expires_at',
              'synthetic_requests_authorized','max_generation_requests','real_evidence_authorized','paid_usage_authorized'}
    if not isinstance(record,dict) or set(record)!=required:raise ValueError('Incomplete Gemini quota/consent receipt')
    if (record['model']!=config['model'] or record['expected_model_version']!=config['expected_model_version']
            or record['key_sha256']!=hashlib.sha256(key.encode()).hexdigest()
            or record['quota_kind'] not in ('free_tier','redeemed_credits')
            or record['synthetic_requests_authorized'] is not True or record['paid_usage_authorized'] is not False
            or type(record['max_generation_requests']) is not int or not 1<=record['max_generation_requests']<=10
            or type(record['real_evidence_authorized']) is not bool):
        raise ValueError('Gemini model/key/quota scope is not authorized; no request sent')
    try:
        verified=datetime.fromisoformat(record['quota_verified_at']);expires=datetime.fromisoformat(record['expires_at'])
        now=datetime.now(timezone.utc)
        if verified.tzinfo is None or expires.tzinfo is None or not verified<=now<expires or not expires<=verified+timedelta(days=1):raise ValueError()
    except (ValueError,TypeError):raise ValueError('Gemini quota verification expired or invalid; reverify locally') from None
    if not synthetic and record['real_evidence_authorized'] is not True:
        raise ValueError('Cloud evidence consent is absent: real or saved SSH evidence will not be uploaded')
    if not synthetic:
        # A real-evidence receipt permits one fresh incident, never saved comparisons.
        context=context or {}
        try:
            start=datetime.fromisoformat(context['_incident_window_start'].replace('Z','+00:00'))
            if not context.get('_incident_id') or start.tzinfo is None or start<verified or record['max_generation_requests']!=1:
                raise ValueError()
        except (KeyError,ValueError,TypeError,AttributeError):
            raise ValueError('Cloud test consent covers one fresh incident only; saved or older evidence is not authorized') from None
    return record


def live_access(config,key,path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        raise ValueError('Invalid ongoing Gemini authorization file')
    try:
        record = json.loads(path.read_text())
        expected = dict(model=config['model'],expected_model_version=config['expected_model_version'],
                        key_sha256=hashlib.sha256(key.encode()).hexdigest(),quota_kind='free_tier')
        if not isinstance(record,dict) or set(record) != expected.keys() | {'live_since'}:
            raise ValueError()
        if any(record[field] != value for field,value in expected.items()):
            raise ValueError()
        if datetime.fromisoformat(record['live_since']) > datetime.now(timezone.utc):
            raise ValueError()
    except (ValueError,TypeError):
        raise ValueError('Ongoing Gemini authorization does not match the configured model and key') from None
    return record


def readiness(config):
    try:
        key=api_key(config.get('_root'))
    except ValueError as error:
        return dict(key_configured=False,synthetic_access_verified=False,real_evidence_authorized=False,note=str(error))
    root = config.get('_root')
    live_path = Path(root)/'.gemini-live-access.local.json' if root else None
    if live_path and (live_path.exists() or live_path.is_symlink()):
        try:
            live_access(config,key,live_path)
        except ValueError as error:
            return dict(key_configured=True,synthetic_access_verified=False,real_evidence_authorized=False,note=str(error))
        try:
            access(config,key,True)
            synthetic_ready = True
        except ValueError:
            synthetic_ready = False
        return dict(key_configured=True,synthetic_access_verified=synthetic_ready,real_evidence_authorized=True,
                    note='Ongoing Gemini access for new advisory incidents. Google Free tier quota applies.')
    try:
        record=access(config,key,True)
        return dict(key_configured=True,synthetic_access_verified=True,real_evidence_authorized=record['real_evidence_authorized'],note='Local operator quota receipt; not proof of unlimited API allowance')
    except ValueError as error:
        return dict(key_configured=True,synthetic_access_verified=False,real_evidence_authorized=False,note=str(error))


def reserve(config,record):
    identifier=hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest()
    with closing(sqlite3.connect(Path(config['_root'])/'gemini-request-budget.sqlite3',timeout=5)) as db,db:
        db.execute('CREATE TABLE IF NOT EXISTS budget(id TEXT PRIMARY KEY,attempts INTEGER NOT NULL)')
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT attempts FROM budget WHERE id=?',(identifier,)).fetchone()
        used=row[0] if row else 0
        if used>=record['max_generation_requests']:raise ValueError('Authorized Gemini request budget exhausted; no retry or paid fallback')
        db.execute('INSERT INTO budget VALUES(?,1) ON CONFLICT(id) DO UPDATE SET attempts=attempts+1',(identifier,))


def request(path,key,body,deadline):
    if not re.fullmatch(r'/v1beta/models/gemini-[A-Za-z0-9_.-]+(?::(?:countTokens|generateContent))?',path):raise ValueError('Unsupported fixed Gemini operation')
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('Gemini request deadline exceeded')
    encoded=json.dumps(body).encode() if body is not None else None
    if encoded is not None and len(encoded)>131072:raise ValueError('Oversized Gemini request')
    conn=http.client.HTTPSConnection(HOST,timeout=remaining)
    try:
        conn.request('POST' if body is not None else 'GET',path,body=encoded,
                     headers={'x-goog-api-key':key,'Content-Type':'application/json','Accept':'application/json'})
        response=conn.getresponse()
        if response.status!=200:
            raise ValueError('Gemini API HTTP '+str(response.status)+'; no retry, billing change or fallback. Check local quota/key/project settings.')
        chunks=[];size=0
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('Gemini request deadline exceeded')
            if conn.sock:conn.sock.settimeout(remaining)
            block=response.read1(min(4096,262145-size))
            if not block:break
            chunks.append(block);size+=len(block)
            if size>262144:raise ValueError('Oversized Gemini response')
        result=json.loads(b''.join(chunks))
        if not isinstance(result,dict):raise ValueError('Malformed Gemini API response')
        return result
    except (OSError,http.client.HTTPException):
        raise RuntimeError('Gemini transport failed; credential and remote response details withheld. No automatic retry.') from None
    finally:conn.close()


def generate(prompt,settings,config,synthetic=False):
    from model_lock import inference_slot
    from ollama_analyst import generation_schema
    with inference_slot():
        key=api_key(config.get('_root'));receipt=access(config,key,synthetic,settings)
        if 'live_since' not in receipt:
            reserve(config,receipt)
        options=dict(num_ctx=config['num_ctx'],num_predict=config['num_predict'])
        advisory = settings.get('_advisory_report') is True
        schema,fact_mode,required_bytes = (
            (None, 'not_applicable', None) if advisory else generation_schema(prompt,settings,config,options))
        start=time.monotonic();deadline=start+120
        path='/v1beta/models/'+config['model']
        model=request(path,key,None,deadline)
        if model.get('name')!='models/'+config['model'] or 'generateContent' not in model.get('supportedGenerationMethods',[]):
            raise ValueError('Gemini model metadata identity/method mismatch')
        contents=[{'role':'user','parts':[{'text':prompt}]}]
        counted=request(path+':countTokens',key,{'contents':contents},deadline).get('totalTokens')
        if (type(counted) is not int or counted<=0 or counted+config['num_predict']>config['num_ctx']
                or type(model.get('inputTokenLimit')) is not int or counted>model['inputTokenLimit']
                or type(model.get('outputTokenLimit')) is not int or config['num_predict']>model['outputTokenLimit']):
            raise ValueError('Complete Gemini input and output reserve do not fit the configured/model limits; no truncation')
        generation = {'temperature':0,'candidateCount':1,'maxOutputTokens':config['num_predict']}
        if schema is not None:
            generation.update(responseMimeType='application/json', responseJsonSchema=schema)
        body = {'contents':contents,'generationConfig':generation}
        result=request(path+':generateContent',key,body,deadline)
        if result.get('modelVersion')!=config['expected_model_version']:
            actual=result.get('modelVersion','')
            safe=actual if isinstance(actual,str) and re.fullmatch(r'gemini-[A-Za-z0-9_.-]{1,120}',actual) else 'unavailable'
            raise ValueError('Returned Gemini model version '+safe+' differs from the explicitly configured pin; no automatic alias acceptance')
        candidates=result.get('candidates',[])
        if len(candidates)!=1 or candidates[0].get('finishReason')!='STOP' or result.get('promptFeedback',{}).get('blockReason'):
            raise ValueError('Gemini output blocked, incomplete or truncated')
        parts=candidates[0].get('content',{}).get('parts',[])
        if len(parts)!=1 or set(parts[0])!={'text'} or not isinstance(parts[0]['text'],str) or len(parts[0]['text'].encode())>4096:
            raise ValueError('Unexpected Gemini tools, thoughts, nontext or oversized output')
        usage=result.get('usageMetadata',{});prompt_tokens=usage.get('promptTokenCount');out=usage.get('candidatesTokenCount');thoughts=usage.get('thoughtsTokenCount',0)
        if (type(prompt_tokens) is not int or prompt_tokens<counted or prompt_tokens+config['num_predict']>config['num_ctx']
                or type(out) is not int or out<=0 or type(thoughts) is not int or thoughts<0 or out+thoughts>config['num_predict']
                or usage.get('toolUsePromptTokenCount',0)!=0 or candidates[0].get('groundingMetadata')):
            raise ValueError('Gemini complete-input/output token accounting is missing or exceeds the budget')
        return dict(text=parts[0]['text'],engine='gemini_direct',model=config['model'],model_version=result['modelVersion'],
            request_count=1,request_attempts=1,preflight_requests=2,assessment_version=__import__('assessment_facts').VERSION,
            fact_generation='requested_schema_bound_observations' if fact_mode!='not_applicable' else fact_mode,
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),schema_hash=hashlib.sha256(json.dumps(schema,sort_keys=True).encode()).hexdigest() if schema is not None else None,
            input_bytes=len(prompt.encode()),max_output_tokens=config['num_predict'],options=options,truncated=False,
            input_truncation_disabled=True,context_budget_verified=True,required_output_bound_bytes=required_bytes,
            done_reason='stop',elapsed_seconds=round(time.monotonic()-start,3),prompt_tokens=prompt_tokens,output_tokens=out,thought_tokens=thoughts)
