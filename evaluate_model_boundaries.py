"""Synthetic boundary evaluation only. No VM, Telegram or response operations."""
import argparse
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from unittest.mock import MagicMock,patch

from approved_plans import select_plan
from analyst import analyze_next
from experiment_store import active_instruction
from lab_config import runtime_settings
from ollama_analyst import assessment_payload,make_prompt,model_config,validate_assessment
from assessment_providers import provider_report as ollama_report,freeze
from ollama_transport import request_json
from ssh_investigation import build_bundle_job
from ssh_scenarios import ROOT as FIXTURES,load_scenario,plan_checks

ROOT=Path(__file__).resolve().parent


def boundary_cases():
    approved,_=load_scenario(FIXTURES/'approved_test.json')
    unapproved,_=load_scenario(FIXTURES/'unapproved_activity.json')
    expired=deepcopy(approved);old=expired['plan']
    old.update(start='2026-10-26T17:00:00Z',end='2026-10-26T17:30:00Z')
    expired['plan']=select_plan(expired['incident'],[old])
    assert expired['plan'] is None
    low_count=deepcopy(approved)
    low_count['authentication'].update(failed_password_count=2,failed_accounts={'root':1,'soc_test':1})
    consolidated=deepcopy(unapproved);consolidated['incident']['alert_count']=4
    results=[]
    for name,case in [('outside_approved_window',expired),('single_unexpected_root_attempt',low_count),('consolidated_alerts',consolidated)]:
        incident=case['incident']
        _,job=build_bundle_job(dict(incident=incident,authentication=case['authentication'],plan=case['plan'],plan_checks=plan_checks(incident,case['plan'])))
        evidence=dict(signature_id=9001001,source_ip=incident['source_ip'],destination_ip=incident['target_ip'],
                      destination_port=22,window_start=incident['start'],alert_count=incident['alert_count'])
        results.append(dict(name=name,evidence=evidence,investigation=job,expected_verdict='SUSPICIOUS'))
    return results


def local_safety_checks():
    case=boundary_cases()[0];job=deepcopy(case['investigation']);job['authentication']['coverage']='partial'
    with tempfile.TemporaryDirectory() as folder:
        db=Path(folder)/'synthetic.sqlite3'
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
            connection.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('synthetic',1,json.dumps(case['evidence']),1,'pending'))
        runner=MagicMock(side_effect=AssertionError('Model must not be called with missing coverage'))
        with patch('ssh_live_investigation.ready_after',return_value=datetime(2020,1,1,tzinfo=timezone.utc)),\
             patch('ssh_live_investigation.prepare_live_job',return_value=('',job)):
            result=analyze_next(db,{'ssh_enrichment':True,'approved_plans':'synthetic-unused.json'},runner=runner)
        missing=result['status']=='manual_review' and runner.call_count==0
    payload=assessment_payload(case['evidence'],case['investigation'])
    try:validate_assessment('{malformed output',payload,case['investigation']);malformed=False
    except ValueError:malformed=True
    return dict(missing_evidence={'passed':missing,'status':result['status'],'model_calls':runner.call_count},
                malformed_output={'passed':malformed,'model_calls':0})


def run(output,instruction=None,*,claims_first=False,model=None,threads=None,provider=None,expected_model_version=None):
    settings=runtime_settings(ROOT);configured,options=model_config(settings)
    if model or threads is not None:
        settings=deepcopy(settings)
        if model:settings['lab_profile']['ollama']['model']=model
        if threads is not None:settings['lab_profile']['ollama']['num_thread']=threads
        settings['ollama']=dict(settings['lab_profile']['ollama'])
    if claims_first:settings['ollama']=dict(settings['ollama'],claims_first=True)
    from provider_state import effective
    if provider or model:
        if provider=='gemini' and (not model or not expected_model_version):raise ValueError('Gemini evaluation requires an explicit model and expected returned version')
        selected=provider or 'ollama';name=model or settings['ollama']['model']
        settings['_provider_snapshot']=effective(settings,dict(provider=selected,model=name,expected_model_version=expected_model_version or name))
    settings=freeze(dict(settings,_synthetic_evaluation=True));configured=effective(settings)
    options={k:configured[k] for k in ('num_ctx','num_predict')}
    instruction=instruction or active_instruction(ROOT)['text']
    receipt=dict(model=configured['model'],provider=configured['provider'],route=configured['route'],options=options,instruction_hash=hashlib.sha256(instruction.encode()).hexdigest(),
                 synthetic_only=True,responses_disabled=True,attacks_launched=0,telegram_messages=0,firewall_actions=0,
                 results=[],safety_checks=local_safety_checks(),passed=False)
    for case in boundary_cases():
        evidence=case['evidence'];job=case['investigation'];payload=assessment_payload(evidence,job)
        prompt=make_prompt(payload,instruction=instruction)
        if case['name'] in prompt:raise ValueError('Evaluation label leaked into prompt')
        row=dict(name=case['name'],expected_verdict=case['expected_verdict'],valid_structured_response=False,verdict_matches_reference=False,
                 assessment_data=payload,investigation=job)
        started=time.monotonic()
        try:
            envelope=ollama_report(prompt,dict(settings,investigation=job))
            row['metadata']={k:v for k,v in envelope.items() if k!='text'};row['raw_report']=envelope['text']
            row['report']=validate_assessment(envelope['text'],payload,job);row['valid_structured_response']=True
            row['verdict_matches_reference']=row['report']['verdict']==row['expected_verdict']
            row['security_judgment_review']='Required: reference-label agreement alone does not certify the explanation.'
        except Exception as error:row['error']=(type(error).__name__+': '+str(error))[:3000]
        row['wall_seconds']=round(time.monotonic()-started,3)
        row['loaded_models']=request_json(configured,'/api/ps',timeout=10) if configured['provider']=='ollama' else {'note':'Cloud provider; no local model status request'}
        receipt['results'].append(row);output.write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({k:row.get(k) for k in ['name','valid_structured_response','verdict_matches_reference','wall_seconds','report','error']}),flush=True)
    receipt['passed']=all(r['valid_structured_response'] and r['verdict_matches_reference'] for r in receipt['results']) and all(v['passed'] for v in receipt['safety_checks'].values())
    output.write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instruction-file',type=Path)
    parser.add_argument('--output',type=Path,default=ROOT/'verification-model-boundaries.json')
    parser.add_argument('--claims-first',action='store_true')
    parser.add_argument('--model',help='Explicit evaluation override; never activates a model')
    parser.add_argument('--provider',choices=['ollama','gemini'])
    parser.add_argument('--expected-model-version')
    parser.add_argument('--threads',type=int,choices=range(1,5),help='Explicit evaluation CPU threads; never activates configuration')
    args=parser.parse_args();result=run(args.output,args.instruction_file.read_text() if args.instruction_file else None,claims_first=args.claims_first,model=args.model,threads=args.threads,provider=args.provider,expected_model_version=args.expected_model_version)
    raise SystemExit(0 if result['passed'] else 1)
