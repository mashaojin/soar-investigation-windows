"""Actual base-model assessment of synthetic fixtures; no lab/Telegram/firewall IO."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from ollama_analyst import assessment_payload, make_prompt, validate_assessment
from assessment_providers import provider_report as ollama_report,freeze
from ssh_investigation import build_job
from ssh_scenarios import ROOT, load_scenario


def run(output, fixtures=ROOT, settings=None, instruction=None):
    from lab_config import runtime_settings
    from ollama_analyst import model_config
    settings=settings or runtime_settings(Path(__file__).parent)
    from provider_state import effective
    settings=freeze(dict(settings,_synthetic_evaluation=True))
    configured=effective(settings);options={k:configured[k] for k in ('num_ctx','num_predict')}
    from experiment_store import active_instruction
    if instruction is None:instruction=active_instruction(Path(__file__).parent)
    else:
        import hashlib
        instruction=dict(id=hashlib.sha256(instruction.encode()).hexdigest(),text=instruction,label='Explicit evaluation candidate; not activated')
    receipt={'started_at':datetime.now(timezone.utc).isoformat(),'provider':configured['provider'],'route':configured['route'],
             'mode':'synthetic_fixture_actual_base_model','model':configured['model'],'options':options,
             'prompt_version':instruction,'telegram_messages':0,'firewall_actions':0,'attacks_launched':0,'results':[],'passed':False}
    for path in sorted(fixtures.glob('*.json')):
        case,_=load_scenario(path)
        _,job=build_job(path)
        payload=assessment_payload({'signature_id':9001001,'source_ip':case['incident']['source_ip'],
             'destination_ip':case['incident']['target_ip'],'destination_port':22,
             'window_start':case['incident']['start'],'alert_count':case['incident']['alert_count']},job)
        row={'scenario':case['id'],'assessment_data':payload,'investigation':job,'passed':False}
        try:
            prompt=make_prompt(payload,instruction=instruction['text'])
            envelope=ollama_report(prompt,dict(settings,investigation=job))
            row['metadata']={k:v for k,v in envelope.items() if k!='text'}
            row['raw_report']=envelope['text']
            row['report']=validate_assessment(envelope['text'],payload,job)
            row['valid_structured_response']=True
            row['expected_verdict']=case['expected'].get('verdict','BENIGN' if case['id']=='approved_test' else 'SUSPICIOUS')
            row['verdict_matches_reference']=row['report']['verdict']==row['expected_verdict']
            row['security_judgment_review']='Required: matching a verdict label does not certify its explanation.'
            row['passed']=row['verdict_matches_reference']
        except Exception as exc: row.update(error=str(exc)[:3000],valid_structured_response=False,verdict_matches_reference=False)
        receipt['results'].append(row)
        output.write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({k:row.get(k) for k in ['scenario','passed','report','error']}),flush=True)
    receipt['passed']=len(receipt['results'])==3 and all(r['passed'] for r in receipt['results'])
    output.write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt['passed']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path(__file__).with_name('verification-gemma-direct.json'))
    parser.add_argument('--instruction-file',type=Path,help='Evaluate a candidate without activating it')
    parser.add_argument('--claims-first',action='store_true',help='Evaluate schema ordering without changing facts or verdict choices')
    parser.add_argument('--model',help='Explicit synthetic-evaluation model override; never changes active configuration')
    parser.add_argument('--provider',choices=['ollama','gemini'],help='Explicit evaluation route; no automatic fallback')
    parser.add_argument('--expected-model-version',help='Required exact returned version for Gemini evaluation')
    parser.add_argument('--threads',type=int,choices=range(1,5),help='Explicit synthetic-evaluation CPU threads; never changes active configuration')
    args=parser.parse_args()
    from lab_config import runtime_settings
    settings=runtime_settings(Path(__file__).parent)
    if args.model or args.threads:
        from copy import deepcopy
        settings=deepcopy(settings)
        if args.model:settings['lab_profile']['ollama']['model']=args.model
        if args.threads:settings['lab_profile']['ollama']['num_thread']=args.threads
        settings['ollama']=dict(settings['lab_profile']['ollama'])
    if args.claims_first:settings['ollama']=dict(settings['ollama'],claims_first=True)
    if args.provider or args.model:
        from provider_state import effective
        if args.provider=='gemini' and (not args.model or not args.expected_model_version):parser.error('Gemini requires explicit --model and --expected-model-version')
        provider=args.provider or 'ollama';model=args.model or settings['ollama']['model']
        settings['_provider_snapshot']=effective(settings,dict(provider=provider,model=model,expected_model_version=args.expected_model_version or model))
    raise SystemExit(0 if run(args.output,settings=settings,instruction=args.instruction_file.read_text() if args.instruction_file else None) else 1)
