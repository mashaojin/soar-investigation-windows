"""Dashboard operations: select a route or test public synthetic evidence, never grant cloud consent."""
from pathlib import Path
from assessment_providers import provider_report
from provider_state import effective,activate,validate_choice
from lab_config import runtime_settings


class ProviderService:
    def __init__(self,root):self.root=Path(root).resolve()

    def state(self):
        config=effective(runtime_settings(self.root))
        value={k:config[k] for k in ('provider','model','expected_model_version','route','selection_id','binding','num_ctx','num_predict')}
        value['providers']=[dict(id='ollama',label='Ollama — configured host'),dict(id='gemini',label='Gemini API — Google cloud')]
        if config['provider']=='gemini':
            from gemini_provider import readiness
            value['access']=readiness(config)
        else:value['access']=dict(note='Ollama remains the default. No automatic cloud fallback.')
        return value

    def activate(self,values):return activate(self.root,values)

    def check(self,values):
        choice=validate_choice(values)
        settings=runtime_settings(self.root);config=effective(settings,choice)
        settings.update(_provider_snapshot=config,_synthetic_evaluation=True,_advisory_report=True)
        # A fixed repository fixture, never saved incidents, active plans or user-supplied evidence.
        from ssh_scenarios import ROOT,load_scenario
        from ssh_investigation import build_job
        from ollama_analyst import assessment_payload,make_prompt
        from advisory_report import validate
        case,_=load_scenario(ROOT/'approved_test.json');_,job=build_job(ROOT/'approved_test.json');i=case['incident']
        payload=assessment_payload(dict(signature_id=9001001,source_ip=i['source_ip'],destination_ip=i['target_ip'],
            destination_port=22,window_start=i['start'],alert_count=i['alert_count']),job)
        result=provider_report(make_prompt(payload,advisory=True),dict(settings,investigation=job))
        outcome={k:result.get(k) for k in ('provider','model','model_version','model_route','elapsed_seconds','prompt_tokens','output_tokens')}
        outcome.update(synthetic_only=True,active_selection_changed=False,firewall_actions=0,telegram_messages=0)
        try:
            outcome.update(checks_passed=True,report=validate(result['text'],payload))
        except ValueError as error:
            outcome.update(checks_passed=False,validation_error=str(error))
        return outcome
