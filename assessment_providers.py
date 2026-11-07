"""Provider-neutral assessment entry point. Ollama is the implicit default."""
from copy import deepcopy
from provider_state import effective,stamp


def freeze(settings):
    value=deepcopy(settings);value['_provider_snapshot']=effective(settings);return value


def provider_report(prompt,settings):
    config=effective(settings)
    if config['provider']=='gemini':
        from gemini_provider import generate
        result=generate(prompt,settings,config,synthetic=settings.get('_synthetic_evaluation') is True)
    else:
        from ollama_analyst import ollama_report
        value=deepcopy(settings)
        if isinstance(value.get('lab_profile'),dict):value['lab_profile']['ollama']['model']=config['model']
        value['ollama']=dict(value.get('ollama',{}),model=config['model'])
        result=ollama_report(prompt,value)
    return dict(result,**stamp(config))
