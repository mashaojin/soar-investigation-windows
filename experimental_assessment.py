"""Trusted opt-in for an unqualified Windows model; never response authorization."""
from datetime import datetime
from lab_config import load_profile


def qualification(settings, policy=None):
    value=settings.get('experimental_assessment')
    if value is None:return {}
    required={'model','authorized_at','mode'}
    if not isinstance(value,dict) or not required<=set(value) or set(value)-required-{'provider','provider_binding'}:
        raise ValueError('Invalid experimental assessment authorization')
    lab=load_profile(settings)
    from provider_state import effective
    route=effective(settings)
    if (lab['platform']!='windows-hyperv' or value['model']!=route['model'] or value['mode']!='dry_run_human_review'
            or value.get('provider','ollama')!=route['provider']
            or (route['selection_id']!='default' and value.get('provider_binding')!=route['binding'])):
        raise ValueError('Experimental authorization differs from the configured Windows model or review-only scope')
    stamp=datetime.fromisoformat(value['authorized_at'].replace('Z','+00:00'))
    if stamp.tzinfo is None:raise ValueError('Experimental authorization requires a timezone')
    if policy is not None and (policy.get('mode')!='dry_run' or policy.get('experimental_assessment')!=value):
        raise ValueError('Experimental assessment is restricted to the same authorized dry-run human-review policy')
    return dict(model_qualification='experimental_unverified',human_review_required=True,
                configured_model=value['model'],experimental_authorized_at=value['authorized_at'])


def experimental_metadata(metadata):
    return isinstance(metadata,dict) and (metadata.get('model_qualification')=='experimental_unverified' or metadata.get('human_review_required') is True)
