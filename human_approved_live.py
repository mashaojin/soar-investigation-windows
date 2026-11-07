"""Explicit operator acceptance of an unqualified model; not block approval."""
from datetime import datetime
from lab_config import load_profile


def authorization(settings, policy=None):
    value=settings.get('human_approved_live')
    if value is None:return {}
    lab=load_profile(settings)
    from provider_state import effective
    route=effective(settings)
    required={'model','authorized_at','accept_unqualified_model'}
    if (not isinstance(value,dict) or not required<=set(value) or set(value)-required-{'provider','provider_binding'}
            or value['accept_unqualified_model'] is not True or lab['platform']!='windows-hyperv'
            or value['model']!=route['model'] or value.get('provider','ollama')!=route['provider']
            or (route['selection_id']!='default' and value.get('provider_binding')!=route['binding'])
            or settings.get('experimental_assessment')):
        raise ValueError('Invalid model-bound human-approved live authorization')
    stamp=datetime.fromisoformat(value['authorized_at'].replace('Z','+00:00'))
    if stamp.tzinfo is None:raise ValueError('Live authorization requires a timezone')
    if policy is not None and (policy.get('mode')!='live' or policy.get('experimental_assessment')
            or policy.get('human_approved_live')!=value
            or policy.get('live_enabled_after')!=value['authorized_at']
            or policy.get('live_rehearsal_authorized_at')!=value['authorized_at']):
        raise ValueError('Human-approved live authorization differs from activation policy')
    return dict(human_approved_live=dict(value),model_qualification='operator_accepted_unqualified')
