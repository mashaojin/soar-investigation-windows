"""Read-only presentation of recorded investigations and plan management context."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re

from approved_plans import select_plan
from ssh_live_investigation import incident_context
from ssh_correlation import scope, recorded_plan, ready_at
from ssh_scenarios import timestamp


def document_key(plan):
    path, digest = plan.get('source_document'), plan.get('source_sha256')
    if not isinstance(path,str) or not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):
        return None
    return hashlib.sha256((str(Path(path).resolve())+'\0'+digest).encode()).hexdigest()[:32]


def plan_view(plan, now=None, lab=None):
    from lab_config import load_profile,validate_profile
    lab=validate_profile(lab) if lab is not None else load_profile()
    now=now or datetime.now(timezone.utc)
    result=dict(plan)
    start,end=timestamp(plan['start']),timestamp(plan['end'])
    result['timing']='upcoming' if now<start else 'active' if now<end else 'expired'
    source=plan['source_ips'][0]
    command=None
    if (plan['approval_status']=='approved' and source==lab['trust_client']['ip']
            and plan['target_ip']==lab['victim']['ip'] and plan['target_port']==22
            and set(plan['allowed_accounts'])=={'soc_test'} and plan['maximum_failed_attempts']>=6):
        command='python3 ~/soc-demo/ssh_demo_client.py --mode approved --execute'
        if lab['platform']=='windows-hyperv':command+=' --lab-config ~/soc-demo/lab.local.json'
    result['run_instructions']={
        'vm':{lab['trust_client']['ip']:lab['trust_client']['vm'],lab['attacker']['ip']:lab['attacker']['vm']}.get(source,'Source VM'),
        'command':command, 'start':plan['start'],'end':plan['end'],
        'waiting_until':(end+timedelta(seconds=30)).isoformat(),
        'scope_note':'Run once within the permitted window. Use only the listed accounts and stay within the total attempt limit.',
        'telegram_note':'Watch for the incident report in Telegram. Any eligible response needs a separate incident-bound approval. Check the message for the response mode.'}
    return result


def authorization(incident,plans,now,plan_error=None,lab=None):
    metadata=incident.get('metadata',{})
    direct=metadata.get('investigation')
    if metadata.get('engine') in ('ollama_direct','gemini_direct') and direct:
        evidence=direct['plan_evidence']
        plan=evidence['plan']
        return {'source':'recorded','plan':plan_view(plan,now,lab) if plan else None,
                'checks':evidence['checks'],'scope_comparison':evidence['scope_comparison']}
    for call in incident.get('metadata',{}).get('tool_trace',[]):
        if call.get('tool')=='get_approved_test_plan' and isinstance(call.get('result'),dict):
            evidence=call['result']
            if 'plan' in evidence:
                plan=evidence['plan']
                return {'source':'recorded','plan':plan_view(plan,now,lab) if plan else None,
                        'checks':evidence.get('checks',{}),
                        'scope_comparison':evidence.get('scope_comparison',{})}
    # Never attach a newer registry plan to a completed historical assessment.
    if incident.get('report') or incident.get('status')=='complete' or incident.get('analysis_status')=='manual_review':
        return {'source':'unavailable','plan':None,'checks':{}}
    if plan_error:
        return {'source':'unavailable','plan':None,'checks':{},'error':plan_error}
    try:
        context=incident_context(incident['incident_id'],incident['evidence'])
        plan=recorded_plan(incident['evidence'],plans) if scope(incident['evidence']) else select_plan(context,plans)
        return {'source':'scheduling','plan':plan_view(plan,now,lab) if plan else None,'checks':{}}
    except (ValueError,KeyError,TypeError):
        return {'source':'unavailable','plan':None,'checks':{},'error':'Correlation or authorization scope needs review'}


def incident_view(incident,plans,now=None,plan_error=None,lab=None):
    now=now or datetime.now(timezone.utc)
    auth=authorization(incident,plans,now,plan_error,lab)
    analysis=incident.get('analysis_status',incident.get('status'))
    approval=incident.get('approval') or {}
    response=approval.get('status')
    report=incident.get('report')
    ai_verdict=(report or {}).get('verdict')
    if ai_verdict not in ('BENIGN','SUSPICIOUS','INSUFFICIENT_EVIDENCE'): ai_verdict=None
    human=incident.get('human_review')
    resolved=bool(human and human['conclusion'] in ('BENIGN','SUSPICIOUS'))
    more_evidence=bool(report and report.get('recommended_action')=='REQUEST_MORE_EVIDENCE')
    traces=incident.get('metadata',{}).get('tool_trace',[])
    deadline=None
    if not report:
        try:
            start=timestamp(incident['evidence']['window_start'])
            base=start+timedelta(seconds=120)
            deadline=ready_at(incident['evidence']) if scope(incident['evidence']) else timestamp(auth['plan']['end'])+timedelta(seconds=30) if auth.get('plan') else base
        except (ValueError,KeyError,TypeError): pass
    labels={'pending':'Awaiting Telegram decision','approved':'Response approved; validation pending',
            'dry_run_complete':'Simulated response complete','notified':'Report delivered',
            'denied':'Report only — declined','expired':'Response request expired',
            'stale':'Response request invalidated','duplicate_action':'Simulation already recorded',
            'policy_rejected':'Response needs review','delivery_unknown':'Telegram delivery needs review',
            'queued':'Queued for Telegram','sending':'Sending to Telegram',
            'live_preparing':'Preparing approved live response','live_executing':'Applying / verifying live response',
            'live_blocked':'SSH block applied; rollback pending','live_complete':'Live block removed; access restored',
            'live_failed':'Live response verification failed','live_recovery_required':'Live response needs operator review'}
    if resolved:
        code,label='human_resolved','Resolved by human review'
    elif human and human['conclusion']=='NEEDS_MORE_EVIDENCE':
        code,label='manual_review','Awaiting more evidence'
    elif analysis=='manual_review':
        code,label='manual_review','More evidence requested' if more_evidence else 'Manual review required'
    elif response in labels:
        code,label=response,labels[response]
        if code in ('queued','sending'): code='telegram_'+code
    elif report: code,label='report_ready','Report ready'
    elif analysis=='running': code,label='investigating','Gathering evidence / analyzing'
    elif auth.get('error'): code,label='manual_review','Plan configuration needs review'
    elif deadline and now<deadline: code,label='waiting','Waiting for approved plan / log arrival' if auth.get('plan') else 'Waiting for correlation window / log arrival'
    else: code,label='queued','Queued for AI assessment'
    details={'human_resolved':'The operator’s conclusion is recorded separately from the AI assessment. No firewall action was authorized by this review.',
             'manual_review':('The AI recorded an assessment and requested more evidence. No additional evidence collection or firewall response runs automatically.' if more_evidence else 'The investigation needs human review. This workflow status is separate from any recorded AI verdict.'),
             'investigating':'The worker is collecting SSH evidence or requesting a direct AI assessment. These phases are not separately recorded.',
             'waiting':'The complete evidence window must close before assessment.',
             'queued':'Waiting for the worker and collection catch-up; this page does not assert monitor health.',
             'notified':'A report was delivered. No response approval was required.',
             'pending':'Use the incident-bound buttons in Telegram. Plan approval does not approve a response.',
             'dry_run_complete':'The approved response was simulated. No firewall command was executed.',
             'denied':'The report was retained and no response was executed.',
             'expired':'The request expired without response execution.'}
    decision_required=bool(approval.get('plan')) if approval else False if analysis=='manual_review' else None
    decision_state='skipped' if decision_required is False else 'waiting'
    if decision_required and response in ('approved','dry_run_complete','duplicate_action','live_preparing','live_executing','live_blocked','live_complete','live_failed','live_recovery_required'): decision_state='done'
    elif decision_required and response in ('denied','expired','stale','policy_rejected'): decision_state='attention'
    final_state='done' if response in ('notified','dry_run_complete','duplicate_action','denied','expired','stale','live_complete') else 'attention' if response in ('live_failed','live_recovery_required','policy_rejected') else 'active' if response in ('live_preparing','live_executing','live_blocked') else 'waiting'
    final_label={'notified':'Report delivered','dry_run_complete':'Simulation complete',
                 'duplicate_action':'No duplicate action','denied':'Report retained',
                 'expired':'No action — expired','stale':'No action — invalidated',
                 'live_complete':'Block removed / verified','live_blocked':'Temporary SSH block',
                 'live_failed':'Verification failed','live_recovery_required':'Recovery needs review'}.get(response,'Delivery / response')
    notice=(incident.get('review_context') or {}).get('notification') or {}
    if analysis=='manual_review' and not approval:
        final_label='Review notice sent' if notice.get('status')=='sent' else 'Review notification'
        final_state='done' if notice.get('status')=='sent' else 'waiting'
    stages=[{'label':'Detection','state':'done'},
            {'label':'Evidence','state':'done' if incident.get('metadata',{}).get('assessment_data') or len(traces)>=2 else 'active' if analysis=='running' else 'waiting'},
            {'label':'AI assessment','state':'attention' if analysis=='manual_review' else 'done' if report else 'active' if analysis=='running' else 'waiting'},
            {'label':'Approval not required' if decision_required is False else 'Response approval','state':decision_state},
            {'label':final_label,'state':final_state}]
    if analysis=='manual_review' or human:
        stages.insert(3,{'label':'Human review','state':'done' if resolved else 'attention'})
    if resolved:
        stages[1]['state']='done' if incident.get('metadata',{}).get('assessment_data') or len(traces)>=2 else 'skipped'
        if stages[1]['state']=='skipped': stages[1]['label']='Evidence unavailable'
        stages[2]={'label':'AI assessment' if report else 'No AI verdict','state':'done' if report else 'skipped'}
        stages[4]={'label':'No action authorized','state':'skipped'}
        stages[5]={'label':'Review saved','state':'done'}
    completed=sum(s['state'] in ('done','skipped') for s in stages)
    if decision_state=='attention' and response in ('denied','expired','stale'): completed+=1
    phase={'kind':'indeterminate','label':label}
    if code=='waiting' and deadline:
        start=timestamp(auth['plan']['start']) if auth.get('plan') else timestamp(incident['evidence']['window_start'])
        phase={'kind':'determinate','label':'Evidence-window time elapsed','start':start.isoformat(),'end':deadline.isoformat()}
    elif response=='pending' and approval.get('created_at') is not None and approval.get('expires_at') is not None:
        phase={'kind':'determinate','label':'Approval-window time elapsed — awaiting your decision',
               'start':datetime.fromtimestamp(approval['created_at'],timezone.utc).isoformat(),
               'end':datetime.fromtimestamp(approval['expires_at'],timezone.utc).isoformat()}
    elif response=='live_blocked':
        action=incident.get('live_action',{}); due=action.get('rollback_due_at')
        if due:
            phase={'kind':'determinate','label':'Temporary block timer — removal still requires verification',
                   'start':datetime.fromtimestamp(due-60,timezone.utc).isoformat(),
                   'end':datetime.fromtimestamp(due,timezone.utc).isoformat()}
    if completed==len(stages) or analysis=='manual_review' or response in ('live_failed','live_recovery_required','policy_rejected'):
        phase={'kind':'paused' if completed<len(stages) else 'complete','label':label}
    return {'status':code,'label':label,'ai_verdict':ai_verdict,'workflow_attention':code=='manual_review','human_resolved':resolved,'detail':details['human_resolved'] if resolved else incident.get('error') or details.get(code,''),
            'waiting_until':deadline.isoformat() if deadline and code in ('waiting','queued','investigating') else None,
            'authorization':auth,'stages':stages,'response_approval_required':decision_required,
            'progress':{'completed':completed,'total':len(stages),'phase':phase}}


def document_references(state):
    """Allow only Word sources registered or retained in actual incident evidence."""
    plans=list(state.get('plans',[]))
    for incident in state.get('history',{}).get('incidents',[]):
        plan=incident.get('view',{}).get('authorization',{}).get('plan')
        if plan: plans.append(plan)
    return {document_key(plan):plan for plan in plans if document_key(plan)}
