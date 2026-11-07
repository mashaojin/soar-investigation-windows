'use strict';
const $=id=>document.getElementById(id);
let zone='America/Vancouver';
const entryZone=Intl.DateTimeFormat().resolvedOptions().timeZone;
function readStore(key,fallback){try{return JSON.parse(localStorage.getItem(key))||fallback;}catch{return fallback;}}
const saved=readStore('soar-investigation-ui-v2',{});
const ui={selected:typeof saved.selected==='string'?saved.selected:null,open:saved.open&&typeof saved.open==='object'?saved.open:{},focusPlan:saved.focusPlan||null,drawerOpen:!!saved.drawerOpen};
let data=null,review=null,busy=false,refreshing=false,mainSignature='',plansSignature='',restored=false;
function saveUI(){try{localStorage.setItem('soar-investigation-ui-v2',JSON.stringify(ui));}catch{}}
function node(tag,text,cls){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;}
function button(text,action,cls){const el=node('button',text,cls);el.type='button';el.onclick=action;return el;}
function parseTime(value){if(typeof value==='string'&&/^\d{4}-\d\d-\d\d /.test(value))value=value.replace(' ','T')+'Z';return new Date(value);}
function formatTime(value,compact=false,seconds=false){const d=parseTime(value);return Number.isNaN(d.getTime())?'Not recorded':d.toLocaleString(undefined,{timeZone:zone,dateStyle:compact?'short':'medium',timeStyle:seconds?'medium':'short'});}
function jsonBlock(value){return node('pre',JSON.stringify(value,null,2));}
function disclosure(key,label,content,defaultOpen=false){const el=node('details');el.open=ui.open[key]??defaultOpen;el.append(node('summary',label),content);el.addEventListener('toggle',()=>{ui.open[key]=el.open;saveUI();});return el;}
function definition(rows,cls){const el=node('dl',undefined,cls);for(const [key,value] of rows)el.append(node('dt',key),node('dd',value??'Not recorded'));return el;}
function badge(text,kind){return node('span',text,'badge '+(kind||''));}
function verdictClass(value){return value==='SUSPICIOUS'?'suspicious':value==='BENIGN'?'benign':'review';}
function severityLabel(value){return value==='SUSPICIOUS'?'Suspicious':value==='BENIGN'?'Benign':value==='INSUFFICIENT_EVIDENCE'?'Insufficient evidence':'No verdict yet';}
function severityIcon(value){const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('class','severity-icon');svg.setAttribute('aria-hidden','true');svg.setAttribute('fill','none');svg.setAttribute('stroke','currentColor');svg.setAttribute('stroke-width','2');svg.setAttribute('stroke-linecap','round');svg.setAttribute('stroke-linejoin','round');const kind=verdictClass(value);if(kind!=='suspicious'){const circle=document.createElementNS(ns,'circle');circle.setAttribute('cx','12');circle.setAttribute('cy','12');circle.setAttribute('r','9');svg.append(circle);}for(const d of kind==='suspicious'?['M10.3 3.5a2 2 0 0 1 3.4 0l8 14A2 2 0 0 1 20 20H4a2 2 0 0 1-1.7-2.5z','M12 8v5m0 3h.01']:kind==='benign'?['m8 12 3 3 5-6']:['M12 7v5l3 2']){const path=document.createElementNS(ns,'path');path.setAttribute('d',d);svg.append(path);}return svg;}
function severityBadge(value){const el=node('span',undefined,'incident-severity '+verdictClass(value));el.setAttribute('aria-label','AI verdict: '+severityLabel(value));el.append(severityIcon(value),document.createTextNode(severityLabel(value)));return el;}
function assessmentVerdict(incident){return Object.hasOwn(incident.view||{},'ai_verdict')?incident.view.ai_verdict:incident.report?.verdict;}
function entries(){return data?.history?.incidents||[];}
function technicalPlan(plan,key){const body=node('div',undefined,'technical');body.append(node('p','Source: '+(plan.source_format||'Historical record')+' · Version: '+(plan.version||'legacy')),jsonBlock(plan));return disclosure(key,'Technical details and provenance',body);}
function planFields(plan,key){const body=node('div');body.append(definition([
['Plan',plan.id],['Operator',plan.owner],['Approval',plan.approval_status],['Source → target',plan.source_ips.join(', ')+' → '+plan.target_ip+':'+plan.target_port],['Accounts',plan.allowed_accounts.join(', ')],['Failure limit',String(plan.maximum_failed_attempts)+' total'],['Starts',formatTime(plan.start)],['Ends',formatTime(plan.end)],['Timezone',zone],['UTC window',plan.start+' → '+plan.end],['Scope',plan.scope],['Stop conditions',(plan.stop_conditions||[]).join('; ')]
],'plan-fields'));
body.append(technicalPlan(plan,key+':technical'));return body;}
function runInstructions(plan,key,open=false){const body=node('div');const run=plan.run_instructions;body.append(node('p',plan.timing==='expired'?'This window has ended. Repeat with new times before running a new test.':plan.timing==='upcoming'?'Wait until the permitted start time before running the test.':'This test window is active.',plan.timing==='expired'?'window-ended':''));
body.append(definition([['VM',run.vm],['Permitted window',formatTime(run.start)+' → '+formatTime(run.end)],['Timezone',zone],['Analysis eligible after',formatTime(run.waiting_until,false,true)]]));
if(run.command){body.append(node('p','Run once on the named VM:'),node('pre',run.command));}
else body.append(node('p','No preset command matches this account scope. Use a manual SSH test limited to the reviewed accounts and total attempt limit.'));
body.append(node('p',run.scope_note),node('p',run.telegram_note),node('p','Gemma processing can take up to another two minutes after the evidence window closes. The dashboard shows saved state; it does not start the monitor.','muted'));
const result=disclosure(key,'Run instructions',body,open);result.className='run-instructions';return result;}
function historyWorkflow(incident){const el=node('span',undefined,'incident-status'+(incident.view?.workflow_attention?' needs-review':''));el.setAttribute('aria-label','Investigation status: '+(incident.view?.label||incident.status));if(incident.view?.workflow_attention)el.append(severityIcon(null));el.append(document.createTextNode(incident.view?.label||incident.status));return el;}
function renderHistory(){const rows=entries();const requested=location.hash.match(/^#incident=([a-f0-9]{64})$/)?.[1];if(requested&&rows.some(i=>i.incident_id===requested)&&ui.lastIncidentLink!==requested){ui.selected=requested;ui.lastIncidentLink=requested;saveUI();}if(!rows.some(i=>i.incident_id===ui.selected)){ui.selected=rows[0]?.incident_id||null;saveUI();}
$('incidents').replaceChildren(...rows.map(i=>{const b=button('',()=>{ui.selected=i.incident_id;saveUI();renderHistory();renderSelected();},i.incident_id===ui.selected?'active':'');b.setAttribute('aria-current',i.incident_id===ui.selected?'true':'false');b.append(node('span',i.evidence.source_ip||'Unknown source','incident-source'),node('span',i.incident_number||i.incident_id.slice(0,16),'incident-number'),node('span',formatTime(i.incident_occurred_at||i.evidence.window_start,true),'incident-date'),severityBadge(assessmentVerdict(i)),historyWorkflow(i));return b;}));
if(!rows.length)$('incidents').append(node('p','No recorded incidents yet.','muted small'));
$('incident-count').textContent=String(data.history?.counts?.incidents??rows.length);
}
function renderProgress(r){const p=r?.view?.progress;if(!p)return;
$('stage-progress').max=p.total;$('stage-progress').value=p.completed;
$('stage-progress-label').textContent=p.completed+' / '+p.total+' stages resolved';
const phase=p.phase;$('phase-label').textContent=phase.label;$('phase-time').textContent='';
$('phase-box').hidden=['complete','paused'].includes(phase.kind);
const bar=$('phase-progress');bar.hidden=false;bar.removeAttribute('value');bar.dataset.kind=phase.kind;bar.dataset.start=phase.start||'';bar.dataset.end=phase.end||'';
bar.setAttribute('aria-label',phase.label);updateTimers();}
function renderService(){const service=data?.history?.service||{},fresh=service.running&&Date.now()/1000-(service.last_heartbeat||0)<=20;
$('service-label').textContent=fresh?'Monitor running':service.label==='Monitor running'?'Monitor heartbeat overdue':service.label||'Monitor status unavailable';
$('service-progress').hidden=!fresh;
const components=service.components||{},parts=[];
if(fresh){parts.push('Watching for new alerts');if(service.assessment_version==='gemma_judgment_v2')parts.push('AI judgment v2');if(service.correlation_version==='ssh_correlation_v1')parts.push('Plan / 2-minute grouping');if(components.collector?.status==='catching_up')parts.push('Catching up with logs');if(['error','gap'].includes(components.collector?.status))parts.push('Collection needs attention');if(components.telegram?.status==='error'||components.telegram?.status==='stopped')parts.push('Telegram needs attention');}
else parts.push('Saved incidents remain available; continuous processing is not confirmed.');
$('service-detail').textContent=parts.join(' · ');
if($('experimental-notice'))$('experimental-notice').hidden=!data?.experimental_assessment;
if($('provider-routing')){const p=data?.assessment_provider;$('provider-routing').textContent=p?'AI: '+p.provider+' / '+p.model+' · '+p.route.toUpperCase():'AI route unavailable';}
const mode=data?.response_policy?.mode;$('response-mode').textContent=mode==='live'?'Response: LIVE · '+data.response_policy.duration_seconds+'s':mode==='dry_run'?'Response: dry run':'Response mode unavailable';}
function updateTimers(){const bar=$('phase-progress');if(bar?.dataset.kind==='determinate'){
const start=new Date(bar.dataset.start).getTime(),end=new Date(bar.dataset.end).getTime(),now=Date.now();
if(Number.isFinite(start)&&end>start){bar.max=(end-start)/1000;bar.value=Math.max(0,Math.min(bar.max,(now-start)/1000));
const remaining=Math.max(0,Math.ceil((end-now)/1000));$('phase-time').textContent=remaining?Math.floor(remaining/60)+'m '+String(remaining%60).padStart(2,'0')+'s remaining':'Time elapsed — waiting for recorded confirmation';}}
const active=data?.history?.service?.running&&Date.now()/1000-(data.history.service.last_heartbeat||0)<=20;if(bar?.dataset.kind==='indeterminate'){bar.hidden=!active;if(!active)$('phase-time').textContent='Processing not confirmed — check monitor status';}
renderService();}
function renderSelected(){const r=entries().find(i=>i.incident_id===ui.selected);$('detail').hidden=!r;$('empty').hidden=!!r;
if(!r){$('human-review-panel').hidden=true;$('authorization').replaceChildren(node('p','Select an incident to inspect its recorded authorization.','muted'));$('response-context').replaceChildren(node('p','No incident selected.','muted'));return;}
const m=r.metadata||{},report=r.report,shown=r.display_report||report,trace=m.tool_trace||[],v=r.view||{};
$('title').textContent=(r.evidence.source_ip||'Unknown')+' → '+(r.evidence.destination_ip||'Unknown')+':'+(r.evidence.destination_port||22);
const severity=assessmentVerdict(r), assessment=severityLabel(severity);
$('verdict').replaceChildren(severityIcon(severity),document.createTextNode(assessment));
$('verdict').className='badge '+verdictClass(severity);
$('verdict').setAttribute('aria-label','AI verdict: '+assessment);
const correlation=r.evidence.correlation;
$('incident-time').textContent=correlation?(correlation.kind==='approved_plan'?'Approved-plan window: ':'Correlation window: ')+formatTime(r.evidence.window_start)+' → '+formatTime(correlation.end)+' · '+zone+' · '+r.alert_count+' grouped alerts':'Recorded '+formatTime(r.evidence.window_start)+' · '+zone;
$('incident-id').textContent=(r.incident_number||r.incident_id.slice(0,16))+' · revision '+r.revision;
if(r.incident_occurred_at)$('incident-time').textContent='First recorded alert: '+formatTime(r.incident_occurred_at,false,true)+' · '+zone+' · '+$('incident-time').textContent;
renderProgress(r);renderHumanReview(r);$('investigation-status').replaceChildren(...(v.workflow_attention?[severityIcon(null)]:[]),document.createTextNode('Investigation status: '+(v.label||r.status)));$('investigation-status').className=v.workflow_attention?'badge review workflow-review':'';$('status-detail').textContent=v.detail||'';
$('waiting-deadline').hidden=!v.waiting_until||!!report;$('waiting-deadline').textContent=v.waiting_until?'Evidence window closes for analysis: '+formatTime(v.waiting_until,false,true)+' ('+zone+')':'';
$('stages').replaceChildren(...(v.stages||[]).map(s=>{const el=node('li',undefined,'stage '+s.state);el.append(node('span',({done:'✓',active:'…',attention:'!',skipped:'—',waiting:'○'})[s.state]||'○'),document.createTextNode(s.label));return el;}));
$('model-name').textContent=(m.model||(r.analysis_status==='manual_review'?'No validated AI assessment':'Awaiting analysis'))+(report?(m.assessment_version==='gemma_judgment_v2'?' · model-led judgment':m.engine==='ollama_direct'?' · historical rule-guided':' · historical Hermes'):'');$('reason').textContent=shown?.reason||r.error?.replace(/^Manual review required\. No automatic retry\. \w+: /,'')||(v.human_resolved?'No AI assessment was recorded.':v.detail||'No assessment recorded yet.');
if(m.model_qualification==='experimental_unverified')$('model-name').textContent=(m.model||m.configured_model||'Requested model')+' · experimental, unverified';
if(m.provider)$('model-name').textContent=(m.model||m.configured_model||'Requested model')+' · '+m.provider+' / '+(m.model_route||'route unavailable')+(m.model_version?' · returned '+m.model_version:'')+(m.model_qualification==='experimental_unverified'?' · experimental, unverified':'');
$('recommendations').replaceChildren(...(shown?.recommendations||[]).filter(x=>!['none','n/a'].includes(x.toLowerCase())).map(x=>node('li',x)));
$('limits').textContent='Requests: '+(m.request_count??'—')+' · Last input: '+(m.input_bytes??'—')+' bytes · Truncated: '+(m.truncated===undefined?'not recorded':m.truncated?'yes':'no')+(report?.coverage?' · Coverage: '+report.coverage:'');
$('judgment-facts')?.remove();
if(report?.claims){const checked=node('div',undefined,'judgment-facts');checked.id='judgment-facts';
checked.append(node('p','AI recommended next step: '+({REPORT_ONLY:'Report only',REQUEST_BLOCK_APPROVAL:'Request temporary-block approval',REQUEST_MORE_EVIDENCE:'Request more evidence'}[report.recommended_action]||report.recommended_action||'Not recorded'),'small'),node('p','Python checked these structured facts against the collected evidence and recorded test-plan scope. These checks do not certify every sentence of the explanation.','muted small'),disclosure(r.incident_id+':claims','Checked factual claims',jsonBlock(report.claims)));$('limits').after(checked);}
const facts=m.assessment_data?.observed_facts,policy=m.assessment_data?.policy_findings;
$('tool-count').textContent=facts?Object.keys(facts).length+' evidence references':(trace.length?trace.length+' historical evidence calls':'Awaiting scoped evidence');
$('tools').replaceChildren();$('policy-findings').replaceChildren();
const factCard=(id,source,result,limitation)=>{const card=node('div',undefined,'tool-card');card.id='evidence-'+id;card.append(node('strong',id+' · '+source));
if(result.source_ip)card.append(node('p',result.source_ip+' → '+(result.target_ip||result.destination_ip||'unknown'),'muted small'));
if(result.start||result.window_start){const end=result.end||result.correlation?.end;card.append(node('p','Window: '+formatTime(result.start||result.window_start,false,true)+(end?' → '+formatTime(end,false,true):' (historical grouped minute)'),'muted small'));}
if(result.failed_password_count!==undefined){card.append(definition([['Failed passwords',result.failed_password_count],['Successful logins',result.successful_login_count],['Attempted accounts',Object.entries(result.failed_accounts||{}).map(([a,n])=>a+': '+n).join(', ')],['Coverage',result.coverage],...(result.connection_drop_count!==undefined?[['SSH connection drops',result.connection_drop_count],['SSH penalty activations',result.penalty_event_count],['Failure span',result.failed_password_span_seconds===null?'No failures recorded':result.failed_password_span_seconds+' seconds']]:[])]));}
if('plan_available' in result){card.append(node('p',result.plan_available?'Matching authorization found.':'No matching approved plan.'));if(result.unexpected_accounts?.length)card.append(node('p','Outside permitted accounts: '+result.unexpected_accounts.join(', '),'scope-warning'));if(result.observed_failed_attempts!==undefined)card.append(node('p','Observed failures: '+result.observed_failed_attempts+' / permitted '+result.maximum_failed_attempts+(result.attempt_limit_exceeded?' — limit exceeded':' — within limit')));if(result.plan_checks)card.append(definition(Object.entries(result.plan_checks).map(([k,v])=>[k.replaceAll('_',' '),v?'yes':'no'])));}
if(result.alert_count!==undefined)card.append(node('p','Grouped connection alerts: '+result.alert_count));
if('plan' in result)card.append(node('p',result.plan?'Authorization snapshot: '+result.plan.id+' · permitted: '+result.plan.allowed_accounts.join(', '):'No matching approved plan.'));
card.append(node('p',limitation,'muted small'),disclosure(r.incident_id+':'+id,'Inspect recorded data',jsonBlock(result)));return card;};
if(facts){for(const [id,fact] of Object.entries(facts))$('tools').append(factCard(id,fact.source,fact.data,fact.limitation));
for(const [id,finding] of Object.entries(policy||{})){$('policy-findings').append(factCard(id,finding.source,finding.data,'Computed from '+finding.evidence_refs.join(', ')+'. These comparisons do not establish successful compromise.'));}}
else{for(const [index,call] of trace.entries()){$('tools').append(factCard('historical-'+index,call.tool,call.result||{},'Historical Hermes evidence call; retained unchanged.'));}
const comparison=v.authorization?.scope_comparison;if(comparison&&Object.keys(comparison).length)$('policy-findings').append(factCard('historical-policy','Recorded Python scope comparison',comparison,'Historical findings retained with this incident.'));
else $('policy-findings').append(node('p','No deterministic findings recorded yet.','muted small'));}
if(!facts&&!trace.length)$('tools').append(node('p','No scoped authentication evidence recorded yet.','muted small'));
const refBox=node('div',undefined,'assessment-references');
if(report?.evidence_refs?.length){refBox.append(node('span','AI-cited references: '));for(const id of report.evidence_refs){const link=node('a',id);link.href='#evidence-'+id;refBox.append(link,document.createTextNode(' '));}const dependencies=(report.resolved_evidence_refs||[]).filter(id=>!report.evidence_refs.includes(id));if(dependencies.length){refBox.append(node('span',' · Python-linked sources: '));for(const id of dependencies){const link=node('a',id);link.href='#evidence-'+id;refBox.append(link,document.createTextNode(' '));}}refBox.append(node('p',report.reference_limit||'References identify supplied evidence; they do not verify every prose claim.','muted small'));}
else if(report)refBox.append(node('p',report.format==='advisory_text'?'No evidence IDs cited.':'Historical assessment: structured claim references were not recorded.','muted small'));
$('original-ai-details')?.remove();refBox.id='assessment-references';const technical=node('div');technical.append(refBox,jsonBlock({report:report||null,rejected_output:m.rejected_output||null,error:r.error||null,analysis_status:r.analysis_status}));const original=disclosure(r.incident_id+':original-ai','Original AI output and evidence references',technical);original.id='original-ai-details';$('limits').after(original);
$('incident-technical').replaceChildren(disclosure(r.incident_id+':'+r.revision+':incident','Incident technical details',jsonBlock(r.evidence)));
renderAuthorization(r);renderResponse(r);
}
function renderAuthorization(r){const a=r.view.authorization,p=a.plan,body=$('authorization'),key=r.incident_id+':'+r.revision+':plan';body.replaceChildren();
if(a.source==='unavailable'){body.append(node('p',a.error||'Authorization evidence was not recorded for this incident.','muted'));return;}
if(!p){body.append(badge('No matching approved plan','suspicious'),node('p',a.source==='recorded'?'The recorded authorization lookup found no match.':'No plan matches the incident’s scheduling scope. Python has not collected its authorization snapshot yet.'));return;}
body.append(badge(a.source==='recorded'?'Recorded plan match':'Scheduled plan'),node('p',p.id),node('p',a.source==='recorded'?'Authorization evidence retained with this assessment.':'Used to schedule evidence collection; not yet retained as collected evidence.','muted small'));
body.append(definition([['Accounts',p.allowed_accounts.join(', ')],['Limit',p.maximum_failed_attempts+' failures'],['Window',formatTime(p.start)+' → '+formatTime(p.end)]]));
const scope=a.scope_comparison||{};
if(scope.unexpected_accounts?.length)body.append(node('p','Outside scope: '+scope.unexpected_accounts.join(', '),'scope-warning'));
if(scope.attempt_limit_exceeded)body.append(node('p','Attempt limit exceeded: '+scope.observed_failed_attempts+' / '+scope.maximum_failed_attempts,'scope-warning'));
if(Object.keys(a.checks||{}).length){const checks=node('ul',undefined,'check-list');for(const [k,value] of Object.entries(a.checks))checks.append(node('li',k.replaceAll('_',' ')+': '+(value?'yes':'no')));body.append(checks);}
body.append(disclosure(key+':view','View plan',planFields(p,key)));

}
function renderResponse(r){const body=$('response-context'),a=r.approval;body.replaceChildren();
if(!a){body.append(node('p',r.view?.human_resolved?(r.human_review?.conclusion==='SUSPICIOUS'?'Suspicious review saved. Eligible incidents receive a separate live approval request in Telegram.':'Human review saved. No firewall response was authorized.'):r.review_context?.review_optional?'Report only. Human review is optional.':r.review_context?.can_review?'Human review is needed. No firewall response has been proposed.':r.report?'Report ready; no Telegram delivery recorded yet.':'Waiting for the assessment.','muted'));return;}
const label={pending:'Awaiting your Telegram decision',approved:'Response approved',notified:'Report delivered',denied:'Report only — declined',expired:'Request expired',stale:'Request invalidated',dry_run_complete:'Simulated response complete',duplicate_action:'Equivalent simulation already recorded',policy_rejected:'Response validation failed',delivery_unknown:'Delivery needs review',queued:'Queued for delivery',sending:'Sending report',live_preparing:'Preparing live response',live_executing:'Applying / verifying live response',live_blocked:'Temporary SSH block applied',live_complete:'Live block removed; connectivity restored',live_failed:'Live response verification failed',live_recovery_required:'Live response needs operator review'}[a.status]||a.status;
body.append(badge(label,['pending','expired','stale','policy_rejected','delivery_unknown'].includes(a.status)?'suspicious':''));
if(a.plan){body.append(node('p','Proposed scope: '+a.plan.source_ip+' → '+a.plan.destination_ip+':'+a.plan.port+' for '+a.plan.duration_seconds+' seconds.'),node('p',a.plan.mode==='live'?'LIVE response. Approval automatically starts the guarded block; monitoring continues.':'Dry-run only. No firewall rule is applied.'));
if(a.status==='pending')body.append(node('p','Use YES / NO on this incident’s Telegram message.'));
if(['pending','approved'].includes(a.status))body.append(node('p','Approval expires: '+formatTime(a.expires_at*1000,false,true),'muted small'));
if(a.status==='denied')body.append(node('p','Rejection recorded; the incident report is retained.'));
if(a.status==='expired')body.append(node('p','The approval window elapsed without response execution.'));
}else body.append(node('p','Report-only path. Response approval was not required.'));
if(r.live_action){const action=r.live_action,record=action.result||{};body.append(node('p','Live run: '+action.run_id,'muted small'));if(action.rollback_due_at)body.append(node('p','Rollback scheduled: '+formatTime(action.rollback_due_at*1000,false,true)));if(record.error)body.append(node('p',record.error,'error'));if(a.status==='live_recovery_required')body.append(node('p','Inspect the victim console and this run’s rollback helper. Do not repeat the action.','scope-warning'));body.append(disclosure(r.incident_id+':live','Live execution receipt',jsonBlock(record)));}
}
function renderNextPlan(){const target=$('next-plan'),p=data.next_plan;target.replaceChildren();if(data.plan_error){target.append(node('p','Active plan cannot be determined.','error'),node('p',data.plan_error,'muted'));return;}
if(!p){target.append(node('p','No active test plan','muted'),node('p','No approved active or upcoming window. Previous plans remain in plan history.','muted small'),button('New test plan',()=>openEditor()));return;}
target.append(badge(p.timing.toUpperCase()),node('p',p.id,'muted small'),node('p',p.source_ips.join(', ')+' → '+p.target_ip+':'+p.target_port),node('p',formatTime(p.start)+' → '+formatTime(p.end),'muted small'),node('p','This is the next test plan, not necessarily the plan matched to the selected incident.','muted small'));
const actions=node('div',undefined,'card-actions');actions.append(button('View plan',()=>{openPlans();showPlan(p.id);}),button('Run instructions',()=>{ui.focusPlan=p.id;saveUI();openPlans();renderInstructions(true);}));target.append(actions);}
function showPlan(id){ui.open['plan-history']=true;ui.open['plan:'+id]=true;saveUI();$('plan-history').open=true;renderPlans(true);$('plan-history').scrollIntoView({block:'start'});}
function renderPlans(force=false){const signature=JSON.stringify([data.plans,data.plan_error]);if(!force&&signature===plansSignature)return;plansSignature=signature;
const plans=[...(data.plans||[])].sort((a,b)=>new Date(b.start)-new Date(a.start));$('plan-count').textContent='('+plans.length+')';$('drawer-plan-count').textContent=plans.length+' retained plan versions';$('plan-history-count').textContent='('+plans.length+')';
$('plan-error').hidden=!data.plan_error;$('plan-error').textContent=data.plan_error||'';
if(!plans.length){$('plans').replaceChildren(node('p','No approved plans recorded.','muted'));renderInstructions();return;}
const table=node('table',undefined,'plan-table'),head=node('thead'),headRow=node('tr');for(const label of ['Status','Local window','Source → target','Accounts','Actions'])headRow.append(node('th',label));head.append(headRow);table.append(head);const body=node('tbody');
plans.forEach((p,index)=>{const row=node('tr');const values=[badge(p.timing.toUpperCase(),p.timing==='active'?'benign':''),node('span',formatTime(p.start,true)+' → '+formatTime(p.end,true)),node('span',p.source_ips.join(', ')+' → '+p.target_ip+':'+p.target_port),node('span',p.allowed_accounts.join(', '))];
values.forEach((content,i)=>{const td=node('td');td.dataset.label=['Status','Local window','Source → target','Accounts'][i];td.append(content);row.append(td);});
const expansion=node('tr',undefined,'plan-details-row');expansion.hidden=!ui.open['plan:'+p.id];expansion.id='plan-details-'+index;const full=node('td');full.colSpan=5;full.append(node('h3',p.id),planFields(p,'history:'+p.id),button('Show run instructions',()=>{ui.focusPlan=p.id;saveUI();renderInstructions(true);}));expansion.append(full);
const actionCell=node('td');actionCell.dataset.label='Actions';const actions=node('div',undefined,'table-actions');const view=button(expansion.hidden?'View plan':'Hide plan',()=>{expansion.hidden=!expansion.hidden;ui.open['plan:'+p.id]=!expansion.hidden;saveUI();view.textContent=expansion.hidden?'View plan':'Hide plan';view.setAttribute('aria-expanded',String(!expansion.hidden));});view.setAttribute('aria-expanded',String(!expansion.hidden));view.setAttribute('aria-controls',expansion.id);actions.append(view,button('Repeat with new times',()=>openEditor(p)));actionCell.append(actions);row.append(actionCell);body.append(row,expansion);});
table.append(body);const wrap=node('div',undefined,'table-wrap');wrap.append(table);$('plans').replaceChildren(wrap);renderInstructions();}
function renderInstructions(open=false){const p=(data.plans||[]).find(p=>p.id===ui.focusPlan);const target=$('instructions-panel');target.hidden=!p;if(!p)return;
target.replaceChildren(node('h3','Instructions for approved plan'),node('p',p.id,'muted small'),runInstructions(p,'instructions:'+p.id,open));if(open){ui.open['instructions:'+p.id]=true;saveUI();target.querySelector('details').open=true;target.scrollIntoView({block:'nearest'});}}
function message(text,error=false){$('plan-message').textContent=text;$('plan-message').className=error?'error':'success';}
function invalidate(){review=null;$('plan-review').hidden=true;$('approve-plan').disabled=true;}
function localInput(date){const p=v=>String(v).padStart(2,'0');return `${date.getFullYear()}-${p(date.getMonth()+1)}-${p(date.getDate())}T${p(date.getHours())}:${p(date.getMinutes())}`;}
function rawFields(){return {owner:$('plan-owner').value,source_ip:$('plan-source').value,target_ip:$('plan-target').value,allowed_accounts:$('plan-accounts').value,maximum_failed_attempts:$('plan-limit').value,start:$('plan-start').value,end:$('plan-end').value};}
function persistDraft(){try{sessionStorage.setItem('soar-plan-form-v2',JSON.stringify({open:!$('editor').hidden,fields:rawFields()}));}catch{}}
function fillFields(values){for(const [key,id] of Object.entries({owner:'plan-owner',source_ip:'plan-source',target_ip:'plan-target',allowed_accounts:'plan-accounts',maximum_failed_attempts:'plan-limit',start:'plan-start',end:'plan-end'}))if(values[key]!==undefined)$(id).value=values[key];}
function freshTimes(after){let start=Math.floor(Date.now()/60000)*60000+120000;if(typeof after==='string')start=Math.max(start,new Date(after).getTime()+60000);const source=$('plan-source').value.trim(),target=$('plan-target').value.trim();for(let n=0;n<34;n++){const overlap=(data.plans||[]).find(p=>p.source_ips.includes(source)&&p.target_ip===target&&Math.max(start,new Date(p.start))<Math.min(start+180000,new Date(p.end)));if(!overlap)break;start=new Date(overlap.end).getTime()+60000;}
$('plan-start').value=localInput(new Date(start));$('plan-end').value=localInput(new Date(start+180000));invalidate();persistDraft();message('Fresh non-overlapping times set. Validate to review the scope.');}
function openPlans(){if(!$('plan-drawer').open)$('plan-drawer').showModal();document.body.classList.add('drawer-open');ui.drawerOpen=true;saveUI();}
function closePlans(){if($('plan-drawer').open)$('plan-drawer').close();}
function openEditor(plan){if(busy)return;if(!data?.editor_options){openPlans();message('Plan configuration is unavailable. Refresh and try again.',true);return;}
openPlans();$('editor').hidden=false;$('plan-success').hidden=true;$('editor-title').textContent=plan?'Repeat as a new test plan':'New test plan';
fillFields({owner:plan?.owner||$('plan-owner').value||'',source_ip:plan?.source_ips?.[0]||(data.editor_options.preferred_source_ip||data.editor_options.source_ips[0]),target_ip:plan?.target_ip||data.editor_options.target_ip,allowed_accounts:plan?.allowed_accounts?.join(', ')||'soc_test',maximum_failed_attempts:plan?.maximum_failed_attempts||10});freshTimes(plan?.end);$('editor').scrollIntoView({block:'start'});$('plan-owner').focus();}
function setBusy(value){busy=value;for(const el of $('plan-form').elements)el.disabled=value;$('new-plan').disabled=value;$('drawer-new-plan').disabled=value;$('approve-plan').disabled=value||!review;}
function formValues(){const raw=rawFields();return {...raw,maximum_failed_attempts:Number(raw.maximum_failed_attempts),start:new Date(raw.start).toISOString(),end:new Date(raw.end).toISOString()};}
async function post(path,body){if(!data?.csrf_token)throw new Error('Dashboard is reconnecting. Refresh and try again.');const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-SOAR-CSRF':data.csrf_token},body:JSON.stringify(body)});const result=await response.json().catch(()=>({error:'Request rejected. Refresh the dashboard and try again.'}));if(!response.ok)throw new Error(result.error||'Plan request failed.');return result;}
$('new-plan').onclick=()=>openEditor();$('drawer-new-plan').onclick=()=>openEditor();$('plans-button').onclick=openPlans;$('close-plans').onclick=closePlans;$('fresh-times').onclick=()=>freshTimes();
$('plan-drawer').addEventListener('close',()=>{ui.drawerOpen=false;document.body.classList.remove('drawer-open');saveUI();persistDraft();});
$('plan-history').open=!!ui.open['plan-history'];$('plan-history').addEventListener('toggle',()=>{ui.open['plan-history']=$('plan-history').open;saveUI();});
$('cancel-plan').onclick=()=>{invalidate();$('editor').hidden=true;persistDraft();message('Draft closed. No approval recorded.');};
$('plan-form').addEventListener('input',()=>{if(review){invalidate();message('Fields changed. Validate again before approval.');}persistDraft();});
$('plan-form').onsubmit=async event=>{event.preventDefault();if(busy)return;invalidate();setBusy(true);message('Validating scope and saving an immutable draft…');try{
review=await post('/api/plans/validate',formValues());const p=review.plan;$('review-fields').replaceChildren(...Array.from(definition([['Source → target',p.source_ips.join(', ')+' → '+p.target_ip+':'+p.target_port],['Accounts',p.allowed_accounts.join(', ')],['Failure limit',p.maximum_failed_attempts+' total'],['Starts',formatTime(p.start)],['Ends',formatTime(p.end)],['Timezone',zone],['UTC window',p.start+' → '+p.end],['Operator',p.owner],['Scope',p.scope],['Stop conditions',p.stop_conditions.join('; ')]]).childNodes));$('plan-review').hidden=false;message('Validation passed. Review the scope before approving.');$('plan-review').scrollIntoView({block:'nearest'});
}catch(error){message(error.message,true);}finally{setBusy(false);}};
$('approve-plan').onclick=async()=>{if(busy||!review)return;setBusy(true);message('Recording approval of this exact dashboard version…');try{
const result=await post('/api/plans/approve',{draft_id:review.draft_id,validation_token:review.validation_token});const p=result.plan;invalidate();$('editor').hidden=true;persistDraft();ui.focusPlan=p.id;ui.open['instructions:'+p.id]=true;saveUI();$('plan-success').replaceChildren(node('strong','Test plan approved'),node('p',p.id+' · '+formatTime(p.start)+' → '+formatTime(p.end)),node('p',data.experimental_assessment?'Experimental mode: response actions are disabled. This approves only the test plan.':'Response actions still need a separate Telegram decision.'));$('plan-success').hidden=false;message('Approval saved. Run instructions are retained with this plan.');await refresh();renderInstructions(true);
}catch(error){message(error.message,true);}finally{setBusy(false);}};
function restoreEditor(){if(restored)return;restored=true;$('time-zone').textContent='Enter times in '+entryZone+'. Review and incident times display in '+zone+'. Stored windows use UTC and whole minutes.';
$('lab-sources').replaceChildren(...(data.editor_options?.source_ips||[]).map(ip=>{const option=node('option');option.value=ip;return option;}));
try{const draft=JSON.parse(sessionStorage.getItem('soar-plan-form-v2'));if(draft?.open&&draft.fields){fillFields(draft.fields);$('editor').hidden=false;invalidate();message('Draft fields restored. Validate again to review the current scope.');}}catch{}
if(ui.drawerOpen)openPlans();}
async function refresh(){if(refreshing)return;refreshing=true;try{const response=await fetch('/api/state',{cache:'no-store'});if(!response.ok)throw new Error('Unavailable');data=await response.json();zone=data.display_timezone||'America/Vancouver';$('connection').textContent='Dashboard updated '+formatTime(data.updated_at,true);$('history-summary').textContent=(data.history?.counts?.incidents??0)+' incidents · '+(data.history?.counts?.analyses??0)+' analyses · '+(data.history?.counts?.dry_run_actions??0)+' simulations · '+(data.history?.counts?.live_actions??0)+' live responses';$('state-note').textContent='Last collection: '+formatTime(data.history?.last_collection)+' ('+zone+'). Monitor status is verified separately by heartbeat.';renderService();
const signature=JSON.stringify(data.history?.incidents||[]);if(signature!==mainSignature){mainSignature=signature;renderHistory();renderSelected();}
renderNextPlan();renderPlans();restoreEditor();const selected=entries().find(i=>i.incident_id===ui.selected);if(selected)renderProgress(selected);
}catch(error){$('connection').textContent='Dashboard unavailable · showing saved view';}finally{refreshing=false;}}
const historyMedia=matchMedia('(max-width:760px)');
function restoreHistoryPanel(){const key=historyMedia.matches?'incident-history:narrow':'incident-history:wide';$('history-panel').open=ui.open[key]??!historyMedia.matches;}
$('history-panel').addEventListener('toggle',()=>{ui.open[historyMedia.matches?'incident-history:narrow':'incident-history:wide']=$('history-panel').open;saveUI();});
historyMedia.addEventListener('change',restoreHistoryPanel);restoreHistoryPanel();
$('refresh').onclick=refresh;setInterval(refresh,5000);setInterval(updateTimers,1000);

// Append-only human review is separate from AI judgment and response approval.
let humanReviewKey='',humanReviewBusy=false,humanFollowupOpen=false;
function humanDraftKey(r){return r.incident_id+':'+r.revision+':'+r.review_context.snapshot_hash;}
function persistHumanDraft(){const r=entries().find(i=>i.incident_id===ui.selected);if(!r?.review_context)return;try{sessionStorage.setItem('soar-human-review:'+humanDraftKey(r),JSON.stringify({reviewer:$('review-reviewer').value,conclusion:$('review-conclusion').value,notes:$('review-notes').value}));}catch{}}
function renderHumanReview(r){const context=r.review_context||{},human=r.human_review,history=r.human_review_history||[],panel=$('human-review-panel');panel.hidden=!context.can_review&&!history.length;if(panel.hidden)return;
const key=context.snapshot_hash?humanDraftKey(r):r.incident_id;const currentKey=key+':'+(human?.review_id||'none');
if(humanReviewKey!==currentKey){humanReviewKey=currentKey;humanFollowupOpen=false;let draft={};try{draft=JSON.parse(sessionStorage.getItem('soar-human-review:'+key))||{};}catch{}$('review-reviewer').value=draft.reviewer||'';$('review-conclusion').value=draft.conclusion||'';$('review-notes').value=draft.notes||'';$('human-review-message').textContent='';}
const resolved=human&&human.conclusion!=='NEEDS_MORE_EVIDENCE';const label=human?({BENIGN:'Benign',SUSPICIOUS:'Suspicious',NEEDS_MORE_EVIDENCE:'More evidence needed'}[human.conclusion]):'Not reviewed';
$('human-review-status').textContent='Human review: '+label;$('human-review-status').className='badge '+(human?.conclusion==='BENIGN'?'benign':human?.conclusion==='SUSPICIOUS'?'suspicious':'review');
$('human-review-scope').textContent='Incident '+(r.incident_number||r.incident_id.slice(0,16))+' · revision '+r.revision+(human?' · '+human.reviewer+' · '+formatTime(human.created_at):' · your conclusion will be saved for this evidence revision');
$('human-review-form').hidden=!context.can_review||(resolved&&!humanFollowupOpen);$('open-followup-review').hidden=!context.can_review||!resolved||humanFollowupOpen;
for(const el of $('human-review-form').elements)el.disabled=humanReviewBusy;
const notice=context.notification,status=notice?.status;const delivered={queued:'Queued for the monitor’s Telegram handler.',sent:'Review notice sent to Telegram.',delivery_unknown:'Delivery could not be confirmed. No automatic resend.',sending:'Sending review notice…',stale:'An earlier notice was invalidated by changed evidence.',cancelled:'Queued notice cancelled because the review was resolved.'};
$('human-review-notification').textContent=delivered[status]||'Telegram can notify you to complete this review on the dashboard.';
$('notify-human-review').hidden=!context.can_review||context.review_optional||!!resolved;$('notify-human-review').disabled=humanReviewBusy||!!notice;
$('human-review-history').hidden=!history.length;
$('human-review-history-list').replaceChildren(...history.map(h=>{const item=node('div',undefined,'human-review-entry');item.append(node('strong',({BENIGN:'Benign / authorized activity',SUSPICIOUS:'Suspicious / unauthorized activity',NEEDS_MORE_EVIDENCE:'Need more evidence — keep open'})[h.conclusion]),node('p',h.reviewer+' · '+formatTime(h.created_at)+' · revision '+h.revision+(h.applies_to_current_snapshot?'':' · earlier evidence snapshot'),'muted small'),node('p',h.notes,'human-review-notes'));return item;}));}
$('human-review-form').addEventListener('input',persistHumanDraft);
$('open-followup-review').onclick=()=>{humanFollowupOpen=true;renderHumanReview(entries().find(i=>i.incident_id===ui.selected));};
$('human-review-form').onsubmit=async event=>{event.preventDefault();if(humanReviewBusy)return;const r=entries().find(i=>i.incident_id===ui.selected),context=r?.review_context;if(!context?.can_review)return;humanReviewBusy=true;renderHumanReview(r);try{const result=await post('/api/reviews/save',{incident_id:r.incident_id,revision:r.revision,snapshot_hash:context.snapshot_hash,expected_review_id:context.expected_review_id,reviewer:$('review-reviewer').value,conclusion:$('review-conclusion').value,notes:$('review-notes').value});try{sessionStorage.removeItem('soar-human-review:'+humanDraftKey(r));}catch{}await refresh();$('human-review-message').textContent=result.note;$('human-review-message').className='success';}catch(error){$('human-review-message').textContent=error.message;$('human-review-message').className='error';}finally{humanReviewBusy=false;const current=entries().find(i=>i.incident_id===ui.selected);if(current)renderHumanReview(current);}};
$('notify-human-review').onclick=async()=>{if(humanReviewBusy)return;const r=entries().find(i=>i.incident_id===ui.selected);if(!r?.review_context)return;humanReviewBusy=true;renderHumanReview(r);try{const result=await post('/api/reviews/notify',{incident_id:r.incident_id,revision:r.revision,snapshot_hash:r.review_context.snapshot_hash});await refresh();$('human-review-message').textContent=result.note;}catch(error){$('human-review-message').textContent=error.message;$('human-review-message').className='error';}finally{humanReviewBusy=false;const current=entries().find(i=>i.incident_id===ui.selected);if(current)renderHumanReview(current);}};

refresh();

window.addEventListener('hashchange',()=>{if(/^#incident=[a-f0-9]{64}$/.test(location.hash)){mainSignature='';refresh();}});
