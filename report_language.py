"""Display-only source names. Never changes saved reports, verdicts or fact claims."""
from copy import deepcopy
import re

NAMES={'E1':'network alert','E2':'SSH log summary','E3':'test-plan lookup','P1':'scope comparison'}
REF=r'(?:E[123]|P1)'
CITATIONS=re.compile(r'\s*\('+REF+r'(?:\s*(?:,|/|;|and|&)\s*'+REF+r')*\)')
QUOTED=re.compile(r'(`[^`]*`|\'[^\']*\'|"[^"]*")')
NEXT_STEPS={
    'REPORT_ONLY':'Keep the incident report; no response action is recommended.',
    'REQUEST_BLOCK_APPROVAL':'Ask for approval to temporarily block the source’s SSH access.',
    'REQUEST_MORE_EVIDENCE':'Collect more evidence for a human review.'}


def plain_text(text,scenario=None):
    if not isinstance(text,str): return text
    names=dict(NAMES)
    if scenario=='dvwa_sqli':
        names.update(E1='web-request evidence',E2='lab application context',E3='authorization lookup',P1='response policy')
    parts=QUOTED.split(text)
    for index in range(0,len(parts),2):
        value=re.sub(r'\s*\(E3\.plan\s*=\s*null\)','',parts[index])
        value=CITATIONS.sub('',value)
        def replace(match):
            before=value[:match.start()]
            article='The ' if not before.strip() or re.search(r'[.!?]\s*$',before) else 'the '
            return article+names[match.group()]
        parts[index]=re.sub(r'\b(?:E[123]|P1)\b',replace,value)
    return ''.join(parts).strip()


def present_report(report):
    if not report: return None
    shown=deepcopy(report)
    if shown.get('format') == 'advisory_text':
        return shown
    shown['reason']=plain_text(report.get('reason'),report.get('scenario'))
    shown['recommendations']=[plain_text(item,report.get('scenario')) for item in report.get('recommendations',[])]
    shown['next_step']=NEXT_STEPS.get(report.get('recommended_action'),report.get('recommended_action'))
    return shown
