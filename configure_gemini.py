"""Record a Gemini allowance after the operator verifies the project tier."""
import argparse
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import time
from gemini_provider import api_key
from provider_state import validate_choice


def prepare(root,model,version,quota_kind,max_requests,hours,confirmed=False):
    root=Path(root).resolve()
    validate_choice(dict(provider='gemini',model=model,expected_model_version=version))
    if quota_kind not in ('free_tier','redeemed_credits') or type(max_requests) is not int or not 1<=max_requests<=10 or type(hours) is not int or not 1<=hours<=24:
        raise ValueError('Use verified free-tier quota or redeemed credits, 1–10 requests and 1–24 hours')
    if not confirmed:raise ValueError('Verify the exact API project/model allowance in AI Studio first; subscription alone is not verification')
    key=api_key(root);now=datetime.now(timezone.utc)
    value=dict(model=model,expected_model_version=version,key_sha256=hashlib.sha256(key.encode()).hexdigest(),quota_kind=quota_kind,
        quota_verified_at=now.isoformat(),expires_at=(now+timedelta(hours=hours)).isoformat(),
        synthetic_requests_authorized=True,max_generation_requests=max_requests,real_evidence_authorized=False,paid_usage_authorized=False)
    path=root/'.gemini-access.local.json'
    if path.is_symlink():raise ValueError('Unsafe local receipt path')
    if path.exists():
        backup=root/('.gemini-access-'+str(time.time_ns())+'.local.json')
        with backup.open('x') as file:file.write(path.read_text())
    temp=path.with_name('.gemini-access.local.json.tmp')
    with temp.open('x') as file:file.write(json.dumps(value,indent=2)+'\n')
    temp.chmod(0o600);temp.replace(path)
    return dict(configured=True,synthetic_only=True,model=model,max_generation_requests=max_requests,expires_at=value['expires_at'],
        api_calls=0,billing_changes=0,real_evidence_authorized=False,note='Operator-attested allowance, not automatic verification of provider billing or unlimited API access')


def enable_ongoing_live(root,model,version,quota_kind,confirmed=False):
    root = Path(root).resolve()
    validate_choice(dict(provider='gemini',model=model,expected_model_version=version))
    if quota_kind != 'free_tier' or not confirmed:
        raise ValueError('Ongoing access requires confirmed Free tier and explicit permission to send new incident evidence')
    record = dict(model=model,expected_model_version=version,
                  key_sha256=hashlib.sha256(api_key(root).encode()).hexdigest(),
                  quota_kind=quota_kind,live_since=datetime.now(timezone.utc).isoformat())
    path = root/'.gemini-live-access.local.json'
    if path.is_symlink():
        raise ValueError('Unsafe ongoing authorization path')
    temporary = path.with_name('.gemini-live-access.tmp.local.json')
    with temporary.open('x') as output:
        output.write(json.dumps(record,indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(path)
    return dict(model=model,ongoing_live=True,live_since=record['live_since'],quota_kind=quota_kind)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).parent)
    parser.add_argument('--model',required=True)
    parser.add_argument('--expected-model-version',required=True)
    parser.add_argument('--quota-kind',choices=['free_tier','redeemed_credits'],required=True)
    parser.add_argument('--max-requests',type=int,default=1)
    parser.add_argument('--hours',type=int,default=1)
    parser.add_argument('--confirm-project-allowance',action='store_true')
    parser.add_argument('--ongoing-live',action='store_true',
                        help='Authorize Google to receive evidence from new advisory incidents until revoked')
    args=parser.parse_args()
    try:
        if args.ongoing_live:
            result = enable_ongoing_live(args.root,args.model,args.expected_model_version,args.quota_kind,args.confirm_project_allowance)
        else:
            result = prepare(args.root,args.model,args.expected_model_version,args.quota_kind,args.max_requests,args.hours,args.confirm_project_allowance)
        print(json.dumps(result,indent=2))
    except ValueError as error:parser.exit(1,str(error)+'\n')
