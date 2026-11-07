"""Foreground Windows lab launcher. Run with WSL Python; Ctrl+C stops each service."""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

NAMES={'SOC_TELEGRAM_BOT_TOKEN','SOC_TELEGRAM_CHAT_ID','SOC_TELEGRAM_USER_ID'}


def read_env(path):
    """Parse local credential data only. Never source or execute a shell file."""
    path=Path(path);info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size>8192:
        raise ValueError('Credential file must be a small regular file')
    values={}
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'(SOC_TELEGRAM_[A-Z_]+)\s*=\s*(.*)',line)
        if not match or match[1] not in NAMES or match[1] in values:
            raise ValueError('Credential file has unsupported or duplicate fields')
        try:value=ast.literal_eval(match[2])
        except (SyntaxError,ValueError):raise ValueError('Credential values must be quoted literal strings') from None
        if not isinstance(value,str) or not value or value.startswith('replace-with-') or any(ord(c)<32 for c in value):
            raise ValueError('Credential file contains a placeholder or invalid value')
        values[match[1]]=value
    if not {'SOC_TELEGRAM_BOT_TOKEN','SOC_TELEGRAM_CHAT_ID'}<=values.keys():
        raise ValueError('Bot token and private chat ID are required locally')
    return values


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service',choices=['dashboard','monitor','status'])
    parser.add_argument('--root',type=Path,default=Path(__file__).parent)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--telegram',action='store_true')
    parser.add_argument('--collection-only',action='store_true',help='Pause model assessment while collecting/correlating events')
    parser.add_argument('--experimental-assessment',action='store_true',help='Explicitly run the authorized unverified model in dry-run human-review mode')
    parser.add_argument('--human-approved-live',action='store_true',help='Explicit operator-authorized live mode; every block still requires Telegram approval')
    parser.add_argument('--env-file',type=Path,help='Explicit local data file; never executed')
    parser.add_argument('--duration',type=float,help='Bounded monitor verification only')
    args=parser.parse_args()
    if sys.platform!='linux' or 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        parser.error('Run this launcher in WSL2 Ubuntu, not native Windows Python')
    root=args.root.resolve()
    from lab_config import load_profile,sources
    lab=load_profile(root=root)
    if lab['platform']!='windows-hyperv':parser.error('Explicit Windows lab profile required')
    if args.service=='status':
        from dashboard import snapshot
        value=snapshot(root)
        print(json.dumps(dict(platform=lab['platform'],model=value['assessment_provider']['model'],provider=value['assessment_provider']['provider'],route=value['assessment_provider']['route'],timezone=lab['display_timezone'],response_policy=value['response_policy'],history=value['history']),indent=2))
        return 0
    if args.service=='dashboard':
        if args.telegram or args.env_file or args.duration is not None or args.collection_only or args.experimental_assessment or args.human_approved_live:parser.error('Dashboard does not collect logs, poll Telegram or load credentials')
        argv=[sys.executable,str(Path(__file__).with_name('dashboard.py')),'--root',str(root),'--port',str(args.port)]
    else:
        policy=json.loads((root/'response.local.json').read_text())
        if policy['mode']!='dry_run' and not args.human_approved_live:parser.error('Live mode requires explicit --human-approved-live and recorded authorization')
        if args.human_approved_live and (not args.telegram or args.collection_only or args.experimental_assessment):parser.error('Human-approved live mode requires Telegram and excludes review-only/collection-only modes')
        if args.experimental_assessment and args.collection_only:parser.error('Choose experimental assessment or collection-only mode')
        from lab_config import runtime_settings
        from experimental_assessment import qualification
        runtime=runtime_settings(root)
        from human_approved_live import authorization
        accepted=authorization(runtime,policy) if args.human_approved_live else {}
        if args.human_approved_live:
            if not accepted:parser.error('Human-approved live authorization has not been recorded')
            from windows_response import check_policy
            check_policy(policy,lab)
        elif runtime.get('human_approved_live'):
            parser.error('Use --human-approved-live explicitly for this authorized profile')
        if args.experimental_assessment and not qualification(runtime,policy):parser.error('Explicit experimental authorization has not been recorded')
        if not args.collection_only and runtime.get('experimental_assessment') and not args.experimental_assessment:
            parser.error('Use --experimental-assessment explicitly for the unverified model, or --collection-only')
        if not args.collection_only and not args.experimental_assessment and not accepted and policy.get('model_evaluation_passed') is not True:
            parser.error('Model reliability is unverified. Use --collection-only while model evaluation is deferred')
        collector=json.loads((root/'live.ssh.local.json').read_text())
        if collector.get('start_at')!='end' or collector.get('destination_ip')!=lab['victim']['ip'] or set(collector.get('source_ips',[]))!=set(sources(lab)):
            parser.error('Collector must use current profile scope and an end-only initial cursor')
        if args.env_file and not args.telegram:parser.error('Credential file is only used with --telegram')
        if args.env_file:
            path=args.env_file if args.env_file.is_absolute() else root/args.env_file
            for key,value in read_env(path).items():os.environ.setdefault(key,value)
        if args.telegram:
            from telegram_client import load_credentials
            load_credentials(policy)
            if policy.get('exclusive_polling_confirmed') is not True:parser.error('Confirm exclusive polling before starting Telegram')
        argv=[sys.executable,str(Path(__file__).with_name('monitor.py')),'--config',str(root/'live.ssh.local.json'),'--runtime',str(root/'runtime.ssh.live.local.json'),'--db',str(root/'ssh-live.sqlite3')]
        if args.telegram:argv+=['--telegram','--response-config',str(root/'response.local.json')]
        if args.collection_only:argv+=['--collection-only']
        if args.duration is not None:
            if not 0<args.duration<=3600:parser.error('Verification duration must be positive and bounded at one hour')
            argv+=['--duration',str(args.duration)]
    try:return subprocess.run(argv,cwd=root).returncode
    except KeyboardInterrupt:return 130


if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError) as error:
        # Do not print parsing exceptions: a credential line may be embedded.
        print('Windows lab startup failed. Check local configuration/credential file and service prerequisites.',file=sys.stderr)
        raise SystemExit(1) from None
