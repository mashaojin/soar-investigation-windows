"""Read-only publication audit of tracked and nonignored candidate files in a Git checkout."""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote,urlsplit


def audit(root, credentials_file=None):
    root=Path(root).resolve()
    result=subprocess.run(['git','-C',str(root),'ls-files','-z','--cached','--others','--exclude-standard'],
                          capture_output=True,check=True)
    names=sorted(set(result.stdout.decode().split('\0'))-{''})
    needles=[]
    if credentials_file:
        for line in Path(credentials_file).read_text(encoding='utf-8-sig').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            key,separator,value=line.partition('=')
            if separator and (key.strip().startswith('SOC_TELEGRAM_') or key.strip()=='GEMINI_API_KEY'):
                try:literal=ast.literal_eval(value.strip())
                except (ValueError,SyntaxError):raise ValueError('Invalid local credential data; contents withheld') from None
                if isinstance(literal,str) and len(literal)>=6:needles.append(literal)
    findings=[]
    for name in names:
        p=root/name
        if not p.exists():continue
        parts=Path(name).parts
        if (p.is_symlink() or name=='.env' or (p.name.startswith('.env.') and p.name!='.env.example')
                or p.name.endswith(('.local.json','.sqlite3','.db','.lock','.log','.jsonl','.pem','.key'))
                or '.sqlite3-' in p.name or '.db-' in p.name
                or parts[0] in ('local-artifacts','verification-windows','windows-upstream-backup')
                or (parts[0]=='plans' and p.suffix=='.json')):
            findings.append(dict(path=name,issue='private/generated candidate file'));continue
        if p.suffix.lower() in ('.png','.jpg','.jpeg','.gif','.pdf','.docx'):continue
        text=p.read_text(encoding='utf-8-sig',errors='replace')
        if (re.search(r'\b\d{8,12}:[A-Za-z0-9_-]{30,}\b',text)
                or re.search(r'AIza[0-9A-Za-z_-]{35}',text)
                or re.search(r'AQ\.[0-9A-Za-z_-]{40,}',text)
                or re.search(r'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----',text)
                or any(value in text for value in needles)):
            findings.append(dict(path=name,issue='credential pattern or configured credential match'))
        if re.search(r'(?:[A-Za-z]:[/\\]Users[/\\]|/mnt/[a-z]/Users/)[A-Za-z][A-Za-z0-9_.-]+[/\\]',text):
            findings.append(dict(path=name,issue='operator-specific home path'))
        if p.suffix=='.md':
            for target in re.findall(r'\]\(([^)]+)\)',text):
                target=target.split(' "',1)[0].strip('<>')
                if urlsplit(target).scheme or target.startswith('#'):continue
                local=unquote(target.split('#',1)[0])
                if local and not (p.parent/local).exists():
                    findings.append(dict(path=name,issue='broken relative link',target=local))
    return dict(candidate_files=len(names),findings=findings,passed=not findings,
                note='Heuristic audit; inspect the complete diff and image assets before publication')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path.cwd())
    parser.add_argument('--credentials-file',type=Path,help='Optional local literal-data file; values are never printed')
    args=parser.parse_args()
    value=audit(args.root,args.credentials_file)
    print(json.dumps(value,indent=2))
    raise SystemExit(0 if value['passed'] else 1)
