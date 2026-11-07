"""Trusted operator lab profiles. Model output never selects transport or policy."""
from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

MAC = {
    'schema_version':1,'platform':'macos-utm','display_timezone':'America/Vancouver',
    'victim':{'ip':'192.168.64.6','user':'victim','vm':'Victim'},
    'trust_client':{'ip':'192.168.64.8','user':'trust-client','vm':'Trust-Client'},
    'attacker':{'ip':'192.168.64.4','user':'kali','vm':'Kali Linux'},
    'management_ips':['192.168.64.1'],'ssh_port':22,'block_duration_seconds':60,
    'ssh':{'transport':'native','identity_file':None,'known_hosts_file':None},
    'utmctl':'/Applications/UTM.app/Contents/MacOS/utmctl',
    'ollama':{'endpoint':'http://127.0.0.1:11434','model':'gemma4:e4b','transport':'http',
              'num_ctx':65536,'num_predict':1024},
}


def validate_profile(value):
    value=deepcopy(value)
    if not isinstance(value,dict) or value.get('schema_version')!=1 or value.get('platform') not in ('macos-utm','windows-hyperv'):
        raise ValueError('Unsupported explicit lab profile')
    addresses=[]
    for role in ('victim','trust_client','attacker'):
        host=value[role];address=ipaddress.IPv4Address(host['ip'])
        if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError('Lab roles require private unicast IPv4 addresses')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*',host['user']):raise ValueError('Invalid SSH username')
        addresses.append(str(address))
    if len(set(addresses))!=3:raise ValueError('Lab roles must have distinct addresses')
    management=value['management_ips']
    if not isinstance(management,list) or not management:raise ValueError('Explicit protected management addresses required')
    for address in management:
        if str(ipaddress.IPv4Address(address)) in addresses:raise ValueError('Management and client/victim roles must be separate')
    if value.get('ssh_port')!=22 or value.get('block_duration_seconds')!=60:
        raise ValueError('This lab supports TCP/22 and 60-second bounded live responses only')
    ZoneInfo(value['display_timezone'])
    ssh=value['ssh']
    expected='windows-stdio' if value['platform']=='windows-hyperv' else 'native'
    if ssh.get('transport')!=expected:raise ValueError('SSH transport does not match platform')
    if expected=='windows-stdio' and not all(isinstance(ssh.get(k),str) and ssh[k] for k in ('identity_file','known_hosts_file','windows_powershell')):
        raise ValueError('Windows SSH requires explicit key, verified hosts and PowerShell 7 path')
    ollama=value['ollama'];url=urlsplit(ollama['endpoint'])
    if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
        raise ValueError('Ollama endpoint must be an HTTP(S) origin without credentials')
    if not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',ollama['model']):raise ValueError('Invalid configured model identity')
    if type(ollama['num_ctx']) is not int or not 2048<=ollama['num_ctx']<=65536:
        raise ValueError('Invalid configured context capacity')
    if type(ollama['num_predict']) is not int or not 1<=ollama['num_predict']<=1024:
        raise ValueError('Output budget must be bounded at 1024 tokens')
    if 'num_thread' in ollama and (type(ollama['num_thread']) is not int or not 1<=ollama['num_thread']<=4):
        raise ValueError('CPU thread count must be a whole number from 1 to 4')
    if ollama.get('transport') not in ('http','windows-stdio'):raise ValueError('Unsupported Ollama transport')
    return value


def load_profile(settings=None,root=None):
    """Legacy callers without an explicit profile retain deterministic Mac defaults."""
    if root is not None:root=Path(root).resolve()
    source=(settings or {}).get('lab_profile')
    if source is None and root is not None and (Path(root)/'lab.local.json').exists():
        source=Path(root)/'lab.local.json'
    if source is None:return validate_profile(MAC)
    if isinstance(source,dict):return validate_profile(source)
    path=Path(source).expanduser()
    if not path.is_absolute():path=Path(root or Path.cwd())/path
    value=validate_profile(json.loads(path.read_text()))
    value['_path']=str(path.resolve())
    return value


def sources(profile):return [profile['attacker']['ip'],profile['trust_client']['ip']]


def protected(profile):return list(dict.fromkeys(profile['management_ips']+[profile['victim']['ip']]))


def runtime_settings(root):
    path=Path(root)/'runtime.ssh.live.local.json'
    value=json.loads(path.read_text()) if path.exists() else {}
    profile=load_profile(value,root)
    return dict(value,lab_profile=profile,ollama=dict(profile['ollama'],**value.get('ollama',{})),_provider_root=str(Path(root).resolve()))
