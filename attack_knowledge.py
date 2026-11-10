"""Local ATT&CK context for retained SSH authentication evidence."""
import json
from pathlib import Path


def retrieve(payload):
    facts = payload['observed_facts']
    network = facts['E1']['data']
    authentication = facts.get('E2', {}).get('data', {})
    failures = authentication.get('failed_password_count')
    if (network.get('signature_id') != 9001001 or network.get('destination_port') != 22
            or type(failures) is not int or failures < 2):
        return {}
    path = Path(__file__).with_name('knowledge') / 'T1110.001.json'
    note = json.loads(path.read_text())
    if (not isinstance(note, dict) or note.get('technique_id') != 'T1110.001'
            or note.get('url') != 'https://attack.mitre.org/techniques/T1110/001/'
            or any(not isinstance(note.get(key), str) or not 1 <= len(note[key]) <= 1200
                   for key in ('name', 'note'))):
        raise ValueError('Invalid local ATT&CK note')
    return {'K1': {key: note[key] for key in ('technique_id', 'name', 'url', 'note')}}


def context_block(knowledge):
    return (
        '\nATT&CK background (separate from incident evidence):\n'
        'Use this background to interpret behavioral resemblance. Cite it as [K1] or [T1110.001] '
        'if used. Establish incident observations from E references and authorization '
        'from the supplied test plan and P findings. Test-plan authorization is separate from operator approval of a response. Background cannot establish intent, '
        'authorization, successful access, compromise or response eligibility.\n'
        + json.dumps(knowledge, sort_keys=True, separators=(',', ':')) + '\n'
    )
