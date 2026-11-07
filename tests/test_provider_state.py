"""Provider activation and binding tests; no external service or credential required."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from lab_config import MAC
from provider_state import effective,activate,stamp,validate_binding,validate_choice
from provider_service import ProviderService

ROOT=Path(__file__).parents[1]
CHOICE=dict(provider='gemini',model='gemini-test',expected_model_version='gemini-test-001')


class ProviderStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.settings=dict(lab_profile=deepcopy(MAC),_provider_root=str(self.root))

    def switch(self,**kwargs):return activate(self.root,dict(CHOICE,expected_selection='default',**kwargs))

    def test_default_ollama_and_platform_independence(self):
        for platform in (deepcopy(MAC),json.loads((ROOT/'config/lab.windows-hyperv.example.json').read_text())):
            settings=dict(lab_profile=platform,_provider_root=str(self.root))
            before=deepcopy(platform)
            self.assertEqual(effective(settings)['provider'],'ollama')
            config=effective(settings,CHOICE)
            self.assertEqual(config['provider'],'gemini');self.assertEqual(config['route'],'cloud')
            self.assertEqual(platform,before)

    def test_activation_invalidates_pending_actions_but_not_reports(self):
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db,db:
            db.execute('CREATE TABLE approval_requests(request_id TEXT,status TEXT,plan TEXT,status_notified TEXT)')
            db.executemany('INSERT INTO approval_requests VALUES(?,?,?,?)',
                [('a','pending','{}',''),('b','approved','{}',''),('c','notified',None,''),('d','denied','{}','')])
        value=self.switch();self.assertEqual(value['invalidated_approvals'],2)
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db:
            states=dict(db.execute('SELECT request_id,status FROM approval_requests'))
        self.assertEqual(states,dict(a='stale',b='stale',c='notified',d='denied'))
        with self.assertRaises(ValueError):self.switch()

    def test_switch_refused_during_unresolved_live_operation(self):
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db,db:
            db.execute('CREATE TABLE live_actions(status TEXT)');db.execute("INSERT INTO live_actions VALUES('live_recovery_required')")
        with self.assertRaisesRegex(ValueError,'reconciliation'):self.switch()
        self.assertEqual(effective(self.settings)['provider'],'ollama')

    def test_historical_identity_cannot_be_rebound_after_switch(self):
        initial=effective(self.settings);metadata=dict(stamp(initial),model=initial['model'])
        validate_binding(metadata,self.settings)
        self.switch()
        with self.assertRaises(ValueError):validate_binding(metadata,self.settings)
        active=effective(self.settings);metadata=dict(stamp(active),model=active['model'],model_version=active['expected_model_version'])
        validate_binding(metadata,self.settings)
        metadata['model_version']='gemini-different'
        with self.assertRaises(ValueError):validate_binding(metadata,self.settings)

    def test_no_endpoint_key_or_cloud_alias_can_be_submitted(self):
        for value in [dict(CHOICE,api_key='not-accepted'),dict(CHOICE,endpoint='https://elsewhere.test'),
                      dict(CHOICE,model='gemini-test?key=x'),dict(provider='ollama',model='gemma4:cloud',expected_model_version='gemma4:cloud')]:
            with self.subTest(value=value),self.assertRaises(ValueError):validate_choice(value)

    def test_synthetic_check_never_uses_saved_evidence_or_activates(self):
        calls=[]
        def runner(prompt,settings):
            self.assertTrue(settings['_synthetic_evaluation']);calls.append(settings)
            self.assertTrue(settings['_advisory_report'])
            return dict(text='Attempts fit the approved test scope [E2, P1]. Retain the evidence.',
                        provider='gemini',model='gemini-test',model_version='gemini-test-001',model_route='cloud')
        with patch('provider_service.provider_report',side_effect=runner):value=ProviderService(self.root).check(CHOICE)
        self.assertTrue(value['checks_passed'])
        self.assertEqual(value['report']['evidence_refs'], ['E2', 'P1'])
        self.assertEqual(len(calls),1);self.assertFalse((self.root/'ssh-live.sqlite3').exists())

    def test_provider_report_default_does_not_contact_gemini(self):
        from assessment_providers import provider_report
        with patch('ollama_analyst.ollama_report',return_value=dict(text='{}',model=MAC['ollama']['model'])) as local,patch('gemini_provider.generate') as cloud:
            result=provider_report('synthetic',self.settings)
        local.assert_called_once();cloud.assert_not_called();self.assertEqual(result['provider'],'ollama')
