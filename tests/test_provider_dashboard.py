"""Localhost API controls; no external APIs, credentials, VMs or model calls."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from unittest.mock import patch

from dashboard import make_server
from configure_local import configure
from provider_state import effective
from lab_config import runtime_settings


class ProviderDashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        source=Path(__file__).parents[1]
        # Initialization's public dependencies are copied; no operational files reused.
        import shutil
        for name in ('config','prompts','web'):shutil.copytree(source/name,self.root/name)
        configure(self.root,profile='windows-hyperv')
        self.server=make_server(self.root,0);self.addCleanup(self.server.server_close)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.addCleanup(self.stop)
        self.origin='http://127.0.0.1:'+str(self.server.server_port)

    def stop(self):self.server.shutdown();self.thread.join(timeout=3)

    def post(self,path,value,csrf=True):
        headers={'Origin':self.origin,'Content-Type':'application/json'}
        if csrf:headers['X-SOAR-CSRF']=self.server.csrf_token
        return urlopen(Request(self.origin+path,data=json.dumps(value).encode(),headers=headers),timeout=10)

    def test_get_exposes_routing_but_never_credentials_or_cloud_calls(self):
        with patch('gemini_provider.request') as api,closing(urlopen(self.origin+'/api/experiments')) as response:
            value=json.load(response)
        self.assertEqual(value['provider']['provider'],'ollama');api.assert_not_called()
        self.assertNotIn('api_key',json.dumps(value).lower())

    def test_selection_requires_csrf_and_sends_no_api_request(self):
        value=dict(provider='gemini',model='gemini-test',expected_model_version='gemini-test-001',expected_selection='default')
        with self.assertRaises(HTTPError) as error:self.post('/api/providers/activate',value,False)
        self.assertEqual(error.exception.code,403);error.exception.close()
        with patch('gemini_provider.request') as api,closing(self.post('/api/providers/activate',value)) as response:
            result=json.load(response)
        self.assertEqual(result['selection']['provider'],'gemini');api.assert_not_called()
        self.assertEqual(effective(runtime_settings(self.root))['provider'],'gemini')

    def test_synthetic_check_without_access_does_not_upload_or_activate(self):
        value=dict(provider='gemini',model='gemini-test',expected_model_version='gemini-test-001')
        with patch('gemini_provider.request') as api,self.assertRaises(HTTPError) as error:self.post('/api/providers/check',value)
        self.assertEqual(error.exception.code,400);error.exception.close();api.assert_not_called()
        self.assertEqual(effective(runtime_settings(self.root))['provider'],'ollama')

    def test_saved_evidence_comparison_requires_cloud_consent(self):
        from provider_state import activate
        from experiment_store import active_instruction
        activate(self.root,dict(provider='gemini',model='gemini-test',expected_model_version='gemini-test-001',expected_selection='default'))
        with patch('gemini_provider.request') as api,self.assertRaises(ValueError):
            self.server.experiments.start_comparison(dict(incident_id='anything',prompt_id=active_instruction(self.root)['id']))
        api.assert_not_called()
