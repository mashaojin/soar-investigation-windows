"""Failure-injection tests. Every API response is mocked; no Google calls or billing."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch,MagicMock

import gemini_provider as gemini
from provider_state import effective
from lab_config import MAC
from ollama_analyst import assessment_payload,make_prompt,validate_assessment
from ssh_investigation import build_job
from ssh_scenarios import ROOT,load_scenario
from assessment_facts import observed_claims


class GeminiProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.key='synthetic_'+('k'*30)
        env=patch.dict(os.environ,{'GEMINI_API_KEY':self.key});env.start();self.addCleanup(env.stop)
        lab=deepcopy(MAC);lab['ollama'].update(num_ctx=8192,num_predict=1024)
        self.settings=dict(lab_profile=lab,_provider_root=str(self.root))
        self.config=effective(self.settings,dict(provider='gemini',model='gemini-test',expected_model_version='gemini-test-001'))
        self.case,_=load_scenario(ROOT/'approved_test.json');_,self.job=build_job(ROOT/'approved_test.json');i=self.case['incident']
        self.payload=assessment_payload(dict(signature_id=9001001,source_ip=i['source_ip'],destination_ip=i['target_ip'],destination_port=22,window_start=i['start'],alert_count=i['alert_count']),self.job)
        self.prompt=make_prompt(self.payload);self.settings['investigation']=self.job
        now=datetime.now(timezone.utc)
        self.receipt=dict(model='gemini-test',expected_model_version='gemini-test-001',key_sha256=hashlib.sha256(self.key.encode()).hexdigest(),
            quota_kind='free_tier',quota_verified_at=(now-timedelta(seconds=1)).isoformat(),expires_at=(now+timedelta(hours=1)).isoformat(),
            synthetic_requests_authorized=True,max_generation_requests=10,real_evidence_authorized=False,paid_usage_authorized=False)
        self.save_receipt()
        report=dict(verdict='BENIGN',reason='Observed attempts fit the approved test scope.',recommendations=['Retain evidence.','Monitor source.'],
            evidence_refs=['E2','E3','P1'],claims=observed_claims(self.job),recommended_action='REPORT_ONLY')
        self.answer=dict(modelVersion='gemini-test-001',candidates=[dict(finishReason='STOP',content=dict(parts=[dict(text=json.dumps(report))]))],
            usageMetadata=dict(promptTokenCount=500,candidatesTokenCount=180,thoughtsTokenCount=0))

    def save_receipt(self):(self.root/'.gemini-access.local.json').write_text(json.dumps(self.receipt))

    def responses(self):return [dict(name='models/gemini-test',inputTokenLimit=32768,outputTokenLimit=8192,supportedGenerationMethods=['generateContent']),dict(totalTokens=500),deepcopy(self.answer)]

    def call(self,responses=None):
        with patch('gemini_provider.request',side_effect=responses or self.responses()) as request:
            result=gemini.generate(self.prompt,self.settings,self.config,synthetic=True)
        return result,request

    def test_exact_schema_facts_identity_budget_and_one_generation(self):
        result,request=self.call()
        self.assertEqual(result['model_version'],'gemini-test-001');self.assertEqual(result['request_count'],1)
        self.assertEqual(request.call_count,3)
        body=request.call_args.args[2]
        self.assertNotIn(self.key,json.dumps(body));self.assertNotIn('tools',body)
        self.assertEqual(body['generationConfig']['responseJsonSchema']['properties']['claims']['const'],observed_claims(self.job))
        self.assertEqual(validate_assessment(result['text'],self.payload,self.job)['verdict'],'BENIGN')

    def test_real_evidence_denied_before_any_api_call(self):
        with patch('gemini_provider.request') as request,self.assertRaisesRegex(ValueError,'consent'):
            gemini.generate(self.prompt,self.settings,self.config,synthetic=False)
        request.assert_not_called()

    def test_ongoing_access_allows_multiple_new_advisory_incidents(self):
        from configure_gemini import enable_ongoing_live
        enable_ongoing_live(self.root,'gemini-test','gemini-test-001','free_tier',confirmed=True)
        settings = dict(self.settings,_advisory_report=True,
                        _incident_window_start=datetime.now(timezone.utc).isoformat())
        for identifier in ('first','second'):
            with patch('gemini_provider.request',side_effect=self.responses()) as request:
                gemini.generate(self.prompt,dict(settings,_incident_id=identifier),self.config)
            self.assertEqual(request.call_count,3)
        self.assertFalse((self.root/'gemini-request-budget.sqlite3').exists())
        self.assertTrue(gemini.readiness(self.config)['real_evidence_authorized'])
        with self.assertRaisesRegex(ValueError,'new advisory incidents'):
            gemini.access(self.config,self.key,False)
        with self.assertRaisesRegex(ValueError,'new advisory incidents'):
            gemini.access(self.config,self.key,False,dict(settings,_incident_id='old',
                                _incident_window_start='2020-01-01T00:00:00+00:00'))

    def test_advisory_generation_omits_the_json_schema(self):
        self.settings['_advisory_report'] = True
        responses = self.responses()
        responses[-1]['candidates'][0]['content']['parts'] = [{'text':'Review these attempts [E2].'}]
        result, request = self.call(responses)
        generation = request.call_args.args[2]['generationConfig']
        self.assertNotIn('responseJsonSchema',generation)
        self.assertNotIn('responseMimeType',generation)
        self.assertEqual(result['text'],'Review these attempts [E2].')

    def test_key_quota_expiry_credit_and_budget_fail_closed(self):
        for change in [dict(key_sha256='wrong'),dict(quota_kind='subscription'),dict(paid_usage_authorized=True),
                       dict(expires_at='2020-01-01T00:00:00+00:00'),dict(synthetic_requests_authorized=False)]:
            with self.subTest(change=change):
                original=deepcopy(self.receipt);self.receipt.update(change);self.save_receipt()
                with patch('gemini_provider.request') as request,self.assertRaises(ValueError):gemini.generate(self.prompt,self.settings,self.config,True)
                request.assert_not_called();self.receipt=original
        self.receipt['max_generation_requests']=1;self.save_receipt();self.call()
        with patch('gemini_provider.request') as request,self.assertRaisesRegex(ValueError,'budget exhausted'):gemini.generate(self.prompt,self.settings,self.config,True)
        request.assert_not_called()

    def test_context_overflow_prevents_generation(self):
        responses=self.responses();responses[1]['totalTokens']=8000
        with patch('gemini_provider.request',side_effect=responses) as request,self.assertRaisesRegex(ValueError,'limits'):
            gemini.generate(self.prompt,self.settings,self.config,True)
        self.assertEqual(request.call_count,2)

    def test_real_test_is_one_fresh_incident_not_saved_evidence(self):
        self.receipt.update(real_evidence_authorized=True,max_generation_requests=1);self.save_receipt()
        fresh=dict(_incident_id='fresh-incident',_incident_window_start=datetime.now(timezone.utc).isoformat())
        self.assertTrue(gemini.access(self.config,self.key,False,fresh)['real_evidence_authorized'])
        for context in ({},dict(fresh,_incident_window_start='2020-01-01T00:00:00+00:00')):
            with self.assertRaisesRegex(ValueError,'fresh incident'):gemini.access(self.config,self.key,False,context)
        self.receipt['max_generation_requests']=2;self.save_receipt()
        with self.assertRaisesRegex(ValueError,'fresh incident'):gemini.access(self.config,self.key,False,fresh)

    def test_identity_truncation_missing_usage_and_tools_rejected(self):
        for case in ('identity','truncation','usage','tools','thought_budget'):
            responses=self.responses();answer=responses[-1]
            if case=='identity':answer['modelVersion']='gemini-other'
            if case=='truncation':answer['candidates'][0]['finishReason']='MAX_TOKENS'
            if case=='usage':answer.pop('usageMetadata')
            if case=='tools':answer['candidates'][0]['content']['parts']=[{'functionCall':{'name':'run_command'}}]
            if case=='thought_budget':answer['usageMetadata']['thoughtsTokenCount']=1024
            with self.subTest(case=case),patch('gemini_provider.request',side_effect=responses) as request,self.assertRaises(ValueError):
                gemini.generate(self.prompt,self.settings,self.config,True)
            self.assertEqual(request.call_count,3)

    def test_python_fact_validator_is_not_replaced_by_provider_schema(self):
        responses=self.responses();bad=json.loads(responses[-1]['candidates'][0]['content']['parts'][0]['text'])
        bad['claims']['failed_password_count']=999;responses[-1]['candidates'][0]['content']['parts'][0]['text']=json.dumps(bad)
        result,_=self.call(responses)
        with self.assertRaises(ValueError):validate_assessment(result['text'],self.payload,self.job)
        with self.assertRaises(ValueError):validate_assessment('{malformed',self.payload,self.job)

    def test_redirect_or_http_error_never_leaks_key_or_follows_location(self):
        for status in (302,400,401,403,429,500):
            connection=MagicMock();connection.getresponse.return_value.status=status
            with self.subTest(status=status),patch('gemini_provider.http.client.HTTPSConnection',return_value=connection),self.assertRaises(ValueError) as error:
                gemini.request('/v1beta/models/gemini-test:generateContent',self.key,{},time.monotonic()+5)
            self.assertNotIn(self.key,str(error.exception));self.assertEqual(connection.request.call_count,1)
            args,kwargs=connection.request.call_args;self.assertNotIn(self.key,args[1]);self.assertEqual(kwargs['headers']['x-goog-api-key'],self.key)

    def test_missing_key_file_is_not_executed_or_echoed(self):
        with patch.dict(os.environ,{'GEMINI_API_KEY':''}):
            (self.root/'.env.gemini').write_text("GEMINI_API_KEY=__import__('os').system('unexpected')")
            with self.assertRaises(ValueError) as error:gemini.api_key(self.root)
            self.assertNotIn('unexpected',str(error.exception))

    def test_authentication_key_format_and_header_safety(self):
        synthetic_key='AQ.'+'x'*50
        with patch.dict(os.environ,{'GEMINI_API_KEY':synthetic_key}):
            self.assertEqual(gemini.api_key(self.root),synthetic_key)
        for invalid in (synthetic_key+'\nInjected: header',synthetic_key+' space'):
            with patch.dict(os.environ,{'GEMINI_API_KEY':invalid}),self.assertRaises(ValueError):
                gemini.api_key(self.root)

    def test_shared_slot_refuses_a_parallel_request(self):
        from model_lock import inference_slot
        with inference_slot():
            with self.assertRaises(TimeoutError):
                with inference_slot(timeout=0):self.fail('Parallel slot acquired')
