"""Quota receipt setup is local-only and cannot grant evidence or paid-use consent."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from configure_gemini import prepare


class GeminiSetupTests(unittest.TestCase):
    def test_explicit_confirmation_required_and_no_cloud_or_paid_consent(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'GEMINI_API_KEY':'synthetic_'+('s'*30)}):
            root=Path(folder)
            with self.assertRaises(ValueError):prepare(root,'gemini-test','gemini-test-001','free_tier',1,1)
            self.assertFalse((root/'.gemini-access.local.json').exists())
            result=prepare(root,'gemini-test','gemini-test-001','free_tier',1,1,True)
            value=json.loads((root/'.gemini-access.local.json').read_text())
            self.assertFalse(value['real_evidence_authorized']);self.assertFalse(value['paid_usage_authorized'])
            self.assertNotIn(os.environ['GEMINI_API_KEY'],json.dumps(value));self.assertEqual(result['api_calls'],0)

    def test_limits_and_subscription_claims_cannot_create_allowance(self):
        with tempfile.TemporaryDirectory() as folder:
            for quota,count,hours in [('pro_subscription',1,1),('free_tier',11,1),('free_tier',1,25)]:
                with self.subTest(quota=quota,count=count,hours=hours),self.assertRaises(ValueError):
                    prepare(folder,'gemini-test','gemini-test-001',quota,count,hours,True)

    def test_existing_receipt_preserved_when_reverified(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'GEMINI_API_KEY':'synthetic_'+('s'*30)}):
            root=Path(folder);prepare(root,'gemini-test','gemini-test-001','free_tier',1,1,True)
            before=(root/'.gemini-access.local.json').read_bytes()
            prepare(root,'gemini-test','gemini-test-001','redeemed_credits',2,1,True)
            self.assertEqual(len(list(root.glob('.gemini-access-*.local.json'))),1)
            self.assertEqual(next(root.glob('.gemini-access-*.local.json')).read_bytes(),before)
