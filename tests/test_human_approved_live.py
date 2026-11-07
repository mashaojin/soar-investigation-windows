"""Offline human-approved live flow. No sockets, model calls or firewall changes."""
from copy import deepcopy
import json
import sqlite3
import unittest
from unittest.mock import patch
from pathlib import Path
from human_approved_live import authorization
from windows_response import check_policy
import test_windows_response as windows_tests
import test_continuous_response as legacy
from assessment_facts import observed_claims
from response import queue_reports,deliver_one,handle_update
from live_response import run_one


class HumanApprovedLiveTests(unittest.TestCase):
    def test_launcher_requires_explicit_live_flag_and_telegram(self):
        import windows_lab
        f,w=self.fixture()
        (f.root/'lab.local.json').write_text(json.dumps(w.lab))
        (f.root/'response.local.json').write_text(json.dumps(f.policy))
        (f.root/'runtime.ssh.live.local.json').write_text(json.dumps(dict(lab_profile='lab.local.json',human_approved_live=f.policy['human_approved_live'])))
        (f.root/'live.ssh.local.json').write_text(json.dumps(dict(start_at='end',destination_ip=w.config['victim_ip'],source_ips=w.config['allowed_sources'])))
        base=['windows_lab.py','monitor','--root',str(f.root)]
        original_read=Path.read_text
        def wsl_read(path,*args,**kwargs):
            if str(path)=='/proc/sys/kernel/osrelease':return 'synthetic-microsoft-wsl2'
            return original_read(path,*args,**kwargs)
        # The launcher test simulates WSL on both the development host and Linux CI.
        platform=patch.object(windows_lab.sys,'platform','linux');platform.start();self.addCleanup(platform.stop)
        host=patch.object(Path,'read_text',wsl_read);host.start();self.addCleanup(host.stop)
        for flags in ([],['--human-approved-live'],['--human-approved-live','--telegram','--collection-only']):
            with patch('sys.argv',base+flags),self.assertRaises(SystemExit):windows_lab.main()
        with patch('sys.argv',base+['--human-approved-live','--telegram']),patch('telegram_client.load_credentials'),patch('windows_lab.subprocess.run') as run:
            run.return_value.returncode=0
            self.assertEqual(windows_lab.main(),0)
            self.assertIn('--telegram',run.call_args.args[0])

    def fixture(self):
        w=windows_tests.WindowsResponseTests();w.setUp()
        f=legacy.ContinuousResponseTests();f.setUp();self.addCleanup(f.doCleanups)
        f.policy.update(w.policy())
        stamp=f.evidence['window_start']
        f.policy.update(model_evaluation_passed=False,live_enabled_after=stamp,live_rehearsal_authorized_at=stamp,
            human_approved_live=dict(model=w.lab['ollama']['model'],authorized_at=stamp,accept_unqualified_model=True))
        f.evidence.update(source_ip=w.source,destination_ip=w.config['victim_ip'])
        f.metadata.update(model=w.lab['ollama']['model'],**authorization(f.policy,f.policy))
        f.metadata['investigation']['authentication'].update(source_ip=w.source,target_ip=w.config['victim_ip'])
        f.report['claims']=observed_claims(f.metadata['investigation'])
        self.persist(f)
        return f,w

    def persist(self,f):
        with sqlite3.connect(f.db) as db:
            db.execute('UPDATE incidents SET evidence=?',(json.dumps(f.evidence),))
            db.execute('UPDATE analyses SET report=?,metadata=?',(json.dumps(f.report),json.dumps(f.metadata)))

    def test_acceptance_is_explicit_model_bound_and_not_quality_certification(self):
        f,w=self.fixture();check_policy(f.policy)
        self.assertFalse(f.policy['model_evaluation_passed'])
        for field,value in [('model','other:1b'),('accept_unqualified_model',False),('authorized_at','2020-01-01T00:00:00Z')]:
            p=deepcopy(f.policy);p['human_approved_live'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):check_policy(p)
        p=deepcopy(f.policy);p.pop('human_approved_live')
        with self.assertRaises(ValueError):check_policy(p)

    def test_only_current_telegram_approval_dispatches_once(self):
        for decision in ('a','d'):
            with self.subTest(decision=decision):
                f,w=self.fixture();queue_reports(f.db,f.policy,legacy.IDENTITY)
                deliver_one(f.db,legacy.Telegram(),legacy.IDENTITY)
                class Executor(legacy.Executor):
                    def probe(self):return dict(super().probe(),actual_source=w.source)
                    def read(self,run_id):return dict(super().read(run_id),source=w.source,destination=w.config['victim_ip'])
                e=Executor()
                self.assertFalse(run_one(f.db,f.policy,legacy.IDENTITY,e,wait=lambda _:None))
                self.assertEqual(e.dispatches,0)
                with sqlite3.connect(f.db) as db:
                    request=db.execute('SELECT request_id FROM approval_requests').fetchone()[0]
                update=dict(update_id=1,callback_query=dict(id='q',data='soc5:'+decision+':'+request,
                    **{'from':{'id':100,'is_bot':False}},message=dict(message_id=42,chat=dict(id=100,type='private'))))
                wrong=deepcopy(update);wrong['update_id']=90;wrong['callback_query']['from']['id']=101
                self.assertEqual(handle_update(f.db,wrong,legacy.IDENTITY),'unauthorized')
                self.assertEqual(handle_update(f.db,update,legacy.IDENTITY),'approved' if decision=='a' else 'denied')
                self.assertEqual(run_one(f.db,f.policy,legacy.IDENTITY,e,wait=lambda _:None),decision=='a')
                self.assertEqual(e.dispatches,1 if decision=='a' else 0)
                self.assertFalse(run_one(f.db,f.policy,legacy.IDENTITY,e,wait=lambda _:None))

    def test_reviewed_advisory_uses_windows_live_scope_and_separate_approval(self):
        f,w=self.fixture()
        f.save_suspicious_review(via_telegram=True)
        self.assertEqual(queue_reports(f.db,f.policy,legacy.IDENTITY),1)
        with sqlite3.connect(f.db) as db:
            plan=json.loads(db.execute('SELECT plan FROM approval_requests').fetchone()[0])
        self.assertEqual(plan['transport'],'windows-ssh-helper')
        self.assertEqual(plan['helper_config_hash'],w.policy()['windows_response']['config_hash'])

        class Executor(legacy.Executor):
            def probe(self):return dict(super().probe(),actual_source=w.source)
            def read(self,run_id):return dict(super().read(run_id),source=w.source,destination=w.config['victim_ip'])

        e=Executor()
        self.assertFalse(run_one(f.db,f.policy,legacy.IDENTITY,e))
        f.approve()
        self.assertEqual(f.outcome,'approved')
        self.assertTrue(run_one(f.db,f.policy,legacy.IDENTITY,e,wait=lambda _:None))
        self.assertEqual(e.dispatches,1)
        self.assertEqual(f.status(),'live_complete')

    def test_invalid_evidence_or_report_only_never_gets_live_plan(self):
        for case in ('partial','identity','binding','report_only','claims'):
            with self.subTest(case=case):
                f,w=self.fixture()
                if case=='partial':f.metadata['investigation']['authentication']['coverage_checks']['window_elapsed']=False
                if case=='identity':f.metadata['model']='other:1b'
                if case=='binding':f.metadata.pop('human_approved_live')
                if case=='report_only':f.report['recommended_action']='REPORT_ONLY'
                if case=='claims':f.report['claims']['failed_password_count']=999
                self.persist(f);queue_reports(f.db,f.policy,legacy.IDENTITY)
                with sqlite3.connect(f.db) as db:self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])
