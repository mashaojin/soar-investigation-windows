from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from live import collect_once
from remote_reader import read_batch
from response import queue_reports, deliver_one, handle_update, execute_dry_run, tick
from live_response import run_one, claim, reconcile
from service_state import record, view
from assessment_facts import VERSION,observed_claims
from dashboard_view import incident_view

IDENTITY={'bot_key':'test-bot','chat_id':100,'user_id':100}


class Telegram:
    def __init__(self): self.methods=[]
    def call(self,method,payload):
        self.methods.append(method)
        if method=='getUpdates': return []
        return {'message_id':42,'chat':{'id':100}}


class Executor:
    def __init__(self): self.dispatches=0; self.reads=0; self.probes=0; self.run_id=None
    def probe(self):
        self.probes+=1
        return {'reachable':self.probes!=2,'actual_source':'192.168.64.4'}
    def dispatch(self,run_id): self.dispatches+=1; self.run_id=run_id
    def read(self,run_id):
        self.reads+=1
        return dict(run_id=run_id,source='192.168.64.4',destination='192.168.64.6',port=22,duration_seconds=60,
                    stage='applied' if self.reads==1 else 'rolled_back',rollback_due_at=time.time()+60,
                    firewall_after='Status: active\n22/tcp ALLOW IN Anywhere')
    def management(self): return {'reachable':True}


class ContinuousResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.db=self.root/'state.sqlite3'
        self.now=int(time.time())
        iso=lambda seconds:datetime.fromtimestamp(self.now+seconds,timezone.utc).isoformat()
        self.policy=dict(mode='live',duration_seconds=60,approval_ttl_seconds=600,exclusive_polling_confirmed=True,
                         live_enabled_after=iso(-600),victim_ip='192.168.64.6',allowed_attacker_ips=['192.168.64.4'],
                         protected_ips=['192.168.64.1','192.168.64.6'],destination_port=22)
        self.evidence=dict(source_ip='192.168.64.4',destination_ip='192.168.64.6',destination_port=22,signature_id=9001001,window_start=iso(-180))
        auth=dict(source_ip='192.168.64.4',target_ip='192.168.64.6',coverage='observed_window',limited=False,
                  failed_password_count=6,successful_login_count=0,failed_accounts={'invalid_demo':6},
                  coverage_checks={k:True for k in ('query_not_limited','retained_entry_before_start','root_service_records','window_elapsed')})
        self.metadata=dict(engine='ollama_direct',model='gemma4:e4b',investigation=dict(origin='live_read_only',authentication=auth,plan_evidence={'plan':None}))
        self.metadata['assessment_version']=VERSION
        self.report=dict(assessment_version=VERSION,claims=observed_claims(self.metadata['investigation']),recommended_action='REQUEST_BLOCK_APPROVAL',verdict='SUSPICIOUS',coverage='observed_window',scenario='ssh_investigation',reason='Six observed failures without a plan.',recommendations=['Review source.','Retain evidence.'])
        with sqlite3.connect(self.db) as db:
            db.executescript('''CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,evidence TEXT,revision INTEGER,status TEXT,alert_count INTEGER);
                CREATE TABLE analyses(incident_id TEXT,revision INTEGER,status TEXT,report TEXT,metadata TEXT);''')
            db.execute('INSERT INTO incidents VALUES(?,?,1,\'complete\',1)',('i',json.dumps(self.evidence)))
            db.execute('INSERT INTO analyses VALUES(?,1,\'complete\',?,?)',('i',json.dumps(self.report),json.dumps(self.metadata)))
        self.telegram=Telegram()

    def approve(self,decision='a',user=100):
        queue_reports(self.db,self.policy,IDENTITY)
        deliver_one(self.db,self.telegram,IDENTITY)
        with sqlite3.connect(self.db) as db:
            request=db.execute('SELECT request_id FROM approval_requests').fetchone()[0]
        update={'update_id':1,'callback_query':{'id':'q','data':'soc5:'+decision+':'+request,'from':{'id':user},'message':{'message_id':42,'chat':{'id':100,'type':'private'}}}}
        self.outcome=handle_update(self.db,update,IDENTITY)
        return request

    def status(self):
        with sqlite3.connect(self.db) as db: return db.execute('SELECT status FROM approval_requests').fetchone()[0]

    def save_suspicious_review(self, *, via_telegram=False):
        from human_review import ReviewService, attach, load_incident
        from provider_state import effective, stamp
        self.policy['_provider_root']=str(self.root)
        self.metadata.update(stamp(effective(self.policy)),assessment_format='advisory_text')
        advisory=dict(format='advisory_text',reason='Assessment: Suspicious\nReview recorded SSH activity [E2].',evidence_refs=['E2'])
        identifier='a'*64
        service=ReviewService(self.root)
        self.db.rename(service.path)
        self.db=service.path
        with closing(sqlite3.connect(self.db)) as db,db:
            db.execute("UPDATE incidents SET incident_id=?,status='manual_review'",(identifier,))
            db.execute("UPDATE analyses SET incident_id=?,status='manual_review',report=?,metadata=?",
                       (identifier,json.dumps(advisory),json.dumps(self.metadata)))
            context=attach(db,load_incident(db,identifier))['review_context']
        self.assertEqual(queue_reports(self.db,self.policy,IDENTITY),0)
        review=dict(incident_id=identifier,revision=1,snapshot_hash=context['snapshot_hash'])
        if via_telegram:
            from human_review import deliver_notifications
            notice=service.notify(review)
            deliver_notifications(self.db,self.policy,self.telegram,IDENTITY)
            update={'update_id':2,'callback_query':{'data':'hr:s:'+notice['notification_id'],
                'from':{'id':100},'message':{'message_id':42,'chat':{'id':100,'type':'private'}}}}
            self.assertEqual(handle_update(self.db,update,IDENTITY),'review_suspicious')
        else:
            service.save(dict(review,expected_review_id=None,reviewer='Test operator',conclusion='SUSPICIOUS',notes=''))

    def test_advisory_live_requires_two_decisions_and_runs_once(self):
        self.save_suspicious_review()
        self.assertEqual(queue_reports(self.db,dict(self.policy,mode='dry_run'),IDENTITY),0)
        self.assertEqual(queue_reports(self.db,self.policy,IDENTITY),1)
        self.assertEqual(queue_reports(self.db,self.policy,IDENTITY),0)
        executor=Executor()
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,executor))
        from response import message_for
        with closing(sqlite3.connect(self.db)) as db:
            db.row_factory=sqlite3.Row
            row=db.execute('SELECT * FROM approval_requests').fetchone()
        payload=message_for(row)
        self.assertIn('Human review:',payload['text'])
        self.assertIn('Approve LIVE 60s block',payload['reply_markup']['inline_keyboard'][0][0]['text'])
        self.approve()
        self.assertEqual(self.outcome,'approved')
        self.assertTrue(run_one(self.db,self.policy,IDENTITY,executor,wait=lambda _:None))
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,executor))
        self.assertEqual(self.status(),'live_complete')
        self.assertEqual(executor.dispatches,1)

    def test_suspicious_human_review_cannot_bypass_live_scope(self):
        self.scoped_trust_case(False)
        self.save_suspicious_review()
        self.assertEqual(queue_reports(self.db,self.policy,IDENTITY),0)

    def test_reviewed_request_stops_when_incident_evidence_changes(self):
        self.save_suspicious_review()
        self.approve()
        self.assertEqual(self.outcome,'approved')
        with closing(sqlite3.connect(self.db)) as db,db:
            db.execute('UPDATE incidents SET alert_count=alert_count+1')
        executor=Executor()
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,executor))
        self.assertEqual(executor.dispatches,0)

    def test_live_success_is_single_dispatch_with_rollback_and_recovery(self):
        self.approve(); executor=Executor()
        self.assertTrue(run_one(self.db,self.policy,IDENTITY,executor,wait=lambda _:None))
        self.assertEqual(self.status(),'live_complete')
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,executor))
        self.assertEqual(executor.dispatches,1)
        with sqlite3.connect(self.db) as db:
            result=json.loads(db.execute('SELECT result FROM live_actions').fetchone()[0])
        self.assertTrue(result['passed']); self.assertTrue(result['management_check']['reachable'])

    def test_five_failures_can_be_eligible_when_model_requests_approval(self):
        auth=self.metadata['investigation']['authentication']
        auth.update(failed_password_count=5,failed_accounts={'invalid_demo':5},connection_drop_count=1,penalty_event_count=1)
        self.report.update(reason='Five observed failures and SSH protection events warrant a temporary response.',claims=observed_claims(self.metadata['investigation']))
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET report=?,metadata=?',(json.dumps(self.report),json.dumps(self.metadata)))
        self.approve(); e=Executor(); run_one(self.db,self.policy,IDENTITY,e,wait=lambda _:None)
        self.assertEqual(self.status(),'live_complete'); self.assertEqual(e.dispatches,1)

    def test_model_report_only_recommendation_never_offers_action(self):
        self.report['recommended_action']='REPORT_ONLY'
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET report=?',(json.dumps(self.report),))
        self.approve(); e=Executor(); self.assertFalse(run_one(self.db,self.policy,IDENTITY,e))
        self.assertEqual(self.status(),'notified'); self.assertEqual(e.dispatches,0)

    def test_more_evidence_request_is_delivered_without_action(self):
        self.report.update(verdict='INSUFFICIENT_EVIDENCE',recommended_action='REQUEST_MORE_EVIDENCE')
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE analyses SET report=?,status='manual_review'",(json.dumps(self.report),))
            db.execute("UPDATE incidents SET status='manual_review'")
        self.approve(); self.assertEqual(self.status(),'notified')
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def test_historical_model_report_never_becomes_v2_live_action(self):
        self.metadata.pop('assessment_version'); self.report.pop('assessment_version')
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET report=?,metadata=?',(json.dumps(self.report),json.dumps(self.metadata)))
        self.approve(); e=Executor(); self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(self.status(),'notified')

    def test_denial_and_wrong_operator_do_not_dispatch(self):
        for decision,user in [('d',100),('a',999)]:
            with self.subTest(decision=decision,user=user):
                with sqlite3.connect(self.db) as db:
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='approval_requests'").fetchone():
                        db.execute('DELETE FROM approval_requests'); db.execute('DELETE FROM telegram_updates')
                self.approve(decision,user); e=Executor()
                self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(e.dispatches,0)

    def test_changed_assessment_and_expired_approval_do_not_dispatch(self):
        self.approve()
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET metadata=?',(json.dumps(dict(self.metadata,changed=True)),))
        e=Executor(); self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(self.status(),'policy_rejected'); self.assertEqual(e.dispatches,0)

    def test_expiry_before_claim_has_no_action(self):
        self.approve()
        with sqlite3.connect(self.db) as db: db.execute('UPDATE approval_requests SET expires_at=0')
        e=Executor(); self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(self.status(),'expired')

    def test_activation_excludes_historical_incidents(self):
        self.policy['live_enabled_after']=datetime.now(timezone.utc).isoformat(); self.approve()
        e=Executor(); self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(self.status(),'notified')

    def test_partial_or_trusted_source_never_gets_live_plan(self):
        self.metadata['investigation']['authentication']['coverage']='partial'
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET metadata=?',(json.dumps(self.metadata),))
        self.approve()
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def test_trust_client_is_outside_live_allowlist(self):
        self.evidence['source_ip']='192.168.64.8'
        with sqlite3.connect(self.db) as db: db.execute('UPDATE incidents SET evidence=?',(json.dumps(self.evidence),))
        self.approve()
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def trust_case(self):
        self.policy['allowed_attacker_ips'].append('192.168.64.8')
        self.evidence['source_ip']='192.168.64.8'
        self.metadata['investigation']['authentication']['source_ip']='192.168.64.8'
        with sqlite3.connect(self.db) as db:
            db.execute('UPDATE incidents SET evidence=?',(json.dumps(self.evidence),))
            db.execute('UPDATE analyses SET metadata=?',(json.dumps(self.metadata),))

    def test_allowlisted_unapproved_trust_client_can_block_and_recover(self):
        self.trust_case(); self.approve()
        class TrustExecutor(Executor):
            def probe(self): return dict(super().probe(),actual_source='192.168.64.8')
            def read(self,run_id): return dict(super().read(run_id),source='192.168.64.8')
        e=TrustExecutor(); run_one(self.db,self.policy,IDENTITY,e,wait=lambda _:None)
        self.assertEqual(self.status(),'live_complete'); self.assertEqual(e.dispatches,1)

    def test_allowlisted_trust_client_denial_never_dispatches(self):
        self.trust_case(); self.approve('d'); e=Executor()
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(e.dispatches,0)

    def test_allowlisted_trust_client_with_plan_still_has_no_action(self):
        self.trust_case()
        self.metadata['investigation']['plan_evidence']['plan']={'plan_id':'approved'}
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET metadata=?',(json.dumps(self.metadata),))
        self.approve()
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def scoped_trust_case(self, violation):
        self.trust_case()
        job=self.metadata['investigation']
        job['authentication']['failed_accounts']={'root':1,'soc_test':5} if violation else {'soc_test':6}
        job['plan_evidence'].update(plan={'plan_id':'approved','allowed_accounts':['soc_test'],'maximum_failed_attempts':10},
            scope_comparison={'unexpected_accounts':['root'] if violation else [],'attempt_limit_exceeded':False})
        self.report['claims']=observed_claims(job)
        with sqlite3.connect(self.db) as db:
            db.execute('UPDATE analyses SET report=?,metadata=?',(json.dumps(self.report),json.dumps(self.metadata)))

    def test_verified_root_scope_violation_can_offer_live_action(self):
        self.scoped_trust_case(True); self.approve()
        class TrustExecutor(Executor):
            def probe(self): return dict(super().probe(),actual_source='192.168.64.8')
            def read(self,run_id): return dict(super().read(run_id),source='192.168.64.8')
        e=TrustExecutor(); run_one(self.db,self.policy,IDENTITY,e,wait=lambda _:None)
        self.assertEqual(self.status(),'live_complete'); self.assertEqual(e.dispatches,1)

    def test_scope_violation_denial_never_dispatches(self):
        self.scoped_trust_case(True); self.approve('d'); e=Executor()
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(e.dispatches,0)

    def test_compliant_plan_still_report_only_despite_model_block_request(self):
        self.scoped_trust_case(False); self.approve()
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def test_fabricated_scope_violation_never_offers_action(self):
        self.scoped_trust_case(False); self.report['claims']['unexpected_accounts']=['root']
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET report=?',(json.dumps(self.report),))
        self.approve()
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def test_source_attribution_mismatch_has_no_action(self):
        self.trust_case(); self.metadata['investigation']['authentication']['source_ip']='192.168.64.4'
        with sqlite3.connect(self.db) as db: db.execute('UPDATE analyses SET metadata=?',(json.dumps(self.metadata),))
        self.approve()
        with sqlite3.connect(self.db) as db: self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def test_mode_change_invalidates_pending_request(self):
        self.approve(); self.policy['mode']='dry_run'
        queue_reports(self.db,self.policy,IDENTITY)
        self.assertEqual(self.status(),'stale')

    def test_wrong_guest_scope_fails_closed_without_repeating_dispatch(self):
        self.approve()
        class WrongGuest(Executor):
            def read(self,run_id): return dict(super().read(run_id),source='192.168.64.8')
        e=WrongGuest(); run_one(self.db,self.policy,IDENTITY,e,wait=lambda _:None)
        self.assertEqual(self.status(),'live_recovery_required'); self.assertEqual(e.dispatches,1)

    def test_dispatch_timeout_is_never_retried_and_is_reconciled(self):
        self.approve()
        class Uncertain(Executor):
            def dispatch(self,run_id):
                super().dispatch(run_id); raise TimeoutError('uncertain dispatch')
        e=Uncertain(); run_one(self.db,self.policy,IDENTITY,e,wait=lambda _:None)
        self.assertEqual(self.status(),'live_recovery_required')
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(e.dispatches,1)
        e.reads=1; reconcile(self.db,e)
        self.assertEqual(self.status(),'live_failed'); self.assertEqual(e.dispatches,1)

    def test_interrupted_preparation_is_not_automatically_dispatched(self):
        self.approve(); claim(self.db,self.policy,IDENTITY); e=Executor(); reconcile(self.db,e)
        self.assertEqual(self.status(),'live_failed'); self.assertEqual(e.dispatches,0)

    def test_unchanged_recovery_error_does_not_repeat_message_updates(self):
        self.approve()
        class Unavailable(Executor):
            def dispatch(self,run_id): raise TimeoutError('uncertain dispatch')
            def read(self,run_id): raise TimeoutError('state unavailable')
        e=Unavailable(); run_one(self.db,self.policy,IDENTITY,e,wait=lambda _:None); reconcile(self.db,e)
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE approval_requests SET status_notified='live_recovery_required'")
            count=db.execute('SELECT count(*) FROM response_audit').fetchone()[0]
        reconcile(self.db,e)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM response_audit').fetchone()[0],count)
            self.assertEqual(db.execute('SELECT status_notified FROM approval_requests').fetchone()[0],'live_recovery_required')

    def test_dry_run_routes_to_simulation_only(self):
        self.policy.update(mode='dry_run',duration_seconds=600); self.approve(); e=Executor()
        self.assertFalse(run_one(self.db,self.policy,IDENTITY,e)); self.assertEqual(execute_dry_run(self.db,self.policy),1)
        self.assertEqual(e.dispatches,0)

    def test_collection_and_telegram_continue_during_live_block(self):
        self.approve(); waiting=threading.Event(); resume=threading.Event(); errors=[]
        def pause(_): waiting.set(); resume.wait(5)
        def worker():
            try: run_one(self.db,self.policy,IDENTITY,Executor(),wait=pause)
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=worker); thread.start()
        try:
            self.assertTrue(waiting.wait(3)); self.assertTrue(thread.is_alive())
            event=dict(event_type='alert',timestamp=datetime.now(timezone.utc).isoformat(),src_ip='192.168.64.8',dest_ip='192.168.64.6',dest_port=22,alert={'signature_id':9001001})
            log=self.root/'eve.json'; log.write_text(json.dumps(event)+'\n')
            config={'ssh_target':'victim@192.168.64.6','log_path':str(log),'start_at':'beginning'}
            result=collect_once(config,self.db,reader=lambda c,cursor:read_batch({'path':c['log_path'],'cursor':cursor,'start_at':'beginning'}))
            self.assertEqual(result['inserted'],1)
            tick(self.db,self.policy,self.telegram,IDENTITY)
            self.assertIn('getUpdates',self.telegram.methods); self.assertTrue(thread.is_alive())
        finally: resume.set(); thread.join(5)
        self.assertFalse(errors); self.assertEqual(self.status(),'live_complete')


class ProgressTests(unittest.TestCase):
    def test_heartbeat_running_stopped_and_stale(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'state.sqlite3'; record(path,'one','monitor','running')
            with closing(sqlite3.connect(path)) as db:
                db.row_factory=sqlite3.Row
                self.assertTrue(view(db)['running']); self.assertFalse(view(db,time.time()+30)['running'])
            record(path,'one','monitor','stopped')
            with closing(sqlite3.connect(path)) as db:
                db.row_factory=sqlite3.Row; self.assertEqual(view(db)['state'],'stopped')

    def test_wait_is_determinate_inference_is_not(self):
        now=datetime.now(timezone.utc)
        row=dict(incident_id='i',status='pending',evidence=dict(source_ip='192.168.64.4',destination_ip='192.168.64.6',destination_port=22,signature_id=9001001,window_start=now.isoformat()))
        self.assertEqual(incident_view(row,[],now)['progress']['phase']['kind'],'determinate')
        row['analysis_status']='running'
        self.assertEqual(incident_view(row,[],now)['progress']['phase']['kind'],'indeterminate')
        row['analysis_status']='manual_review'
        self.assertEqual(incident_view(row,[],now)['progress']['phase']['kind'],'paused')

    def test_resolved_report_counts_skipped_approval_as_resolved(self):
        row=dict(incident_id='i',status='complete',analysis_status='complete',evidence={},report={'verdict':'BENIGN'},metadata={'assessment_data':{'observed_facts':{}}},approval={'status':'notified','plan':None})
        p=incident_view(row,[])['progress']; self.assertEqual(p['completed'],5); self.assertEqual(p['phase']['kind'],'complete')
        row.update(analysis_status='manual_review',status='manual_review')
        row['report']={'verdict':'INSUFFICIENT_EVIDENCE','recommended_action':'REQUEST_MORE_EVIDENCE'}
        p=incident_view(row,[])['progress']; self.assertLess(p['completed'],5); self.assertEqual(p['phase']['kind'],'paused')


if __name__=='__main__': unittest.main()
