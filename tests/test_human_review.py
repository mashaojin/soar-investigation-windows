from contextlib import closing
from copy import deepcopy
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from unittest.mock import patch

from human_review import ReviewService,ReviewConflict,attach,load_incident,initialize,deliver_notifications,notification_message
from dashboard import make_server,snapshot
from dashboard_view import incident_view
from response import deliver_one,queue_reports,message_for
from telegram_client import TelegramError

IDENT='a'*64

class Telegram:
    def __init__(self):self.calls=[]
    def call(self,method,payload):self.calls.append((method,payload));return {'message_id':42}

class ReviewFixture:
    def setup_fixture(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'ssh-live.sqlite3';self.service=ReviewService(self.root)
        self.evidence=dict(source_ip='192.168.64.4',destination_ip='192.168.64.6',destination_port=22,signature_id=9001001,window_start='2026-11-04T22:41:00+00:00')
        with closing(sqlite3.connect(self.path)) as db,db:
            db.executescript('''CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT);
                CREATE TABLE analyses(incident_id TEXT,revision INTEGER,status TEXT,report TEXT,error TEXT,metadata TEXT,created_at TEXT);''')
            db.execute("INSERT INTO incidents VALUES(?,2,?,2,'manual_review')",(IDENT,json.dumps(self.evidence)))
            db.execute("INSERT INTO analyses VALUES(?,2,'manual_review',NULL,?,'{}','2026-11-04 22:41:50')",(IDENT,'No authentication outcomes or protection observations'))
        self.identity=dict(bot_key='synthetic',chat_id=1,user_id=1)

    def incident(self):
        with closing(sqlite3.connect(self.path)) as db:return attach(db,load_incident(db,IDENT))

    def values(self,conclusion='BENIGN'):
        i=self.incident();return dict(incident_id=IDENT,revision=i['revision'],snapshot_hash=i['review_context']['snapshot_hash'],
            expected_review_id=i['review_context']['expected_review_id'],reviewer='QA operator',conclusion=conclusion,
            notes='Isolated test review: checked the retained evidence and operator test schedule.')

    def notify_values(self):
        i=self.incident();return {k:self.values()[k] for k in ('incident_id','revision','snapshot_hash')}

class HumanReviewTests(ReviewFixture,unittest.TestCase):
    def setUp(self):self.setup_fixture()

    def save_advisory(self, status, text):
        report = dict(format='advisory_text', reason=text, evidence_refs=['E1'])
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('UPDATE incidents SET status=?',(status,))
            db.execute('UPDATE analyses SET status=?,report=?,error=NULL',(status,json.dumps(report)))

    def test_benign_advisory_delivers_report_only_and_can_be_reviewed_on_dashboard(self):
        self.save_advisory('complete','Assessment: Benign\nActivity is within the plan [E1].')
        incident=self.incident()
        self.assertTrue(incident['review_context']['review_optional'])
        self.assertEqual(incident_view(incident,[])['label'],'Report only')
        with self.assertRaises(ValueError):
            self.service.notify(self.notify_values())
        policy=dict(mode='dry_run',approval_ttl_seconds=600)
        self.assertEqual(queue_reports(self.path,policy,self.identity,now=1000),1)
        self.assertEqual(queue_reports(self.path,policy,self.identity,now=1000),0)
        client=Telegram()
        with patch.object(client,'call',wraps=client.call) as send:
            send.side_effect=lambda method,payload: dict(message_id=42,chat={'id':1})
            self.assertEqual(deliver_one(self.path,client,self.identity,now=1000),'sent')
            payload=send.call_args.args[1]
        self.assertIn('Report only',payload['text'])
        self.assertNotIn('reply_markup',payload)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT status,plan FROM approval_requests').fetchone(),('notified',None))
        self.assertTrue(self.service.save(self.values('SUSPICIOUS'))['resolved'])
        self.assertEqual(incident_view(self.incident(),[])['ai_verdict'],'BENIGN')

    def test_non_benign_advisory_review_has_buttons_and_never_creates_action_request(self):
        for text in ('Assessment: Suspicious\nConsider blocking [E1].',
                     'Assessment: Insufficient evidence\nCheck logs [E1].',
                     'Unclear [E1].\nAssessment: Benign'):
            with self.subTest(text=text):
                self.save_advisory('manual_review',text)
                incident=self.incident()
                self.assertFalse(incident['review_context']['review_optional'])
                self.assertTrue(incident_view(incident,[])['workflow_attention'])
                notice=notification_message(incident,self.identity,'1'*24)
                self.assertEqual(sum(map(len,notice['reply_markup']['inline_keyboard'])),3)
                self.assertEqual(queue_reports(self.path,dict(mode='dry_run',approval_ttl_seconds=600),self.identity),0)

    def test_save_resolves_view_without_overwriting_ai_or_action_records(self):
        before=self.incident();result=self.service.save(self.values())
        after=self.incident();view=incident_view(after,[])
        self.assertTrue(result['resolved']);self.assertEqual(view['label'],'Resolved by human review')
        self.assertIsNone(view['ai_verdict']);self.assertEqual(view['progress']['phase']['kind'],'complete')
        for field in ('evidence','status','analysis_status','report','error','metadata','revision'):
            self.assertEqual(before[field],after[field])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master WHERE name IN ('live_actions','dry_run_actions')").fetchone())

    def test_human_verdict_can_differ_from_ai(self):
        report=dict(verdict='SUSPICIOUS',recommended_action='REQUEST_MORE_EVIDENCE')
        with closing(sqlite3.connect(self.path)) as db,db:db.execute('UPDATE analyses SET report=?',(json.dumps(report),))
        self.service.save(self.values('BENIGN'));i=self.incident();view=incident_view(i,[])
        self.assertEqual(view['ai_verdict'],'SUSPICIOUS');self.assertEqual(i['human_review']['conclusion'],'BENIGN')
        self.assertEqual(i['report'],report)

    def test_more_evidence_keeps_open_and_followup_retains_history(self):
        self.service.save(self.values('NEEDS_MORE_EVIDENCE'));i=self.incident()
        self.assertEqual(incident_view(i,[])['label'],'Awaiting more evidence')
        self.assertTrue(incident_view(i,[])['workflow_attention'])
        self.service.save(self.values('SUSPICIOUS'));i=self.incident()
        self.assertEqual(len(i['human_review_history']),2)
        self.assertEqual(i['human_review']['conclusion'],'SUSPICIOUS')

    def test_exact_revision_and_analysis_binding(self):
        values=self.values()
        with closing(sqlite3.connect(self.path)) as db,db:db.execute("UPDATE analyses SET metadata='{} ' ")
        # Equivalent JSON whitespace does not change evidence meaning.
        self.service.save(values)
        values=self.values()
        with closing(sqlite3.connect(self.path)) as db,db:db.execute("UPDATE analyses SET error='Changed evidence failure'")
        with self.assertRaises(ReviewConflict):self.service.save(values)

    def test_new_revision_does_not_inherit_old_resolution(self):
        self.service.save(self.values())
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('UPDATE incidents SET revision=3')
            db.execute("INSERT INTO analyses VALUES(?,3,'manual_review',NULL,'New evidence','{}','2026-11-04 22:45:00')",(IDENT,))
        i=self.incident();self.assertIsNone(i['human_review'])
        self.assertEqual(len(i['human_review_history']),1);self.assertFalse(i['human_review_history'][0]['applies_to_current_snapshot'])
        self.assertFalse(incident_view(i,[])['human_resolved'])

    def test_concurrent_or_duplicate_submission_rejected(self):
        old=self.values();self.service.save(old)
        with self.assertRaises(ReviewConflict):self.service.save(old)
        self.assertEqual(len(self.incident()['human_review_history']),1)

    def test_append_only_records_reject_updates_and_deletes(self):
        self.service.save(self.values())
        with closing(sqlite3.connect(self.path)) as db:
            for sql in ["UPDATE human_reviews SET conclusion='SUSPICIOUS'",'DELETE FROM human_reviews']:
                with self.assertRaises(sqlite3.IntegrityError):db.execute(sql)

    def test_notes_have_no_character_count_requirement(self):
        for notes in ('','x','A'*10000):
            self.service.save(dict(self.values('NEEDS_MORE_EVIDENCE'),notes=notes))
            self.assertEqual(self.incident()['human_review']['notes'],notes)

    def review_callback(self,choice='s',**changes):
        self.service.notify(self.notify_values());client=Telegram()
        deliver_notifications(self.path,{},client,self.identity)
        payload=client.calls[0][1];token=payload['reply_markup']['inline_keyboard'][0][0]['callback_data'].split(':')[-1]
        query={'id':'test-query','data':'hr:'+choice+':'+token,'from':{'id':1},
            'message':{'message_id':42,'chat':{'id':1,'type':'private'}}}
        query.update(changes)
        return {'update_id':42,'callback_query':query}

    def test_telegram_review_is_authenticated_deduplicated_and_separate(self):
        from response import handle_update
        update=self.review_callback()
        self.assertEqual(handle_update(self.path,update,self.identity),'review_suspicious')
        self.assertEqual(handle_update(self.path,update,self.identity),'duplicate_update')
        i=self.incident();self.assertEqual(i['human_review']['conclusion'],'SUSPICIOUS');self.assertIsNone(i['report'])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM approval_requests').fetchone()[0],0)
        update['update_id']=43
        self.assertEqual(handle_update(self.path,update,self.identity),'review_unavailable')

    def test_telegram_rejects_wrong_operator_message_and_stale_review(self):
        from response import handle_update
        update=self.review_callback();update['callback_query']['from']['id']=99
        self.assertEqual(handle_update(self.path,update,self.identity),'unauthorized')
        update['update_id']=43;update['callback_query']['from']['id']=1
        update['callback_query']['message']['message_id']=999
        self.assertEqual(handle_update(self.path,update,self.identity),'unauthorized')
        update['update_id']=44;update['callback_query']['message']['message_id']=42
        self.service.save(self.values('NEEDS_MORE_EVIDENCE'))
        self.assertEqual(handle_update(self.path,update,self.identity),'review_changed')

    def test_telegram_benign_and_changed_evidence(self):
        from response import handle_update
        update=self.review_callback('b')
        with closing(sqlite3.connect(self.path)) as db,db:db.execute("UPDATE analyses SET error='Evidence changed'")
        self.assertEqual(handle_update(self.path,update,self.identity),'review_changed')
        self.assertIsNone(self.incident()['human_review'])

    def test_telegram_benign_resolves_review(self):
        from response import handle_update
        self.assertEqual(handle_update(self.path,self.review_callback('b'),self.identity),'review_benign')
        self.assertTrue(incident_view(self.incident(),[])['human_resolved'])

    def test_telegram_expiry_and_more_evidence(self):
        from response import handle_update
        update=self.review_callback('e')
        self.assertEqual(handle_update(self.path,update,self.identity,now=9999999999),'review_expired')
        update['update_id']=43
        self.assertEqual(handle_update(self.path,update,self.identity),'review_needs_more_evidence')
        self.assertFalse(incident_view(self.incident(),[])['human_resolved'])

    def test_invalid_fields_rejected(self):
        for changes in [{'notes':12},{'reviewer':' '},{'conclusion':'BLOCK'},{'revision':True},{'apply_firewall':True}]:
            with self.assertRaises(ValueError):self.service.save(dict(self.values(),**changes))

    def test_active_action_cannot_be_bypassed_by_review(self):
        from response import initialize as responses
        with closing(sqlite3.connect(self.path)) as db,db:
            responses(db)
            db.execute("INSERT INTO approval_requests(request_id,incident_id,revision,report,plan,status,bot_key,chat_id,user_id,created_at,expires_at) VALUES('r',?,2,'{}','{}','approved','test',1,1,0,9999999999)",(IDENT,))
        with self.assertRaises(ReviewConflict):self.service.save(self.values())

    def test_completed_assessment_is_not_silently_reopened(self):
        with closing(sqlite3.connect(self.path)) as db,db:db.execute("UPDATE analyses SET status='complete'")
        with self.assertRaises(ValueError):self.service.save(self.values())

    def test_notice_queued_once_and_uses_no_response_buttons(self):
        result=self.service.notify(self.notify_values());self.service.notify(self.notify_values())
        client=Telegram();self.assertEqual(deliver_notifications(self.path,{},client,self.identity),'sent')
        self.assertEqual(deliver_notifications(self.path,{},client,self.identity),'idle')
        self.assertEqual(len(client.calls),1);payload=client.calls[0][1]
        self.assertIn('Manual review needed on the dashboard',payload['text']);self.assertIn('Reason:',payload['text'])
        self.assertEqual(len(payload['reply_markup']['inline_keyboard']),2)

    def test_advisory_notice_includes_bounded_assessment_and_review_buttons(self):
        reason = 'Assessment: Suspicious\nUnexpected root attempt [E2].'
        incident = dict(incident_id=IDENT,revision=2,report=dict(format='advisory_text',
                        reason=reason+' '+('extra detail '*100)+'END'))
        payload = notification_message(incident,self.identity,'a'*24)
        self.assertIn('AI assessment:\n'+reason,payload['text'])
        self.assertNotIn('END',payload['text'])
        self.assertIn('…',payload['text'])
        self.assertEqual([button['callback_data'][:4] for row in payload['reply_markup']['inline_keyboard']
                          for button in row],['hr:b','hr:s','hr:e'])

    def test_new_failures_notify_after_activation_without_historical_flood(self):
        client=Telegram()
        self.assertEqual(deliver_notifications(self.path,{'review_notifications_enabled_after':'2026-11-04T22:42:00Z'},client,self.identity),'idle')
        self.assertEqual(deliver_notifications(self.path,{'review_notifications_enabled_after':'2026-11-04T22:40:00Z'},client,self.identity),'sent')
        self.assertEqual(deliver_notifications(self.path,{'review_notifications_enabled_after':'2026-11-04T22:40:00Z'},client,self.identity),'idle')

    def test_resolved_review_cancels_queued_notice(self):
        self.service.notify(self.notify_values());self.service.save(self.values())
        client=Telegram();self.assertEqual(deliver_notifications(self.path,{},client,self.identity),'idle');self.assertEqual(client.calls,[])

    def test_changed_snapshot_invalidates_notice(self):
        self.service.notify(self.notify_values())
        with closing(sqlite3.connect(self.path)) as db,db:db.execute("UPDATE analyses SET error='Changed'")
        client=Telegram();self.assertEqual(deliver_notifications(self.path,{},client,self.identity),'stale');self.assertFalse(client.calls)

    def test_uncertain_send_is_never_automatically_repeated(self):
        self.service.notify(self.notify_values())
        client=Telegram()
        with patch.object(client,'call',side_effect=TelegramError('timeout')):
            self.assertEqual(deliver_notifications(self.path,{},client,self.identity),'delivery_unknown')
        self.assertEqual(deliver_notifications(self.path,{},client,self.identity),'idle');self.assertFalse(client.calls)

    def test_valid_manual_report_includes_review_instructions(self):
        report=dict(verdict='SUSPICIOUS',recommended_action='REQUEST_MORE_EVIDENCE',reason='More evidence is needed.',recommendations=['Review source.','Retain logs.'])
        row=dict(report=json.dumps(report),plan=None,expires_at=0,incident_id=IDENT,revision=2,request_id='r',status='notified',chat_id=1)
        text=message_for(row)['text'];self.assertIn('Manual review needed on the dashboard',text);self.assertIn('#incident='+IDENT,text)

class ReviewHTTPTests(ReviewFixture,unittest.TestCase):
    def setUp(self):
        self.setup_fixture();self.server=make_server(self.root,port=0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.addCleanup(self.close)
        self.base='http://127.0.0.1:'+str(self.server.server_port)

    def close(self):self.server.shutdown();self.server.server_close();self.thread.join()

    def request(self,path,values,headers=None):
        return Request(self.base+path,data=json.dumps(values).encode(),headers={'Content-Type':'application/json',
            'Origin':self.base,'X-SOAR-CSRF':self.server.csrf_token,**(headers or {})})

    def test_save_http_and_conflict_with_latest_review_in_snapshot(self):
        values=self.values()
        with urlopen(self.request('/api/reviews/save',values)) as response:self.assertTrue(json.load(response)['resolved'])
        with urlopen(self.base+'/api/state') as response:state=json.load(response)
        row=state['history']['incidents'][0]
        self.assertEqual(row['human_review']['reviewer'],'QA operator');self.assertTrue(row['view']['human_resolved'])
        with self.assertRaises(HTTPError) as caught:urlopen(self.request('/api/reviews/save',values))
        self.assertEqual(caught.exception.code,409)

    def test_origin_csrf_and_arbitrary_action_fields_rejected(self):
        for headers in [{'Origin':'https://untrusted.example'},{'X-SOAR-CSRF':''}]:
            with self.assertRaises(HTTPError) as caught:urlopen(self.request('/api/reviews/save',self.values(),headers))
            self.assertEqual(caught.exception.code,403)
        with self.assertRaises(HTTPError) as caught:urlopen(self.request('/api/reviews/save',dict(self.values(),block_ip=True)))
        self.assertEqual(caught.exception.code,400)

if __name__=='__main__':unittest.main()
