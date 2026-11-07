from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from analyst import analyze_next
from collector import collect
from incidents import group_events
from response import (deliver_one, execute_dry_run, handle_update, initialize,
                      plan_for, queue_reports)
from telegram_client import TelegramError, load_credentials


IDENTITY = dict(bot_key="test-bot", chat_id=100, user_id=100)
REPORT = dict(verdict="SUSPICIOUS", reason="Repeated SSH connections warrant review.",
              recommendations=["Check authentication logs.", "Review the source host."])


class FakeTelegram:
    def call(self, method, payload):
        if method != "sendMessage":
            raise AssertionError(method)
        return dict(message_id=42, chat=dict(id=100))


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "state.sqlite3"
        self.policy = json.loads(Path("config/response.example.json").read_text())
        self.policy.update(mode='dry_run',duration_seconds=600,exclusive_polling_confirmed=True)
        collect("fixtures/eve.json", self.db)
        group_events(self.db)
        analyze_next(self.db, {}, now=datetime(2026, 10, 21, tzinfo=timezone.utc),
                     runner=lambda *args: {"text": json.dumps(REPORT),"model":"gemma4:e4b"})
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE analyses SET status='complete',report=?",(json.dumps(REPORT),))
            db.execute("UPDATE incidents SET status='complete'")

    def pending(self):
        self.assertEqual(queue_reports(self.db, self.policy, IDENTITY, now=1000), 1)
        self.assertEqual(deliver_one(self.db, FakeTelegram(), IDENTITY, now=1000), "sent")
        with closing(sqlite3.connect(self.db)) as db:
            return db.execute("SELECT request_id FROM approval_requests").fetchone()[0]

    def callback(self, request, *, update_id=10, user=100, chat=100, message=42, decision="a"):
        return {"update_id": update_id, "callback_query": {"id": "query-id", "data": f"soc5:{decision}:{request}",
            "from": {"id": user}, "message": {"message_id": message, "chat": {"id": chat, "type": "private"}}}}

    def test_approval_creates_exactly_one_dry_run(self):
        request = self.pending()
        update = self.callback(request)
        self.assertEqual(handle_update(self.db, update, IDENTITY, now=1010), "approved")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 1)
        self.assertEqual(handle_update(self.db, update, IDENTITY, now=1012), "duplicate_update")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1013), 0)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM dry_run_actions").fetchone()[0], 1)

    def test_denial_never_creates_action(self):
        request = self.pending()
        self.assertEqual(handle_update(self.db, self.callback(request, decision="d"), IDENTITY, now=1010), "denied")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 0)

    def test_wrong_user_chat_or_message_cannot_approve(self):
        request = self.pending()
        for update_id, change in enumerate((dict(user=999), dict(chat=999), dict(message=999)), 10):
            self.assertEqual(handle_update(self.db, self.callback(request, update_id=update_id, **change),
                                           IDENTITY, now=1010), "unauthorized")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 0)

    def test_expired_button_cannot_approve(self):
        request = self.pending()
        self.assertEqual(handle_update(self.db, self.callback(request), IDENTITY, now=1600), "not_pending")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1601), 0)

    def test_changed_revision_invalidates_approval(self):
        request = self.pending()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE incidents SET revision=revision+1")
        self.assertEqual(handle_update(self.db, self.callback(request), IDENTITY, now=1010), "not_pending")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 0)

    def test_policy_change_between_approval_and_execution_rejected(self):
        request = self.pending()
        handle_update(self.db, self.callback(request), IDENTITY, now=1010)
        self.policy["duration_seconds"] = 60
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 0)

    def test_protected_and_out_of_scope_targets_rejected(self):
        for source in ("192.168.64.1", "192.168.64.6", "8.8.8.8", "bad; command"):
            with self.assertRaises(ValueError):
                plan_for(dict(source_ip=source, destination_ip="192.168.64.6",
                              destination_port=22, signature_id=9001001), self.policy)

    def test_general_yes_message_is_not_an_approval(self):
        self.pending()
        self.assertEqual(handle_update(self.db, {"update_id": 1, "message": {"text": "YES"}},
                                       IDENTITY, now=1010), "ignored")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 0)

    def test_uncertain_delivery_is_not_automatically_resent(self):
        queue_reports(self.db, self.policy, IDENTITY, now=1000)
        class Broken:
            def call(self, *args):
                raise TelegramError("timeout")
        self.assertEqual(deliver_one(self.db, Broken(), IDENTITY, now=1000), "delivery_unknown")
        self.assertEqual(deliver_one(self.db, FakeTelegram(), IDENTITY, now=1001), "idle")

    def test_no_duplicate_request_on_restart(self):
        self.pending()
        self.assertEqual(queue_reports(self.db, self.policy, IDENTITY, now=1001), 0)

    def test_dry_run_executor_refuses_live_mode(self):
        self.policy["mode"] = "live"
        with self.assertRaises(ValueError):
            execute_dry_run(self.db, self.policy, now=1011)

    def test_approval_expiring_before_execution_is_rejected(self):
        request = self.pending()
        handle_update(self.db, self.callback(request), IDENTITY, now=1010)
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1600), 0)

    def test_same_active_plan_is_not_recorded_twice_across_revisions(self):
        request = self.pending()
        handle_update(self.db, self.callback(request), IDENTITY, now=1010)
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1011), 1)
        with closing(sqlite3.connect(self.db)) as db, db:
            incident, revision = db.execute("SELECT incident_id,revision FROM incidents").fetchone()
            db.execute("UPDATE incidents SET revision=revision+1")
            db.execute("""INSERT INTO analyses(incident_id,revision,status,report,prompt_hash)
                       VALUES(?,?,'complete',?,'test')""", (incident, revision+1, json.dumps(REPORT, sort_keys=True)))
        self.assertEqual(queue_reports(self.db, self.policy, IDENTITY, now=1020), 1)
        self.assertEqual(deliver_one(self.db, FakeTelegram(), IDENTITY, now=1020), "sent")
        with closing(sqlite3.connect(self.db)) as db:
            second = db.execute("SELECT request_id FROM approval_requests WHERE status='pending'").fetchone()[0]
        handle_update(self.db, self.callback(second, update_id=11), IDENTITY, now=1021)
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1022), 0)

    def test_report_only_has_no_approval_buttons(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE analyses SET report=?", (json.dumps(dict(REPORT, verdict="INSUFFICIENT_EVIDENCE")),))
        queue_reports(self.db, self.policy, IDENTITY, now=1000)
        class ReportOnly:
            def call(inner, method, payload):
                self.assertNotIn("reply_markup", payload)
                return dict(message_id=42, chat=dict(id=100))
        self.assertEqual(deliver_one(self.db, ReportOnly(), IDENTITY, now=1000), "sent")
        self.assertEqual(execute_dry_run(self.db, self.policy, now=1001), 0)

    def test_credential_reader_does_not_execute_legacy_script(self):
        script = Path(self.tmp.name) / "legacy.py"
        script.write_text("TOKEN = 'fake-test-token'\nCHAT_ID = '100'\nraise RuntimeError('must not execute')\n")
        credentials = load_credentials(dict(credentials_source=str(script)))
        self.assertEqual(credentials.chat_id, 100)
        self.assertNotIn("fake-test-token", repr(credentials))


if __name__ == "__main__":
    unittest.main()
