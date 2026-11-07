"""Loopback dashboard: explicit test-plan approval and read-only response views."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
from urllib.parse import urlsplit

from human_review import ReviewConflict,ReviewService

ROOT = Path(__file__).resolve().parent


def database_snapshot(path):
    if not path.exists():
        return {'available':False,'incidents':[], 'counts':{},'note':'No database yet. Monitoring has not recorded an incident here.'}
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
        db.row_factory = sqlite3.Row
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        counts={table:db.execute('SELECT count(*) FROM '+table).fetchone()[0]
                for table in ('events','incidents','analyses','dry_run_actions','live_actions') if table in tables}
        result={'available':True,'counts':counts,'incidents':[],
                'note':'Saved database state; this does not assert that the monitor is currently running.'}
        if 'service_state' in tables:
            from service_state import view
            result['service']=view(db)
        if 'remote_checkpoints' in tables:
            result['last_collection']=db.execute('SELECT max(updated_at) FROM remote_checkpoints').fetchone()[0]
        if 'incidents' not in tables:
            return result
        for row in db.execute('SELECT * FROM incidents ORDER BY rowid DESC LIMIT 50'):
            evidence=json.loads(row['evidence']); incident=dict(row);incident['evidence']=evidence
            incident['report']=None;incident['metadata']={};incident['approval']=None
            if 'analyses' in tables:
                analysis=db.execute('SELECT * FROM analyses WHERE incident_id=? AND revision=?',
                                    (row['incident_id'],row['revision'])).fetchone()
                if analysis:
                    incident.update(analysis_status=analysis['status'],error=analysis['error'],
                        report=json.loads(analysis['report']) if analysis['report'] else None,
                        metadata=json.loads(analysis['metadata']) if analysis['metadata'] else {})
            if 'approval_requests' in tables:
                approval=db.execute('SELECT request_id,status,plan,created_at,expires_at FROM approval_requests WHERE incident_id=? AND revision=?',
                                    (row['incident_id'],row['revision'])).fetchone()
                if approval:
                    incident['approval']=dict(approval)
                    incident['approval']['plan']=json.loads(approval['plan']) if approval['plan'] else None
                    if 'live_actions' in tables:
                        action=db.execute('SELECT run_id,status,started_at,updated_at,rollback_due_at,result FROM live_actions WHERE request_id=?',
                                          (approval['request_id'],)).fetchone()
                        if action:
                            incident['live_action']=dict(action)
                            incident['live_action']['result']=json.loads(action['result'])
            from report_language import present_report
            incident['display_report']=present_report(incident['report'])
            from incident_labels import attach as attach_label
            incident=attach_label(db,incident)
            from human_review import attach
            attach(db,incident,tables)
            result['incidents'].append(incident)
        return result


def snapshot(root=ROOT):
    from approved_plans import load_plans
    from dashboard_view import incident_view, plan_view
    now=datetime.now(timezone.utc)
    from lab_config import load_profile
    lab=load_profile(root=root)
    result={'updated_at':now.isoformat(),'display_timezone':lab['display_timezone'],'platform':lab['platform']}
    from provider_service import ProviderService
    result['assessment_provider']=ProviderService(root).state()
    try:
        policy=json.loads((root/'response.local.json').read_text())
        result['response_policy']={'mode':policy['mode'],'duration_seconds':policy['duration_seconds']}
    except (OSError,ValueError,KeyError): result['response_policy']={'mode':'unknown'}
    try: result['history']=database_snapshot(root/'ssh-live.sqlite3')
    except (sqlite3.Error,ValueError,OSError):
        result['history']={'available':False,'incidents':[],'counts':{},'note':'State temporarily unavailable. Retry shortly.'}
    try:
        config=json.loads((root/'runtime.ssh.live.local.json').read_text())
        result['experimental_assessment']=bool(config.get('experimental_assessment'))
        plan_path=Path(config['approved_plans'])
        if not plan_path.is_absolute(): plan_path=root/plan_path
        plans=load_plans(plan_path)
    except (OSError,ValueError,KeyError,TypeError):
        plans=[]
        result['plan_error']='Dashboard plan registry unavailable; review its configuration.'
    result['plans']=[plan_view(p,now,lab) for p in plans]
    eligible=[p for p in result['plans'] if p['approval_status']=='approved' and p['timing'] in ('active','upcoming')]
    result['next_plan']=min(eligible,key=lambda p:(p['timing']!='active',p['start'])) if eligible else None
    for incident in result['history']['incidents']:
        incident['view']=incident_view(incident,plans,now,result.get('plan_error'),lab)
    try:
        live=json.loads((root/'live.ssh.local.json').read_text())
        result['editor_options']={'source_ips':live['source_ips'], 'target_ip':live['destination_ip'],
                                  'preferred_source_ip':lab['trust_client']['ip'],'maximum_window_minutes':10}
    except (OSError, ValueError, KeyError): result['editor_options']=None
    return result


class Handler(BaseHTTPRequestHandler):
    def allowed(self, write=False):
        allowed={f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}
        if self.headers.get('Host') not in allowed:
            self.send_error(403);return False
        origin=self.headers.get('Origin')
        if (write and origin != 'http://'+self.headers.get('Host','')) or (origin and origin not in {'http://'+h for h in allowed}):
            self.send_error(403);return False
        if write and not secrets.compare_digest(self.headers.get('X-SOAR-CSRF',''), self.server.csrf_token):
            self.send_error(403);return False
        return True

    def respond(self, body, mime='application/json', status=200, filename=None):
        if not isinstance(body, bytes): body=json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type',mime+'; charset=utf-8' if mime.startswith(('text/','application/json')) else mime)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if filename: self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
        self.end_headers();self.wfile.write(body)

    def do_GET(self):
        if not self.allowed(): return
        path=urlsplit(self.path).path
        if path=='/api/state':
            body=snapshot(self.server.root)
            body['csrf_token']=self.server.csrf_token
            self.respond(body);return
        elif path=='/api/experiments':
            body=self.server.experiments.state()
            body['samples']=[dict(incident_id=s['incident_id'],revision=s['revision'],source=s['evidence'].get('source_ip'),
                window_start=s['evidence'].get('window_start'),verdict=(s['original_report'] or {}).get('verdict'))
                for s in self.server.experiments.saved_samples()]
            self.respond(body);return
        elif path in ('/','/app.js','/style.css','/experiments.js'):
            file={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/experiments.js':'experiments.js'}[path]
            body=(self.server.root/'web'/file).read_bytes()
            mime={'/':'text/html','/app.js':'text/javascript','/style.css':'text/css','/experiments.js':'text/javascript'}[path]
        else:
            self.send_error(404);return
        self.respond(body,mime)

    def do_POST(self):
        if not self.allowed(write=True): return
        path=urlsplit(self.path).path
        actions={
            '/api/prompts/save':self.server.experiments.save_prompt,
            '/api/prompts/activate':self.server.experiments.activate,
            '/api/experiments/compare':self.server.experiments.start_comparison,
            '/api/rules/read':self.server.rules.read,
            '/api/rules/validate':self.server.rules.validate,
            '/api/rules/apply':self.server.rules.apply,
            '/api/rules/restore':self.server.rules.restore,
            '/api/reviews/save':self.server.reviews.save,
            '/api/reviews/notify':self.server.reviews.notify}
        actions.update({'/api/providers/activate':self.server.providers.activate,'/api/providers/check':self.server.providers.check})
        if path not in ('/api/plans/validate','/api/plans/approve') and path not in actions:
            self.send_error(404);return
        try:
            length=int(self.headers.get('Content-Length','0'))
            limit=8192 if path.startswith('/api/plans/') else 32768
            if not 1 <= length <= limit:
                self.respond({'error':f'Request must be 1–{limit} bytes.'},status=413);return
            if self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                self.respond({'error':'Send JSON plan fields.'},status=415);return
            self.connection.settimeout(10)
            values=json.loads(self.rfile.read(length))
            if path in actions:
                result=actions[path](values)
            elif path.endswith('/validate'):
                result=self.server.editor.validate(values)
            else:
                if not isinstance(values,dict) or set(values) != {'draft_id','validation_token'}:
                    raise ValueError('Approve the exact validated draft.')
                result={'plan':self.server.editor.approve(values['draft_id'],values['validation_token'])}
            self.respond(result)
        except ReviewConflict as exc:
            self.respond({'error':str(exc)},status=409)
        except (ValueError, TypeError, KeyError) as exc:
            self.respond({'error':str(exc)},status=400)
        except (RuntimeError,subprocess.SubprocessError) as exc:
            self.respond({'error':str(exc)[:2000]},status=503)
        except (OSError,sqlite3.Error):
            self.respond({'error':'Plan storage is unavailable. No approval was confirmed; retry after checking local files.'},status=503)
    def log_message(self,*args): pass


class DashboardServer(ThreadingHTTPServer):
    def server_close(self):
        super().server_close()
        if hasattr(self,'experiments'): self.experiments.close()


def make_server(root=ROOT, port=8765):
    from plan_editor import PlanEditor
    from lab_config import load_profile
    from incident_labels import configure_timezone
    configure_timezone(load_profile(root=root)['display_timezone'])
    server=DashboardServer(('127.0.0.1',port),Handler)
    server.root=Path(root).resolve()
    server.csrf_token=secrets.token_hex(32)
    server.editor=PlanEditor(server.root)
    from provider_service import ProviderService
    server.providers=ProviderService(server.root)
    from experiment_store import ExperimentStore
    from rule_editor import RuleEditor
    server.experiments=ExperimentStore(server.root)
    server.rules=RuleEditor(server.root)
    server.reviews=ReviewService(server.root)
    return server


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--root',type=Path,default=ROOT,help='Alternate data root for isolated QA')
    args=parser.parse_args()
    with make_server(root=args.root,port=args.port) as server:
        print(f'SOAR dashboard: http://127.0.0.1:{server.server_port}',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
