import json
from pathlib import Path
from modules.web_test_matrix_v48 import build as build_matrix
from modules.web_probe_v49 import run as run_probe
from modules.web_decisions_v50 import build as build_decisions


def seed(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'web-assessment-plan-v47.json').write_text(json.dumps({
        'tasks':[{'test_id':'W47-a','category':'Security configuration','target':'http://127.0.0.1:8765','priority':'medium','status':'planned'}]
    }))
    (tmp_path/'scope.txt').write_text('127.0.0.1\n')


def test_v48_matrix_is_non_destructive(tmp_path):
    seed(tmp_path)
    ep,rp=build_matrix(tmp_path); d=json.loads(ep.read_text())
    assert d['test_count'] >= 4
    assert all(x['destructive'] is False and x['operator_approval_required'] for x in d['tests'])
    assert rp.exists()


def test_v49_requires_approval_and_scope(tmp_path):
    seed(tmp_path); build_matrix(tmp_path)
    try:
        run_probe(tmp_path,str(tmp_path/'scope.txt'),approved=False)
        assert False
    except PermissionError:
        pass


def test_v49_loopback_and_v50_decisions(tmp_path):
    seed(tmp_path); build_matrix(tmp_path)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header('Content-Type','text/plain'); self.end_headers(); self.wfile.write(b'ok')
        def log_message(self,*a): pass
    server=HTTPServer(('127.0.0.1',8765),H); th=threading.Thread(target=server.serve_forever,daemon=True); th.start()
    try:
        ep,_=run_probe(tmp_path,str(tmp_path/'scope.txt'),approved=True,max_requests=3)
        d=json.loads(ep.read_text()); assert d['result_count']==1 and d['results'][0]['status']=='observed'
        ep2,_=build_decisions(tmp_path); d2=json.loads(ep2.read_text()); assert d2['human_control_required']
        assert d2['decisions'][0]['next_action'] == 'review-security-headers'
    finally:
        server.shutdown()
