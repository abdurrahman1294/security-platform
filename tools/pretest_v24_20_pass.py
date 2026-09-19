from pathlib import Path
import tempfile
import sys, threading, importlib.util
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.remote_lab_v24 import assess
from modules.lab_http import request

ROOT=Path(__file__).resolve().parents[1]
app_path=ROOT/'lab'/'adversarial-remote-lab'/'remote-target'/'app.py'
spec=importlib.util.spec_from_file_location('v24lab', app_path)
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
from http.server import HTTPServer
server=HTTPServer(('127.0.0.1', 18090), mod.H)
t=threading.Thread(target=server.serve_forever, daemon=True); t.start()
try:
    tmp=Path(tempfile.mkdtemp())
    tests=[]
    def check(name, fn):
        try: fn(); tests.append((name,'PASS'))
        except Exception as e: tests.append((name,f'FAIL: {e}'))
    check('01 base loopback accepted', lambda: request('http://127.0.0.1:18090/').get('status')==200)
    check('02 service marker', lambda: 'adversarial-remote-lab' in request('http://127.0.0.1:18090/')['body'])
    check('03 rce proof marker', lambda: 'RCE_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/rce')['body'])
    check('04 command injection marker', lambda: 'COMMAND_INJECTION_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/command-injection')['body'])
    check('05 ssrf marker', lambda: 'SSRF_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/ssrf')['body'])
    check('06 credential exposure fixture', lambda: 'FakeLabPassword-2026' in request('http://127.0.0.1:18090/lab/credentials')['body'])
    check('07 privilege marker', lambda: 'PRIVESC_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/privilege')['body'])
    check('08 persistence marker', lambda: 'PERSISTENCE_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/persistence')['body'])
    check('09 lateral marker', lambda: 'LATERAL_AUTH_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/lateral')['body'])
    check('10 objective marker', lambda: 'OBJECTIVE_ACCESS_CONFIRMED' in request('http://127.0.0.1:18090/lab/proof/objective')['body'])
    check('11 destructive boundary marker', lambda: 'DESTRUCTIVE_ACTION_BLOCKED' in request('http://127.0.0.1:18090/lab/proof/destructive')['body'])
    check('12 dry-run catalog', lambda: assess(tmp/'dry','http://127.0.0.1:18090')['status']=='dry_run')
    check('13 unauthorized execution blocked', lambda: assess(tmp/'blocked','http://127.0.0.1:18090',execute=True,authorized=False,roe_permitted=True)['status']=='blocked')
    check('14 unpermitted ROE blocked', lambda: assess(tmp/'blocked2','http://127.0.0.1:18090',execute=True,authorized=True,roe_permitted=False)['status']=='blocked')
    check('15 non-loopback blocked', lambda: assess(tmp/'blocked3','http://192.0.2.1:18090',execute=True,authorized=True,roe_permitted=True)['status']=='blocked')
    check('16 malformed scenario blocked', lambda: assess(tmp/'blocked4','http://127.0.0.1:18090',scenarios=('not-a-scenario',))['status']=='blocked')
    check('17 full controlled execution', lambda: assess(tmp/'full','http://127.0.0.1:18090',execute=True,authorized=True,roe_permitted=True)['status']=='completed')
    check('18 evidence persisted', lambda: (tmp/'full'/'evidence'/'remote-assessment.json').is_file())
    check('19 evidence contains no arbitrary command field', lambda: 'command_to_execute' not in (tmp/'full'/'evidence'/'remote-assessment.json').read_text())
    check('20 lab app has no shell=True', lambda: 'shell=True' not in app_path.read_text())
    passed=sum(x[1]=='PASS' for x in tests)
    for n,s in tests: print(n,s)
    print(f'SUMMARY passed={passed} failed={len(tests)-passed} total={len(tests)}')
    raise SystemExit(0 if passed==20 else 1)
finally:
    server.shutdown()
