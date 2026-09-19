from pathlib import Path
import json
from modules.dependency_resolution_fabric_v410 import resolve
class E:
 class X: target='127.0.0.1'; scope_file=Path('config/scope.example.txt'); output=Path('/tmp/v410-test')
 e=X()
 def probe(self):
  p=self.e.output/'evidence';p.mkdir(parents=True,exist_ok=True);(p/'pentest-http-probe.json').write_text('{}');return {'returncode':0}
 def crawl_and_scan(self):
  p=self.e.output/'web';p.mkdir(parents=True,exist_ok=True);(p/'urls.txt').write_text('http://127.0.0.1');return {'status':'completed'}
def test_auth_waits_for_operator(monkeypatch):
 monkeypatch.delenv('PENTEST_AUTH_COOKIE',raising=False);monkeypatch.delenv('PENTEST_AUTH_BEARER',raising=False);monkeypatch.delenv('PENTEST_AUTH_HEADER',raising=False); e=E();e.e.output=Path('/tmp/v410-a');d=resolve(engine=e,dependencies=[{'hypothesis_id':'h','dependency':'authenticated','priority':1}],approval_token='ok',authorized=True);assert d['status']=='waiting_for_operator'
def test_web_resolves():
 e=E();e.e.output=Path('/tmp/v410-b');d=resolve(engine=e,dependencies=[{'hypothesis_id':'h','dependency':'web','priority':1}],authorized=True);assert d['status']=='ready_to_resume'
def test_json_safe():
 e=E();e.e.output=Path('/tmp/v410-c');d=resolve(engine=e,dependencies=[{'hypothesis_id':'h','dependency':'web','priority':1}],authorized=True);json.dumps(d)
