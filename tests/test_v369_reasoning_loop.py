from pathlib import Path
from modules.specialist_reasoning_loop_v369 import run_loop

class E:
    class X:
        target='127.0.0.1'; output=Path('/tmp/v369-test')
    e=X()
    def probe(self): return {'web_signal':'api'}
    def web(self): return {'finding':'authorization'}
    def api(self): return {'ok':True}
    def ports(self): return {'ports':[80]}
    def dns(self): return {'dns':'local'}
    def tls(self): return {'tls':'ok'}

def test_loop_blocks_without_authorization(tmp_path):
    E.e.output=tmp_path
    out=run_loop(engine=E(), objective='web test', authorized=False)
    assert out['status']=='blocked'
    assert (tmp_path/'evidence'/'specialist-reasoning-loop-v369.json').exists()

def test_loop_cross_checks_and_reassesses(tmp_path):
    E.e.output=tmp_path
    out=run_loop(engine=E(), objective='web API network authorization assessment', story='API authorization issue', authorized=True, max_rounds=2)
    assert out['convergence']['hypothesis_challenge'] is True
    assert any(r['actions'] for r in out['rounds'])
    assert (tmp_path/'evidence'/'specialist-reasoning-loop-v369.json').exists()

def test_loop_only_calls_registered_methods(tmp_path):
    E.e.output=tmp_path
    out=run_loop(engine=E(), objective='web network', authorized=True, max_rounds=1)
    phases={a['phase'] for r in out['rounds'] for a in r['actions']}
    assert phases <= {'probe','web','api','ports','dns','tls'}
