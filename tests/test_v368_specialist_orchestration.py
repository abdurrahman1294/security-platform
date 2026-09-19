import json
from pathlib import Path
from modules.specialist_orchestrator_v368 import select_specialists, orchestrate

class E:
    class X:
        target='127.0.0.1'
        output=Path('/tmp/v368-test')
    e=X()
    class P:
        def contains(self, x): return x == '127.0.0.1'
    policy=P()
    def probe(self): return {'ok': True}
    def web(self): return {'ok': True}
    def api(self): return {'ok': True}
    def ports(self): return {'ok': True}
    def dns(self): return {'ok': True}
    def tls(self): return {'ok': True}

def test_specialist_router_selects_relevant_domains():
    s=select_specialists(story='This is a strange JWT authorization and API behavior with a possible IDOR', objective='find the attack path')
    names={x['specialist'] for x in s}
    assert 'web' in names and 'identity' in names

def test_orchestrator_blocks_without_authorization(tmp_path):
    E.e.output=tmp_path
    out=orchestrate(engine=E(), objective='web assessment', authorized=False)
    assert out['status']=='blocked'
    assert (tmp_path/'evidence'/'adaptive-specialist-orchestration-v368.json').exists()

def test_orchestrator_uses_registered_entrypoints(tmp_path):
    E.e.output=tmp_path
    out=orchestrate(engine=E(), objective='web and network assessment', authorized=True, max_rounds=1)
    phases=[a['phase'] for r in out['rounds'] for a in r['actions']]
    assert 'probe' in phases and 'ports' in phases
