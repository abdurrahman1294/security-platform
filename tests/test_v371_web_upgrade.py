from fastapi.testclient import TestClient
from webapp.app import app
client=TestClient(app)

def test_v371_health():
    r=client.get('/api/health'); assert r.status_code==200; assert r.json()['version']=='4.1.0'

def test_attack_path_authorized(tmp_path):
    scope=tmp_path/'scope.txt'; scope.write_text('127.0.0.1\n')
    r=client.post('/api/intelligence/attack-path',json={'target':'127.0.0.1','scope':str(scope),'output':str(tmp_path/'out'),'authorized':True,'story':'role object id behavior'})
    assert r.status_code==200
    assert r.json()['coverage']['node_count']>=1

def test_rare_case_authorized(tmp_path):
    scope=tmp_path/'scope.txt'; scope.write_text('127.0.0.1\n')
    r=client.post('/api/intelligence/rare-case',json={'mission':{'target':'127.0.0.1','scope':str(scope),'output':str(tmp_path/'out'),'authorized':True},'question':'Why does behavior differ between roles?'})
    assert r.status_code==200
    assert 'novel_hypotheses' in r.json()

def test_live_ws_requires_authorization():
    with client.websocket_connect('/api/mission/live') as ws:
        ws.send_json({'authorized':False})
        msg=ws.receive_json()
        assert msg['type']=='error'


def test_precheck_uses_canonical_preflight(tmp_path):
    scope=tmp_path/'scope.txt'; scope.write_text('127.0.0.1\n')
    r=client.post('/api/mission/action/precheck',json={'target':'127.0.0.1','scope':str(scope),'output':str(tmp_path/'out'),'authorized':True})
    assert r.status_code==200
    assert r.json()['result']['ready_for_active'] is True
    assert r.json()['result']['target_in_scope'] is True
