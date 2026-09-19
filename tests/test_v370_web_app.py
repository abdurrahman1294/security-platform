from fastapi.testclient import TestClient
from webapp.app import app

client=TestClient(app)

def test_health():
    r=client.get('/api/health')
    assert r.status_code==200
    assert r.json()['version']=='4.1.0'

def test_unauthorized_reasoning_blocked(tmp_path):
    r=client.post('/api/mission/reason',json={'client':'lab','target':'127.0.0.1','scope':str(tmp_path/'missing.txt'),'output':str(tmp_path/'out'),'authorized':False})
    assert r.status_code==403

def test_static_ui():
    r=client.get('/')
    assert r.status_code==200
    assert 'Cyber Operations Workspace' in r.text
    assert 'V4.1' in r.text


def test_attack_path_requires_authorization(tmp_path):
    r=client.post('/api/intelligence/attack-path',json={'target':'127.0.0.1','scope':str(tmp_path/'missing.txt'),'output':str(tmp_path/'out'),'authorized':False})
    assert r.status_code==403

def test_conversation_endpoint(tmp_path):
    r=client.post('/api/conversation',json={'mission':{'target':'127.0.0.1','output':str(tmp_path/'out')},'message':'What should I investigate next?'})
    assert r.status_code==200

def test_live_endpoint_exists():
    assert '/api/mission/live' in str(app.routes)
