import json
from modules.auth_intelligence_v51 import build as build_auth
from modules.session_intelligence_v54 import build as build_session
from modules.session_observation_v55 import run as run_observe
from modules.identity_transitions_v56 import build as build_transitions

def seed(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'auth-intelligence-v51.json').write_text(json.dumps({'surfaces':[
        {'endpoint':'http://127.0.0.1:8776/login','auth_surface':'login'},
        {'endpoint':'http://127.0.0.1:8776/logout','auth_surface':'logout'},
        {'endpoint':'http://127.0.0.1:8776/session','auth_surface':'session'}]}))
    (tmp_path/'scope.txt').write_text('127.0.0.1\n')

def test_v54_models_lifecycle_without_secrets(tmp_path):
    seed(tmp_path); ep,rp=build_session(tmp_path); d=json.loads(ep.read_text())
    assert d['secret_values_collected'] is False and d['credentials_collected'] is False
    assert d['session_checks'] and d['lifecycle_states']
    assert rp.exists()

def test_v55_requires_approval_and_scope(tmp_path):
    seed(tmp_path); build_session(tmp_path)
    try:
        run_observe(tmp_path,tmp_path/'scope.txt',approved=False)
        assert False
    except PermissionError: pass

def test_v56_decision_layer_is_human_controlled(tmp_path):
    seed(tmp_path); build_session(tmp_path)
    ep,rp=build_transitions(tmp_path); d=json.loads(ep.read_text())
    assert d['human_control_required'] is True
    assert d['exploitation_authorized'] is False
    assert d['decisions']
    assert rp.exists()
