import json
from modules.auth_intelligence_v51 import build as build_auth
from modules.authorization_matrix_v52 import build as build_matrix
from modules.authz_decisions_v53 import build as build_decisions

def seed(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'web-endpoints-v46.json').write_text(json.dumps({
        'endpoints':[
            {'endpoint':'https://app.example.test/login','auth_likelihood':'high'},
            {'endpoint':'https://app.example.test/api/orders?id=7','auth_likelihood':'likely'}],
        'authentication_map':['https://app.example.test/login']
    }))

def test_v51_maps_auth_without_secrets(tmp_path):
    seed(tmp_path); ep,rp=build_auth(tmp_path); d=json.loads(ep.read_text())
    assert d['auth_surface_count'] >= 2
    assert d['secret_values_collected'] is False
    assert any(x['auth_surface']=='login' for x in d['surfaces'])
    assert rp.exists()

def test_v52_is_operator_controlled(tmp_path):
    seed(tmp_path); build_auth(tmp_path); ep,rp=build_matrix(tmp_path); d=json.loads(ep.read_text())
    assert d['test_count'] >= 5
    assert all(x['operator_approval_required'] and not x['destructive'] for x in d['tests'])
    assert rp.exists()

def test_v53_decisions_do_not_authorize_exploitation(tmp_path):
    seed(tmp_path); build_auth(tmp_path); build_matrix(tmp_path); ep,rp=build_decisions(tmp_path); d=json.loads(ep.read_text())
    assert d['human_control_required'] is True
    assert d['secret_values_collected'] is False
    assert d['decisions']
    assert any(x['next_action']=='confirm-role-pair-and-manually-validate' for x in d['decisions'])
    assert rp.exists()
