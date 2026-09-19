import json
from modules.web_surface_v45 import build as build_surface
from modules.web_endpoint_v46 import build as build_endpoints
from modules.web_assessment_v47 import build as build_plan


def test_v45_builds_structured_surface(tmp_path):
    (tmp_path/'recon').mkdir(); (tmp_path/'evidence'/'pipeline-results').mkdir(parents=True)
    (tmp_path/'recon'/'subdomains.txt').write_text('app.example.test\n')
    (tmp_path/'evidence'/'pipeline-results'/'x.json').write_text(json.dumps({'action':'web-crawl','stdout':'https://app.example.test/api/users?id=7&role=user\nhttps://app.example.test/login'}))
    ep,rp=build_surface(tmp_path,'example.test')
    d=json.loads(ep.read_text())
    assert d['applications'] and any('id'==p['name'] for p in d['parameters'])
    assert rp.exists()


def test_v46_maps_endpoints_and_candidates(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'web-surface-v45.json').write_text(json.dumps({'applications':[{'url':'https://app.example.test','host':'app.example.test','api':True,'endpoints':['https://app.example.test/api/orders?id=9','https://app.example.test/login']}]}))
    ep,rp=build_endpoints(tmp_path); d=json.loads(ep.read_text())
    assert d['endpoint_count']==2
    assert 'id' in d['parameter_priorities']
    assert rp.exists()


def test_v47_plan_is_human_controlled(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'web-endpoints-v46.json').write_text(json.dumps({'endpoints':[{'endpoint':'https://app.example.test/api/orders?id=9','type':'api','parameters':['id'],'risk_signals':['object-or-sensitive-parameter'],'auth_likelihood':'unknown'}], 'authentication_map':[], 'business_logic_candidates':[]}))
    ep,rp=build_plan(tmp_path); d=json.loads(ep.read_text())
    assert d['human_control_required'] is True
    assert d['task_count'] >= 2
    assert all(x['operator_approval_required'] for x in d['tasks'])
    assert rp.exists()
