import json
from modules.api_schema_v57 import build as build_schema
from modules.api_surface_v58 import build as build_surface
from modules.api_decisions_v59 import build as build_decisions

def seed(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'web-endpoints-v46.json').write_text(json.dumps({'endpoints':[
        {'endpoint':'https://example.test/api/users?id=7','method_candidates':['GET']},
        {'endpoint':'https://example.test/api/orders/{id}','method_candidates':['GET','POST']},
        {'endpoint':'https://example.test/login','method_candidates':['GET']},
    ]}))

def test_v57_schema_candidates(tmp_path):
    seed(tmp_path); ep,rp=build_schema(tmp_path); d=json.loads(ep.read_text()); assert d['api_endpoint_count']==2 and d['schema_candidates'] and d['secret_values_collected'] is False

def test_v58_api_surface(tmp_path):
    seed(tmp_path); build_schema(tmp_path); ep,rp=build_surface(tmp_path); d=json.loads(ep.read_text()); assert d['endpoint_count']==2; assert any(x['object_reference_candidates'] for x in d['endpoints'])

def test_v59_planning_only(tmp_path):
    seed(tmp_path); build_schema(tmp_path); build_surface(tmp_path); ep,rp=build_decisions(tmp_path); d=json.loads(ep.read_text()); assert d['decisions']; assert d['planning_only'] is True; assert d['exploitation_authorized'] is False
