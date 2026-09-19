import json
from modules.workflow_intelligence_v60 import build as build60
from modules.workflow_sequences_v61 import build as build61
from modules.business_logic_v62 import build as build62

def seed(tmp_path):
    (tmp_path/'evidence').mkdir(parents=True)
    (tmp_path/'evidence'/'web-endpoints-v46.json').write_text(json.dumps({'endpoints':[
        {'endpoint':'https://example.test/register','method_candidates':['GET','POST']},
        {'endpoint':'https://example.test/login','method_candidates':['GET','POST']},
        {'endpoint':'https://example.test/api/order/create','method_candidates':['POST']},
        {'endpoint':'https://example.test/api/payment/checkout','method_candidates':['POST']},
        {'endpoint':'https://example.test/admin/approve','method_candidates':['POST']},
    ]}))

def test_v60_workflow_model(tmp_path):
    seed(tmp_path); p,_=build60(tmp_path); d=json.loads(p.read_text()); assert d['node_count']==5 and d['planning_only'] and d['secrets_collected'] is False

def test_v61_sequences(tmp_path):
    seed(tmp_path); build60(tmp_path); p,_=build61(tmp_path); d=json.loads(p.read_text()); assert d['sequence_count']>=2 and d['replay_executed'] is False

def test_v62_business_logic(tmp_path):
    seed(tmp_path); build60(tmp_path); build61(tmp_path); p,_=build62(tmp_path); d=json.loads(p.read_text()); assert d['decisions'] and d['planning_only'] and d['exploitation_authorized'] is False
