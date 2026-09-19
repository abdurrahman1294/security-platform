import json
from modules.excellence_v111_v145 import build_all

def test_excellence_stack(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    (tmp_path/'evidence'/'execution-state-v101.json').write_text(json.dumps({'tasks':{'a':{'status':'completed'},'b':{'status':'failed'}}}))
    paths=build_all(tmp_path,'example.com',str(tmp_path/'scope.txt'))
    assert len(paths)==8
    for p in paths: assert p.exists()
    d=json.loads((tmp_path/'evidence'/'excellence-platform-v121-v145.json').read_text())
    assert d['maturity_features']['advanced_web_api'] is True
    assert d['decision_policy']

def test_no_fabrication_policy(tmp_path):
    (tmp_path/'evidence').mkdir()
    build_all(tmp_path,'example.com','')
    d=json.loads((tmp_path/'evidence'/'professional-reporting-v118.json').read_text())
    assert d['truthfulness']['no_fabricated_evidence'] is True
