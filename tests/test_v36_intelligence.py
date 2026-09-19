import json
from modules.intelligence_fabric_v36 import build as fabric
from modules.adaptive_next_steps_v36 import build as steps
from modules.continuous_diff_v36 import snapshot, diff

def test_fabric_only_correlates_shared_asset(tmp_path):
    ev=tmp_path/'evidence'; ev.mkdir()
    (ev/'cloud-azure-assessment-v32.json').write_text(json.dumps({'findings':[{'id':'A','asset':'host1'}]}))
    (ev/'database-surface-v33.json').write_text(json.dumps({'services':[{'id':'D','asset':'host1','port':5432}]}))
    (ev/'network-device-config-v33.json').write_text(json.dumps({'findings':[{'id':'N','asset':'other'}]}))
    out=fabric(tmp_path)
    assert out['cross_domain_relationships']
    assert all(x['asset']=='host1' for x in out['cross_domain_relationships'])

def test_adaptive_steps(tmp_path):
    ev=tmp_path/'evidence'; ev.mkdir()
    (ev/'intelligence-fabric-v36.json').write_text(json.dumps({'observation_count':1,'cross_domain_relationships':[{'asset':'a'}]}))
    (ev/'service-protocol-intelligence-v35.json').write_text(json.dumps({'service_count':1,'services':[{'asset':'a','port':23,'flags':['review']}]}))
    (ev/'auth-role-analysis-v35.json').write_text(json.dumps({'finding_count':1}))
    out=steps(tmp_path); assert out['suggestion_count']>=3

def test_continuous_diff(tmp_path):
    ev=tmp_path/'evidence'; ev.mkdir()
    (ev/'intelligence-fabric-v36.json').write_text(json.dumps({'nodes':[{'id':'a','kind':'asset'},{'id':'b','kind':'finding'}]}))
    baseline=snapshot(tmp_path)
    (ev/'intelligence-fabric-v36.json').write_text(json.dumps({'nodes':[{'id':'a','kind':'asset'},{'id':'c','kind':'finding'}]}))
    current=snapshot(tmp_path)
    out=diff(tmp_path, baseline, current)
    assert out['introduced'] and out['removed']
