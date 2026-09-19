import json
from pathlib import Path
from modules.investigation_engine_v18 import build as build_inv
from modules.knowledge_base import build as build_kb
from modules.operator_workspace import generate

def seed(root):
    ev=root/'evidence'; ev.mkdir(parents=True); (root/'reports').mkdir()
    (ev/'attack-graph.json').write_text(json.dumps({'nodes':[
        {'type':'finding','id':'F-A','finding_id':'F-A','label':'Auth weakness','severity':'high','status':'unreviewed','confidence':.6,'asset':'app.example'},
        {'type':'finding','id':'F-B','finding_id':'F-B','label':'Info disclosure','severity':'medium','status':'confirmed','confidence':.95,'asset':'app.example'}], 'edges':[{'source':'F-A','target':'F-B','type':'may-enable','status':'hypothesis'}]}))
    (ev/'assets.json').write_text(json.dumps({'assets':[{'asset_id':'A1','host':'app.example','importance':'high'}]}))
    (ev/'technology-inventory.json').write_text(json.dumps({'technologies':[{'name':'ExampleTech'}]}))
    (ev/'correlation.json').write_text(json.dumps({'correlations':[]}))
    (ev/'validation-ledger.json').write_text('[]'); (ev/'retest-ledger.json').write_text('[]')
    (ev/'engagement.json').write_text(json.dumps({'client':'Test','target':'app.example'}))
    (ev/'validation-queue.json').write_text(json.dumps({'queue':[]})); (ev/'analytics.json').write_text('{}')

def test_v18_v20(tmp_path):
    seed(tmp_path); build_inv(tmp_path); build_kb(tmp_path); p=generate(tmp_path,'Test','app.example')
    assert (tmp_path/'evidence'/'investigation-priorities-v18.json').exists()
    assert (tmp_path/'evidence'/'knowledge-base.json').exists()
    assert p.exists() and 'Operator Workspace' in p.read_text()
    data=json.loads((tmp_path/'evidence'/'knowledge-base.json').read_text())
    assert any(x['type']=='finding' for x in data['entities'])
