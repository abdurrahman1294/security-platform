import json
from modules.case_management import build as build_cases, record as record_case
from modules.risk_analytics_v22 import build as build_risk
from modules.workflow_v23 import status as wf_status, advance as wf_advance

def seed(root):
    ev=root/'evidence'; rep=root/'reports'; ev.mkdir(parents=True); rep.mkdir()
    (ev/'engagement.json').write_text(json.dumps({'client':'T','target':'app'}))
    (ev/'assets.json').write_text(json.dumps({'assets':[{'asset_id':'A1','host':'app','importance':'high'}]}))
    (ev/'attack-graph.json').write_text(json.dumps({'nodes':[
      {'type':'asset','id':'A1','asset':'app'},
      {'type':'finding','id':'F-A','finding_id':'F-A','label':'Auth issue','severity':'high','status':'confirmed','confidence':.9,'asset':'app'},
      {'type':'finding','id':'F-B','finding_id':'F-B','label':'API issue','severity':'medium','status':'unreviewed','confidence':.6,'asset':'app'}], 'edges':[{'source':'F-A','target':'F-B','type':'may-enable','status':'hypothesis','confidence':.7}]}))
    (ev/'business-impact.json').write_text(json.dumps({'F-A':{'asset_importance':'high','data_sensitivity':'confidential'}}))
    (ev/'validation-queue.json').write_text(json.dumps({'queue':[]}))
    (ev/'evidence-index.json').write_text(json.dumps({'entries':[]}))
    (ev/'retest-ledger.json').write_text('[]')
    (rep/'report-pack.md').write_text('# report')

def test_v21_case(tmp_path):
    seed(tmp_path); p=build_cases(tmp_path); record_case(tmp_path,'F-A','note','manual review',approved=True)
    data=json.loads(p.read_text()); assert len(data['cases'])==2 and data['cases'][0]
    assert any(c['notes'] for c in data['cases'] if c['finding_id']=='F-A')

def test_v22_risk(tmp_path):
    seed(tmp_path); p=build_risk(tmp_path); d=json.loads(p.read_text()); assert d['findings_analyzed']==2; assert d['remediation_priority']

def test_v23_workflow(tmp_path):
    seed(tmp_path); p=wf_status(tmp_path); d=json.loads(p.read_text()); assert d['stage']=='planning' and d['can_advance']
    wf_advance(tmp_path,approved=True); d=json.loads(p.read_text()); assert d['stage']=='recon'
