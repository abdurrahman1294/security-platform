import json
from modules.remediation_tracking_v27 import set_record, build as build_rem
from modules.retest_intelligence_v28 import build as build_retest
from modules.closure_engine_v29 import build as build_closure

def seed(root):
    for d in ["evidence","reports"]:(root/d).mkdir(parents=True,exist_ok=True)
    (root/"evidence"/"engagement.json").write_text("{}")
    (root/"evidence"/"assets.json").write_text("{}")
    (root/"evidence"/"evidence-index.json").write_text("{}")
    (root/"evidence"/"normalized-findings.json").write_text(json.dumps({"findings":[]}))
    (root/"evidence"/"attack-graph.json").write_text("{}")
    (root/"reports"/"report-pack.md").write_text("ok")
    (root/"evidence"/"case-ledger.json").write_text("[]")
    (root/"evidence"/"retest-ledger.json").write_text("[]")

def test_v27_v29(tmp_path):
    seed(tmp_path)
    rec,_=set_record(tmp_path,"F-1",status="ready-for-retest",owner="analyst",priority="high",approved=True)
    assert rec["finding_id"]=="F-1"
    (tmp_path/"evidence"/"retest-ledger.json").write_text(json.dumps([{"finding_id":"F-1","result":"fixed","evidence":["E-1"],"timestamp":"now"}]))
    p=build_retest(tmp_path); data=json.loads(p.read_text()); assert data["findings"][0]["assessment"]=="remediated"
    p=build_closure(tmp_path); data=json.loads(p.read_text()); assert data["ready_to_close"] is True
