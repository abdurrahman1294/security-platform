import json
from pathlib import Path
import pytest
from modules.assessment_intelligence import build, set_business_impact
from modules.retest import record


def _graph(tmp_path):
    e=tmp_path/"evidence"; e.mkdir(parents=True)
    (e/"attack-graph.json").write_text(json.dumps({"nodes":[
        {"id":"F-1","finding_id":"F-1","type":"finding","label":"Critical auth weakness","asset":"app.example.com","severity":"critical","status":"unreviewed","confidence":0.4,"metadata":{"evidence_quality":0.45,"prerequisites":["in scope"]}},
        {"id":"F-2","finding_id":"F-2","type":"finding","label":"Confirmed admin issue","asset":"app.example.com","severity":"high","status":"confirmed","confidence":0.95,"metadata":{"evidence_quality":1.0,"prerequisites":[]}},
        {"id":"F-3","finding_id":"F-3","type":"finding","label":"False positive","asset":"app.example.com","severity":"critical","status":"false-positive","confidence":0.1,"metadata":{"evidence_quality":0.45}}
    ],"edges":[{"source":"F-1","target":"F-2","status":"hypothesis"}]}), encoding="utf-8")


def test_assessment_builds_priority_and_queue(tmp_path):
    _graph(tmp_path)
    ep, qp=build(tmp_path)
    data=json.loads(ep.read_text()); queue=json.loads(qp.read_text())
    assert data["recommendations"]
    assert data["recommendations"][0]["finding_id"] in {"F-1", "F-2"}
    assert data["recommendations"][0]["rank_score"] >= data["recommendations"][-1]["rank_score"]
    assert all(x["finding_id"] != "F-3" for x in data["recommendations"])
    assert (tmp_path/"reports"/"assessment-intelligence.md").exists()
    assert queue["queue"]


def test_business_context_is_persisted(tmp_path):
    p=set_business_impact(tmp_path,"F-1","critical","confidential","customer authentication","core login")
    data=json.loads(p.read_text())
    assert data["F-1"]["asset_importance"] == "critical"
    assert data["F-1"]["data_sensitivity"] == "confidential"


def test_retest_requires_approval_and_records(tmp_path):
    with pytest.raises(PermissionError):
        record(tmp_path,"F-1","fixed",approved=False)
    entry,path=record(tmp_path,"F-1","fixed","patched and manually rechecked",["E-1"],approved=True)
    assert entry["execution"] == "manual-record-only"
    assert path.exists()
    data=json.loads(path.read_text())
    assert data[-1]["result"] == "fixed"
    assert "F-1" in (tmp_path/"reports"/"retest-report.md").read_text()
