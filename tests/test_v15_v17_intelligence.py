import json
from pathlib import Path
from modules.technology_intelligence import build as build_tech
from modules.correlation_engine import build as build_corr
from modules.engagement_governance import audit, readiness
from modules.engagement import init_engagement


def fixture(root: Path):
    for d in ["recon","vulns","api","evidence","reports"]: (root/d).mkdir(parents=True, exist_ok=True)
    (root/"recon"/"subdomains.txt").write_text("app.example.com\napi.example.com\n")
    (root/"recon"/"live-hosts.txt").write_text("https://app.example.com [200] [nginx/1.25]\nhttps://api.example.com [200] [express]\n")
    a={"template-id":"a","host":"https://app.example.com","info":{"name":"Remote Code Execution","severity":"high","tags":["rce","nginx"]}}
    b={"template-id":"b","host":"https://app.example.com","info":{"name":"Information Disclosure","severity":"medium","tags":["disclosure"]}}
    c={"template-id":"c","host":"https://api.example.com","info":{"name":"API Secret Exposure","severity":"high","tags":["api","secret"]}}
    (root/"vulns"/"findings.json").write_text("\n".join(json.dumps(x) for x in [a,b])+"\n")
    (root/"api"/"api-findings.json").write_text(json.dumps(c)+"\n")


def test_v15_technology_inventory_is_artifact_derived(tmp_path):
    fixture(tmp_path)
    p=build_tech(tmp_path)
    data=json.loads(p.read_text())
    assert data["asset_count"] == 2
    app=next(x for x in data["assets"] if x["asset"]=="app.example.com")
    assert "nginx" in app["technologies"]


def test_v16_correlation_finds_cross_surface_relationships(tmp_path):
    fixture(tmp_path)
    p=build_corr(tmp_path)
    data=json.loads(p.read_text())
    assert data["finding_count"] == 3
    assert data["cross_surface_relationships"]
    assert any(x["relation"]=="same-parent-domain" for x in data["cross_surface_relationships"])
    assert all(x["status"]=="hypothesis" for x in data["cross_surface_relationships"])


def test_v17_governance_chain_and_readiness(tmp_path):
    fixture(tmp_path)
    init_engagement(tmp_path,"Acme","example.com","scope.txt")
    build_tech(tmp_path); build_corr(tmp_path)
    audit(tmp_path,"test_event",{"ok":True})
    audit(tmp_path,"second_event",{"ok":True})
    p=readiness(tmp_path)
    data=json.loads(p.read_text())
    assert (tmp_path/"evidence"/"audit-log.json").exists()
    assert data["checks"]
    rows=json.loads((tmp_path/"evidence"/"audit-log.json").read_text())
    assert rows[-1]["previous_hash"] == rows[-2]["hash"]
