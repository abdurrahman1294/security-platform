import json
from pathlib import Path
from modules.ecosystem_adapters_v39 import import_bloodhound, import_mobsf, import_findings, build_ecosystem_matrix


def test_bloodhound_import_is_offline(tmp_path):
    src = tmp_path / "bh.json"
    src.write_text(json.dumps({"data": [
        {"source": "USER@LAB", "target": "GROUP@LAB", "label": "GenericAll"},
        {"Properties": {"name": "USER@LAB", "domain": "LAB"}},
    ]}))
    out = import_bloodhound(tmp_path, src)
    assert out["status"] == "completed"
    assert out["interesting_edges"]
    assert (tmp_path / "evidence" / "bloodhound-import-v39.json").exists()
    assert any("No AD/Azure queries".lower() in x.lower() for x in out["limitations"])


def test_mobsf_import(tmp_path):
    src = tmp_path / "mobsf.json"
    src.write_text(json.dumps({"findings": [{"title": "Debuggable application", "severity": "high"}]}))
    out = import_mobsf(tmp_path, src)
    assert out["status"] == "completed"
    assert out["findings"]
    assert out["findings"][0]["source"] == "MobSF"


def test_external_findings_jsonl(tmp_path):
    src = tmp_path / "nuclei.jsonl"
    src.write_text(json.dumps({"template-id": "demo", "info": {"name": "Demo", "severity": "medium"}, "host": "127.0.0.1"}) + "\n")
    out = import_findings(tmp_path, src, source_name="Nuclei")
    assert out["count"] == 1
    assert out["findings"][0]["validation_state"] == "candidate"


def test_ecosystem_matrix_has_high_risk_boundaries(tmp_path):
    out = build_ecosystem_matrix(tmp_path, installed_tools=["nmap", "MobSF"])
    assert out["status"] == "completed"
    assert any(x["ecosystem"] == "bloodhound" for x in out["ecosystems"])
    assert "autonomous C2 operation" in out["high_risk_exclusions"]
