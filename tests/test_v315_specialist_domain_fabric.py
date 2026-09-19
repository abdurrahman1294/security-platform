from pathlib import Path
from modules.specialist_domain_fabric_v315 import VERSION, build_v315_fabric

def test_v315(tmp_path):
    assert VERSION == "3.15.0"
    out = build_v315_fabric(tmp_path, "lab.example", "specialist")
    assert set(out) == {"capability_matrix","wireless","mobile","remote","rce_validation","fusion"}
    assert "BLE" in out["capability_matrix"]["domains"]["wireless"]["ble_inventory"]
    assert "RDP" in [x["protocol"] for x in out["remote"]["protocols"]]
    assert out["rce_validation"]["candidates"] == []

def test_rce_candidate_is_not_execution(tmp_path):
    from modules.specialist_domain_fabric_v315 import build_rce_validation_catalog
    out = build_rce_validation_catalog(tmp_path, [{"service":"demo","version":"1.0","cve":"CVE-TEST"}])
    assert out["candidates"][0]["verdicts"][-1] == "unverified"
    assert out["candidates"][0]["approval"] == "required for any active validation"
