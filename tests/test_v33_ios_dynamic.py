import json
from modules.mobile_ios_dynamic_v33 import assess_export
from modules.expert_capability_audit_v27 import build


def test_ios_dynamic_export(tmp_path):
    src = tmp_path / "runtime.json"
    src.write_text(json.dumps({
        "bundle_id": "com.example.demo",
        "apps": {"com.example.demo": {"path": "/Applications/Demo.app"}},
        "processes": ["501 Demo"],
        "logs": ["Demo: fatal exception observed"]
    }))
    out = assess_export(tmp_path, src)
    assert out["status"] == "completed"
    assert out["mode"] == "offline-export"
    assert any(f["id"] == "IOS-DYN-RUNTIME-ERROR" for f in out["findings"])


def test_ios_dynamic_missing_target(tmp_path):
    src = tmp_path / "runtime.json"
    src.write_text(json.dumps({"bundle_id":"com.example.missing", "apps":{}, "processes":[], "logs":[]}))
    out = assess_export(tmp_path, src)
    assert any(f["id"] == "IOS-DYN-NOT-INSTALLED" for f in out["findings"])


def test_ios_dynamic_no_gap(tmp_path):
    out = build(tmp_path, tool_inventory=[])
    row = {x["id"]: x for x in out["capabilities"]}["mobile.ios.dynamic"]
    assert row["status"] == "implemented-not-executed"
