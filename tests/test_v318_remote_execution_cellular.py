from modules.remote_endpoint_and_advanced_fabric_v318 import (
    build_remote_file_access_plan, build_cellular_perspective_plan,
    build_execution_adapter_catalog, build_v318_fabric, VERSION,
)

def test_version():
    assert VERSION == "3.18.0"

def test_file_access_requires_explicit_scope(tmp_path):
    out = build_remote_file_access_plan(tmp_path, "10.0.0.5", "linux")
    assert out["status"] == "blocked"
    out = build_remote_file_access_plan(tmp_path, "10.0.0.5", "linux", ["/home/test/report.txt"])
    assert out["status"] == "planned"
    assert "file_readable" in out["verdicts"]

def test_cellular_plan(tmp_path):
    out = build_cellular_perspective_plan(tmp_path, "203.0.113.10")
    assert "IPv6 internet" in out["perspective"]["perspectives"]
    assert "carrier NAT/CGNAT" in out["perspective"]["perspectives"]

def test_adapters(tmp_path):
    out = build_execution_adapter_catalog(tmp_path)
    assert "windows_remote" in out["adapters"]
    assert "protocol_fuzzing" in out["adapters"]

def test_full_fabric(tmp_path):
    out = build_v318_fabric(tmp_path, "lab-host", approved_paths=["/tmp/approved.txt"])
    assert set(out) >= {"execution_adapters", "remote_file_access", "cellular_perspective", "advanced_analysis"}
