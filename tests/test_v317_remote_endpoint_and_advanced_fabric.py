from pathlib import Path
from modules.remote_endpoint_and_advanced_fabric_v317 import (
    VERSION, build_remote_computer_plan, build_remote_mobile_plan,
    build_advanced_analysis_fabric, build_v317_fabric,
)

def test_version_and_remote_computer(tmp_path):
    assert VERSION == "3.17.0"
    out = build_remote_computer_plan(tmp_path, "host-1", "linux")
    assert "SSH" in out["platforms"]["linux"]["channels"]
    assert (Path(tmp_path) / "evidence" / "remote-computer-assessment-v317.json").exists()

def test_remote_mobile_limitations(tmp_path):
    out = build_remote_mobile_plan(tmp_path, "phone-1", "ios")
    assert any("iOS" in x for x in out["limitations"])

def test_advanced_analysis(tmp_path):
    out = build_advanced_analysis_fabric(tmp_path, "fw-1", "firmware.bin")
    assert "firmware_emulation" in out["capabilities"]
    assert "binary_reverse_engineering" in out["capabilities"]
    assert "protocol_fuzzing" in out["capabilities"]
    assert "digital_twins_testbeds" in out["capabilities"]
    assert "physical_interface_correlation" in out["capabilities"]

def test_full_fabric(tmp_path):
    out = build_v317_fabric(tmp_path, "target-1")
    assert set(out) == {"remote_capability_matrix", "remote_computer", "remote_mobile", "advanced_analysis"}
