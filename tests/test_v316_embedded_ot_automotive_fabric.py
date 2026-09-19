from pathlib import Path
from modules.embedded_ot_automotive_fabric_v316 import (
    VERSION, capability_matrix, build_firmware_pipeline, build_ot_ics_plan,
    build_automotive_plan, build_hardware_plan, build_iot_network_plan,
    build_network_device_plan, build_embedded_fusion, build_v316_fabric,
)


def test_v316_version_and_domains(tmp_path):
    out = capability_matrix(tmp_path)
    assert VERSION == "3.16.0"
    assert set(out["domains"]) == {"firmware", "hardware_platform", "iot_network", "ot_ics", "automotive", "network_devices"}
    assert out["safety_classes"]["S4"]


def test_firmware_pipeline_is_lab_bounded(tmp_path):
    out = build_firmware_pipeline(tmp_path, "router-lab", "fw.bin")
    assert out["artifact"] == "fw.bin"
    assert any(x["safety_class"] == "S3" for x in out["stages"])
    assert "production" in out["lab_rule"]


def test_ot_safety_stops_and_attack_mapping(tmp_path):
    out = build_ot_ics_plan(tmp_path, "ics-lab")
    assert "Modbus/TCP" in out["protocols"]
    assert "process instability" in out["hard_stop_conditions"]
    assert "ATT&CK for ICS" in out["mapping"]


def test_automotive_defaults_to_lab(tmp_path):
    out = build_automotive_plan(tmp_path, "vehicle-bench")
    assert out["default_target"] == "simulator or isolated vehicle-security bench"
    assert "live-vehicle" in out["physical_vehicle_rule"]
    assert any(x["safety_class"] == "S3" for x in out["stages"])


def test_hardware_interfaces_are_not_implicitly_write_enabled(tmp_path):
    out = build_hardware_plan(tmp_path, "hw-lab")
    jtag = next(x for x in out["interfaces"] if x["interface"] == "JTAG")
    assert jtag["write_or_debug"] == "approval_required"


def test_iot_and_network_device_plans(tmp_path):
    iot = build_iot_network_plan(tmp_path, "iot-lab")
    nd = build_network_device_plan(tmp_path, "netdev-lab")
    assert "MQTT" in iot["protocols"]
    assert "SNMP" in nd["protocols"]
    assert "silently" in nd["rule"]


def test_fusion_and_full_fabric(tmp_path):
    fusion = build_embedded_fusion(tmp_path, "target", "coverage")
    assert any(e["from"] == "automotive" and e["to"] == "firmware" for e in fusion["edges"])
    fabric = build_v316_fabric(tmp_path, "target", "coverage")
    assert set(fabric) == {"capability_matrix", "firmware", "hardware_platform", "iot_network", "ot_ics", "automotive", "network_devices", "fusion"}
    assert (Path(tmp_path) / "evidence" / "embedded-domain-fusion-v316.json").exists()
