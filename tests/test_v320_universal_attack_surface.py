from modules.universal_attack_surface_fabric_v320 import *

def test_version(): assert VERSION == "3.20.0"

def test_surface_breadth():
    assert len(ATTACK_SURFACES) >= 35
    assert {"remote_access","cloud","containers","firmware","ot_ics","automotive","mobile_android","mobile_ios","ai_ml","cellular_telecom"} <= set(ATTACK_SURFACES)

def test_perspectives():
    assert {"lan","internet_ipv4","internet_ipv6","cellular_ipv4","cellular_ipv6","vpn","testbed"} <= set(PERSPECTIVES)

def test_plan_is_not_authorized_by_default(tmp_path):
    out = build_functional_assessment_plan(tmp_path, target="example.test", perspective="cellular_ipv6")
    assert out["authorized"] is False
    assert all(x["status"] == "plan-only" for x in out["steps"])

def test_authorized_plan_reaches_registered_adapters(tmp_path):
    out = build_functional_assessment_plan(tmp_path, target="example.test", authorized=True, requested_surfaces=["external_web","internet_services","cloud"])
    assert all(x["status"] == "ready-for-governed-execution" for x in out["steps"])
    assert any("nmap" in x["adapters"] for x in out["steps"])

def test_full_fabric(tmp_path):
    out = build_v320_fabric(tmp_path, target="example.test", perspective="cellular_ipv4")
    assert out["version"] == "3.20.0"
    assert out["coverage"]["surface_count"] >= 35
