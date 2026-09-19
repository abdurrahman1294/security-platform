from pathlib import Path
from modules.tool_evidence_normalization_v352 import parse_tool_output, normalize_files, v352_test_matrix
from modules.tool_aware_specialist_planner_v353 import build_plan, v353_test_matrix


def test_v352_parsers(tmp_path):
    xml='<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="lab" version="1"/></port></ports></host></nmaprun>'
    assert parse_tool_output("nmap", xml)[0]["kind"] == "open-service"
    assert parse_tool_output("httpx", '{"url":"http://127.0.0.1:8080","status_code":200}\n')[0]["kind"] == "http-observation"
    assert parse_tool_output("nuclei", '{"template-id":"lab-test","matched-at":"http://127.0.0.1:8080"}\n')[0]["confidence"] == "candidate"
    assert parse_tool_output("naabu", "127.0.0.1:8080\n")[0]["kind"] == "open-port"
    assert parse_tool_output("katana", "http://127.0.0.1:8080/\n")[0]["kind"] == "url-observation"


def test_v352_file_normalization_is_sandboxed(tmp_path):
    p=Path(tmp_path)/"out.txt"; p.write_text("127.0.0.1:8080\n")
    r=normalize_files(tmp_path,[{"tool":"naabu","path":str(p)}])
    assert r["status"] == "PASS" and r["evidence_count"] == 1


def test_v353_plan_is_governed(tmp_path):
    r=build_plan(tmp_path)
    assert r["status"] == "PASS"
    assert r["policy"]["planning_only"] is True
    assert len(r["plan"]) >= 16


def test_matrices():
    assert v352_test_matrix()["scenario_count"] == 20
    assert v353_test_matrix()["scenario_count"] == 18
