from pathlib import Path
from modules.unified_security_core_v530 import UnifiedCoreV53, build_capability_audit

def test_audit(tmp_path):
    r = build_capability_audit(tmp_path)
    assert r["summary"]["refuse"] >= 1
    assert Path(r["markdown"]).is_file()
    assert any(x["capability"] == "browser_automation" for x in r["rows"])

def test_mission_requires_auth(tmp_path):
    u = UnifiedCoreV53(tmp_path)
    d = u.mission("http://127.0.0.1", authorized=False)
    assert d["status"] == "denied"
    ok = u.mission("http://example.invalid", authorized=True)
    # may error on network but should not be denied
    assert ok.get("status") in ("completed", "error") or "steps" in ok

def test_malware_static(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ\x90\x00" + b"powershell http://example.com " + b"A" * 100)
    u = UnifiedCoreV53(tmp_path / "out")
    r = u.malware_static(str(sample))
    assert r["status"] == "completed"
    assert r["file_type_guess"] == "pe"

def test_phishing_and_adversary(tmp_path):
    u = UnifiedCoreV53(tmp_path)
    p = u.phishing_sim("Acme Corp")
    assert "forbidden" in p
    a = u.adversary("127.0.0.1")
    assert a["results"]

def test_attack_graph_and_command_center(tmp_path):
    u = UnifiedCoreV53(tmp_path)
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "imported-findings-v520.json").write_text(
        '{"findings":[{"source":"nuclei","severity":"high","name":"x"}]}', encoding="utf-8")
    g = u.attack_graph("t")
    assert g["node_count"] >= 2
    cc = u.command_center()
    assert len(cc["missions"]) >= 5
