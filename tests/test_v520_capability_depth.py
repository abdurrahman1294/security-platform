from pathlib import Path
from modules.capability_depth_v520 import (
    DepthEngineV52, RegisteredAdapterPack, ExpandedFindingsImporter,
    GovernedMCPServer, LLMSupervisor, RetestEngine, build_report_pack, run_lab_benchmark,
)

def test_adapter_requires_auth_and_scope(tmp_path):
    pack = RegisteredAdapterPack(tmp_path)
    r = pack.execute("nmap", "127.0.0.1", authorized=False, scope_file=None, dry_run=True)
    assert r.status == "denied"
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n", encoding="utf-8")
    r2 = pack.execute("nmap", "127.0.0.1", authorized=True, scope_file=scope, dry_run=True)
    assert r2.status == "dry_run"
    r3 = pack.execute("nmap", "evil.example", authorized=True, scope_file=scope, dry_run=True)
    assert r3.status == "denied"

def test_expanded_importers(tmp_path):
    eng = DepthEngineV52(tmp_path)
    xml = tmp_path / "nmap.xml"
    xml.write_text("""<?xml version="1.0"?><nmaprun><host><address addr="1.2.3.4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>""", encoding="utf-8")
    gob = tmp_path / "gobuster.txt"
    gob.write_text("/api (Status: 200)\n", encoding="utf-8")
    mass = tmp_path / "masscan.txt"
    mass.write_text("Discovered open port 443/tcp on 1.2.3.4\n", encoding="utf-8")
    rep = eng.import_findings([xml, gob, mass])
    assert rep["imported"] >= 3

def test_mcp_no_shell(tmp_path):
    mcp = GovernedMCPServer(tmp_path)
    bad = mcp.handle({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell","arguments":{}}}, authorized=True)
    assert "error" in bad
    ok = mcp.handle({"jsonrpc":"2.0","id":2,"method":"tools/list"})
    assert any(t["name"] == "security.plan" for t in ok["result"]["tools"])

def test_supervisor_and_retest_and_report(tmp_path):
    eng = DepthEngineV52(tmp_path)
    prop = eng.propose("127.0.0.1")
    assert prop["executes_tools"] is False
    assert prop["proposals"]
    s1 = eng.snapshot("t1")
    # import something
    xml = tmp_path / "n.xml"
    xml.write_text("""<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>""", encoding="utf-8")
    eng.import_findings([xml])
    s2 = eng.snapshot("t2")
    d = eng.diff(s1["id"], s2["id"])
    assert "new" in d
    rep = eng.report("127.0.0.1")
    assert Path(rep["markdown"]).is_file()
    assert Path(rep["html"]).is_file()

def test_lab_benchmark(tmp_path):
    summary = run_lab_benchmark(tmp_path, "127.0.0.1")
    assert summary["failed"] == 0
    assert summary["passed"] >= 8
