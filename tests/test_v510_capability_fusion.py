from pathlib import Path
from modules.capability_fusion_v510 import (
    FusionEngineV51, PentestingTaskTree, FindingsImporter,
    plan_two_phase_port_scan, findings_to_sarif, offline_role_matrix,
)

def test_ptt_and_episode(tmp_path):
    eng = FusionEngineV51(tmp_path)
    ep = eng.episode("127.0.0.1", "lab recon", installed_tools=["nmap", "httpx"])
    assert ep["reasoning"]["role"] == "reasoning"
    assert ep["generation"]["steps"]
    snap = eng.cycle.tree.snapshot()
    assert snap["node_count"] >= 5

def test_findings_import_nmap(tmp_path):
    xml = tmp_path / "scan.xml"
    xml.write_text("""<?xml version="1.0"?>
    <nmaprun>
      <host><address addr="127.0.0.1"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/>
          <service name="http" product="nginx"/>
        </port></ports>
      </host>
    </nmaprun>""")
    eng = FusionEngineV51(tmp_path / "out")
    rep = eng.import_findings([xml])
    assert rep["imported"] >= 1
    sar = eng.sarif_from_imports()
    assert sar["result_count"] >= 1

def test_process_ledger(tmp_path):
    eng = FusionEngineV51(tmp_path)
    rid = eng.ledger.start("nmap", "127.0.0.1", timeout_s=60, pid=0)
    eng.ledger.finish(rid, status="completed", exit_code=0)
    runs = eng.ledger.list_runs()
    assert runs and runs[0]["status"] == "completed"

def test_port_pipeline_and_offline_roles():
    plan = plan_two_phase_port_scan("127.0.0.1", ["naabu", "nmap"])
    assert len(plan["pipeline"]) == 2
    roles = offline_role_matrix()
    assert "reasoner" in roles["roles"]
    assert "malware_generation" in roles["forbidden"]

def test_no_shell_in_generation(tmp_path):
    eng = FusionEngineV51(tmp_path)
    ep = eng.episode("127.0.0.1", "test")
    for step in ep["generation"]["steps"]:
        assert step["requires_registered_adapter"] is True
        assert not step["command_template"].startswith("nmap ")
