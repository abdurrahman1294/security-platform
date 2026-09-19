import json
from pathlib import Path
from modules.capability_registry_v92 import build as c92
from modules.self_verification_v93 import build as c93
from modules.security_knowledge_graph_v94 import build as c94
from modules.hypothesis_engine_v95 import build as c95
from modules.experiment_planner_v96 import build as c96
from modules.capability_reliability_v97 import build as c97
from modules.plugin_architecture_v98 import build as c98
from modules.operator_dashboard_v99 import build as c99
from modules.integrated_toolchain_v100 import IntegratedToolchain
import modules.integrated_toolchain_v100 as v100

class Proc:
    def __init__(self, out): self.stdout=out; self.stderr=''; self.returncode=0

def test_v92_v99_artifacts(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir(); (tmp_path/'recon').mkdir()
    (tmp_path/'recon'/'subdomains.txt').write_text('a.example.com\n')
    (tmp_path/'evidence'/'web-endpoints-v46.json').write_text('{}')
    (tmp_path/'evidence'/'api-surface-intelligence-v58.json').write_text('{}')
    (tmp_path/'evidence'/'workflow-intelligence-v60.json').write_text('{}')
    for fn in [c92,c93,lambda r:c94(r,'example.com'),c95,c96,c97,c98,lambda r:c99(r,'example.com')]:
        p=fn(tmp_path); assert p.exists()

def test_v100_integrated_chain(tmp_path, monkeypatch):
    scope=tmp_path/'scope.txt'; scope.write_text('*.example.com\nexample.com\n')
    monkeypatch.setattr(v100.shutil,'which',lambda _: '/usr/bin/fake')
    def fake_run(self, tool_id, argv, **kw):
        if tool_id=='subfinder': return Proc('a.example.com\nb.example.com\n')
        if tool_id=='httpx': return Proc('{"url":"https://a.example.com"}\n')
        return Proc('ok\n')
    monkeypatch.setattr(v100.ToolManager,'run',fake_run)
    chain=IntegratedToolchain(tmp_path,'example.com',str(scope)); ep,data=chain.run()
    assert ep.exists(); assert len(data['results'])>=4
    assert (tmp_path/'recon'/'subdomains.txt').exists()
    assert json.loads(ep.read_text())['scope_enforced'] is True
