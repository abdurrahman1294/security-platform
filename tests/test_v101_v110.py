import json
from modules.execution_orchestrator_v101 import ExecutionOrchestrator, build_plan
from modules.normalization_v102 import build as n102
from modules.qa_verification_v103 import build as q103
from modules.smart_tool_selection_v104 import build as s104
from modules.role_testing_v105 import build as r105
from modules.api_intelligence_v106 import build as a106
from modules.correlation_v107 import build as c107
from modules.change_detection_v108 import build as c108
from modules.evidence_vault_v109 import build as e109
from modules.quality_gate_v110 import build as q110
import modules.execution_orchestrator_v101 as v101

def test_v101_v110_artifacts(tmp_path):
    for d in ['evidence','recon','web','ports','vulns']:(tmp_path/d).mkdir()
    build_plan(tmp_path,'example.com')
    (tmp_path/'evidence'/'pipeline-results').mkdir()
    (tmp_path/'evidence'/'pipeline-results'/'x.json').write_text(json.dumps({'task_id':'x','tool':'httpx','status':'completed','stdout':'{"url":"https://a.example.com","tech":["nginx"]}\n','stderr':'','stdout_sha256':'a'}))
    for fn in [n102,q103,lambda r:s104(r,'example.com'),r105,a106,c107,c108,e109]: assert fn(tmp_path).exists()
    p,d=q110(tmp_path,'example.com',str(tmp_path/'scope.txt')); assert p.exists() and d['decision']=='NOT_READY'


class _Proc:
    def __init__(self, out=''):
        self.stdout=out; self.stderr=''; self.returncode=0

def test_v101_real_chain_is_resumable_and_scope_filtered(tmp_path, monkeypatch):
    for d in ['evidence','recon','web','ports','vulns']:(tmp_path/d).mkdir()
    scope=tmp_path/'scope.txt'; scope.write_text('*.example.com\nexample.com\n')
    monkeypatch.setattr(v101.shutil,'which',lambda _: '/usr/bin/fake')
    def fake_run(self, tool_id, argv, **kw):
        if tool_id in ('subfinder','assetfinder'): return _Proc('a.example.com\nb.example.com\noutside.test\n')
        if tool_id=='httpx': return _Proc('{"url":"https://a.example.com","tech":["nginx"]}\n')
        return _Proc('ok\n')
    monkeypatch.setattr(v101.ToolManager,'run',fake_run)
    runner=v101.ExecutionOrchestrator(tmp_path,'example.com',str(scope),max_workers=2,resume=True)
    state_path,state=runner.run()
    assert state_path.exists()
    assert 'outside.test' not in (tmp_path/'recon'/'subdomains.txt').read_text()
    assert state['tasks']['merge-assets']['count']==3
    state2=v101.ExecutionOrchestrator(tmp_path,'example.com',str(scope),max_workers=2,resume=True).run()[1]
    assert state2['tasks']['http-probe']['status']=='completed'
