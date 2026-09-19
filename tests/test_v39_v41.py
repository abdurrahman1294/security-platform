import json
from pathlib import Path

from modules.assessment_engine_v39 import build_plan, next_ready, mark
from modules.tool_manager_v40 import ToolManager, list_tools
from modules.adaptive_engine_v41 import decide


def test_v39_builds_dependency_plan(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    p=build_plan(tmp_path, full=True)
    data=json.loads(p.read_text())
    actions={x['action'] for x in data['tasks']}
    assert 'external-recon' in actions and 'report-pack' in actions
    assert next_ready(tmp_path)[0]['action']=='verify-authorization'
    mark(tmp_path,'verify-authorization','completed','authorization verified')
    assert next_ready(tmp_path)[0]['action']=='external-recon'


def test_v40_tool_manager_allowlist(tmp_path):
    (tmp_path/'evidence').mkdir()
    mgr=ToolManager(tmp_path)
    assert any(x['tool_id']=='nmap' for x in list_tools())
    try: mgr.run('nmap',['sh','-c','echo bad'])
    except ValueError: pass
    else: assert False


def test_v41_decision_artifacts(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    build_plan(tmp_path, full=True)
    ep,rp=decide(tmp_path)
    data=json.loads(ep.read_text())
    assert data['human_control_required'] is True
    assert data['next_actions'][0]['action']=='external-recon'
    assert rp.exists()
