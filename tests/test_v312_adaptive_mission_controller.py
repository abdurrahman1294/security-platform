import json
from pathlib import Path
from modules.adaptive_mission_controller_v312 import build_adaptive_mission, build_capability_fusion_matrix

def test_adaptive_plan_replans(tmp_path):
    (tmp_path/'evidence').mkdir()
    (tmp_path/'evidence'/'web.json').write_text(json.dumps({'web':'api endpoint auth finding'}))
    out=build_adaptive_mission(tmp_path,'example.test','web api',max_steps=5)
    assert out['steps']
    assert all(s['authorization_recheck'] and s['scope_recheck'] for s in out['steps'])

def test_fusion(tmp_path):
    out=build_capability_fusion_matrix(tmp_path)
    assert len(out['fusion_patterns']) >= 5
