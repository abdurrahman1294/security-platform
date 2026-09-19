import json
from pathlib import Path
from modules.security_brain_v77 import build as brain
from modules.evidence_memory_v78 import build as memory
from modules.task_router_v79 import build as router
from modules.operator_loop_v80 import build as loop
from modules.unified_assessment_v81 import build as unified
from modules.final_intelligence_v82 import build as final

def test_brain_memory_router(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    brain(tmp_path,'auto','example.com'); memory(tmp_path); router(tmp_path,'auto')
    assert (tmp_path/'evidence/security-brain-v77.json').exists()
    assert (tmp_path/'evidence/evidence-memory-v78.json').exists()
    assert json.loads((tmp_path/'evidence/task-router-v79.json').read_text())['queue']

def test_operator_unified_final(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'reports').mkdir()
    loop(tmp_path,'osint','example.com','research')
    unified(tmp_path,'osint','example.com','lab','research')
    final(tmp_path)
    assert (tmp_path/'evidence/operator-loop-v80.json').exists()
    assert (tmp_path/'evidence/unified-assessment-v81.json').exists()
    assert (tmp_path/'evidence/final-intelligence-v82.json').exists()
