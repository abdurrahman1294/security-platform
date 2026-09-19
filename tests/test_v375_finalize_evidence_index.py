from pathlib import Path
from security_platform.core.engagement import Engagement
from security_platform.core.policy import ScopePolicy
from security_platform.engines import PentestEngine
import json


def test_finalize_writes_evidence_inventory_and_exposes_readiness(tmp_path):
    scope=tmp_path/'scope.txt'; scope.write_text('127.0.0.1\n')
    e=Engagement('lab','127.0.0.1',tmp_path/'out',scope)
    p=ScopePolicy.from_file(scope,e.target_host)
    engine=PentestEngine(e,p)
    result=engine.finalize()
    index=tmp_path/'out'/'evidence'/'evidence-index.json'
    assert index.is_file()
    data=json.loads(index.read_text())
    assert data['inventory_only'] is True
    assert data['artifact_count'] >= 1
    assert 'report_generated' in result
    assert 'report_ready' in result
