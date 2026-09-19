from pathlib import Path
from modules.pretest_readiness_v355 import run_pretest_readiness, v355_test_matrix


def test_v355_pretest_readiness(tmp_path):
    report = run_pretest_readiness(Path(__file__).resolve().parents[1], tmp_path / "readiness")
    assert report["status"] == "PASS"
    assert report["summary"]["hard_failures"] == 0


def test_v355_matrix():
    matrix = v355_test_matrix()
    assert matrix["scenario_count"] == 10


def test_assurance_stack_schema_version_matches_current_release():
    from security_platform.core.platform import SecurityPlatform
    from security_platform.core.engagement import Engagement
    # Avoid invoking the isolated range here; inspect the method contract source.
    import inspect
    src = inspect.getsource(SecurityPlatform.assurance_stack)
    assert 'schema_version":"3.55.0"' in src


def test_tool_inventory_uses_runtime_policy():
    from modules.pretest_readiness_v355 import run_pretest_readiness
    from security_platform.core.tools import inventory
    report = run_pretest_readiness('.', 'artifacts/test-v355-policy')
    detail = next(c['detail'] for c in report['checks'] if c['name'] == 'specialist-tool-inventory')
    runtime_ready = [x.name for x in inventory() if x.status == 'ready']
    assert 'runtime_policy_available=' + str(runtime_ready) in detail
