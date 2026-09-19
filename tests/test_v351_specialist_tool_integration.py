from pathlib import Path
from modules.specialist_tool_integration_v351 import run_tool_integration, v351_test_matrix


def test_v351_harness_is_safe_and_accountable(tmp_path):
    report = run_tool_integration(tmp_path, execute=True)
    assert report["status"] == "PASS"
    assert report["target_policy"] == {"loopback_only": True, "external_targets": False, "synthetic_data_only": True}
    assert report["summary"]["probes"] == 4
    assert all(r["target"] == "127.0.0.1" for r in report["results"])
    assert (Path(tmp_path) / "evidence" / "specialist-tool-integration-v351.json").exists()


def test_v351_matrix_complete():
    m = v351_test_matrix()
    assert m["schema_version"] == "3.51.0"
    assert m["scenario_count"] == 25
