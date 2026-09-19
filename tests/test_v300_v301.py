from pathlib import Path

from modules.capability_matrix_v300 import build as build_capabilities
from modules.pentest_depth_v301 import build as build_depth


def test_capability_matrix_and_depth(tmp_path):
    data = build_capabilities(tmp_path, target="example.test", tool_inventory=[])
    assert data["schema_version"] == "300.0"
    assert "web" in data["capabilities"]
    assert (tmp_path / "evidence" / "capability-matrix-v300.json").is_file()

    depth = build_depth(tmp_path, executed={"discovery": True})
    assert depth["schema_version"] == "301.0"
    assert depth["domains"]["web"]
    assert (tmp_path / "evidence" / "pentest-depth-v301.json").is_file()
