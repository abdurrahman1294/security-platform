import json
from pathlib import Path
from modules.capability_benchmark_v336 import build_v336_fabric, build_benchmark_matrix, v336_test_matrix


def test_benchmark_has_families_and_gaps(tmp_path):
    out = build_v336_fabric(tmp_path)
    assert out["schema_version"] == "3.36.0"
    assert out["families"] >= 15
    assert out["gaps"]
    assert out["assurance"]["read_only"] is True
    assert out["assurance"]["vendor_parity_not_claimed"] is True


def test_inventory_accounting_is_consistent(tmp_path):
    out = build_v336_fabric(tmp_path)
    assert out["platform_inventory"]["perspectives"] >= 1
    assert out["platform_inventory"]["registered_capabilities"] >= 1
    assert sum(out["status_counts"].values()) == out["families"]
    assert sum(out["gap_counts"].values()) == len(out["gaps"])


def test_machine_artifact_written(tmp_path):
    out = build_v336_fabric(tmp_path)
    p = tmp_path / "evidence" / "capability-benchmark-v336.json"
    assert p.exists()
    loaded = json.loads(p.read_text())
    assert loaded["schema_version"] == out["schema_version"]


def test_suite_matrix_is_nontrivial():
    suite = v336_test_matrix()
    assert suite["scenario_count"] >= 40
    assert len(suite["scenarios"]) == suite["scenario_count"]


def test_family_ids_are_unique():
    rows = build_benchmark_matrix()
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids))
