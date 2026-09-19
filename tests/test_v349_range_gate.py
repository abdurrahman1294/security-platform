from modules.range_assurance_gate_v349 import build_gate, v349_test_matrix

def test_v349_gate_passes(tmp_path):
    r = build_gate(tmp_path, repo_root=tmp_path)
    assert r["status"] == "PASS"
    assert r["range_summary"]["total"] == 36
    assert r["range_summary"]["misses"] == 0
    assert r["range_summary"]["false_positives"] == 0
    assert r["components"]["domain_coverage"] == 1.0
    assert (tmp_path / "evidence" / "range-assurance-gate-v349.json").exists()

def test_v349_matrix_unique_ids():
    m = v349_test_matrix()
    ids = [x["id"] for x in m["scenarios"]]
    assert m["scenario_count"] == len(ids)
    assert len(ids) == len(set(ids))
