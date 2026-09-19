import json
from modules.multi_target_integration_v348 import build_multi_target_range, run_multi_target_campaign, v348_test_matrix

def test_v348_multi_target_campaign(tmp_path):
    meta = build_multi_target_range(tmp_path)
    assert meta["target_count"] == 16
    assert meta["scenario_count"] == 36
    report = run_multi_target_campaign(tmp_path)
    assert report["summary"]["total"] == 36
    assert report["summary"]["true_positives"] == 36
    assert report["summary"]["misses"] == 0
    assert report["summary"]["false_positives"] == 0
    assert report["summary"]["detection_rate"] == 1.0
    assert report["method"] == "discover-before-ground-truth"
    assert len(report["targets"]) == 16
    assert all(r["evidence_source"] == "black_box_target_probe" for r in report["results"])

def test_v348_truth_and_artifacts(tmp_path):
    build_multi_target_range(tmp_path)
    assert (tmp_path / "ground_truth" / "manifest.json").exists()
    report = run_multi_target_campaign(tmp_path)
    assert (tmp_path / "evidence" / "multi-target-integration-v348.json").exists()
    assert (tmp_path / "evidence" / "multi-target-gap-register-v348.json").exists()
    truth = json.loads((tmp_path / "ground_truth" / "manifest.json").read_text())
    assert len(truth["entries"]) == 36

def test_v348_matrix_unique_ids():
    m=v348_test_matrix(); ids=[x["id"] for x in m["scenarios"]]
    assert len(ids) == len(set(ids))
