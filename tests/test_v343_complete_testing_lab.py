from pathlib import Path
from modules.complete_testing_lab_v343 import build_lab_catalog, build_complete_lab, v343_test_matrix

def test_catalog_covers_every_capability():
    from modules.capability_closure_fabric_v342 import build_capability_closure
    assert len(build_lab_catalog()) == len(build_capability_closure())

def test_lab_runs_all(tmp_path):
    out=build_complete_lab(tmp_path,target="127.0.0.1",authorized=True)
    assert out["summary"]["total"] == out["catalog_count"]
    assert out["summary"]["errors"] == 0
    assert out["summary"]["passed"] == out["catalog_count"]
    assert Path(tmp_path,"evidence/complete-lab-report-v343.json").exists()
    assert Path(tmp_path,"evidence/complete-lab-gap-register-v343.json").exists()

def test_suite_matrix():
    assert v343_test_matrix()["scenario_count"] >= 25
