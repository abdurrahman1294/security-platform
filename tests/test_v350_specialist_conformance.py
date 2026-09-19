from modules.specialist_conformance_v350 import build_conformance, v350_test_matrix

def test_v350_conformance_passes(tmp_path):
    r=build_conformance(tmp_path, repo_root=tmp_path)
    assert r["status"] == "PASS"
    assert r["domain_count"] == 16
    assert r["conformant_domains"] == 16
    assert r["gaps"] == []
    assert (tmp_path/"evidence"/"specialist-conformance-v350.json").exists()

def test_v350_matrix_unique_ids():
    m=v350_test_matrix(); ids=[x["id"] for x in m["scenarios"]]
    assert len(ids)==len(set(ids))
