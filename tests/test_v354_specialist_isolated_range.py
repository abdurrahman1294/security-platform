from modules.specialist_isolated_range_v354 import run_specialist_range, v354_test_matrix

def test_v354_full_range(tmp_path):
    r=run_specialist_range(tmp_path)
    assert r['status']=='PASS'
    assert r['summary']['targets']==16
    assert r['summary']['misses']==0
    assert r['summary']['false_positives']==0
    assert r['summary']['detection_rate']==1.0

def test_v354_matrix():
    m=v354_test_matrix(); assert m['scenario_count']==32
