import json
from modules.integration_validation_range_v345 import build_range, run_integration_range, v345_test_matrix
from modules.campaign_quality_resilience_v346 import build_quality_artifact, v346_test_matrix
from modules.campaign_resilience_v347 import build_resilience_matrix, run_resilience_checks


def test_v345_build_and_campaign(tmp_path):
    meta=build_range(tmp_path)
    assert meta['scenario_count'] == 26
    report=run_integration_range(tmp_path)
    assert report['summary']['total'] == 26
    assert report['summary']['misses'] == 0
    assert report['summary']['false_positives'] == 0
    assert report['summary']['detection_rate'] == 1.0
    assert len(report['by_domain']) >= 10


def test_v346_quality_is_explicitly_fixture_scoped(tmp_path):
    report={'summary':{'total':2,'true_positives':1,'misses':1,'false_positives':0}}
    result=build_quality_artifact(tmp_path, report)
    assert 0 <= result['score'] <= 100
    assert 'fixture effectiveness' in result['interpretation']
    assert result['gaps'] == 1


def test_v347_resilience_matrix_is_fail_closed(tmp_path):
    m=build_resilience_matrix()
    assert len(m['failure_modes']) == 8
    assert m['properties']['no_silent_success'] is True
    result=run_resilience_checks(tmp_path)
    assert (tmp_path/'evidence'/'campaign-resilience-v347.json').exists()
    assert result['schema_version'] == '3.47.0'


def test_test_matrices_have_unique_ids():
    for matrix in (v345_test_matrix(), v346_test_matrix(), build_resilience_matrix()):
        if 'scenarios' in matrix:
            ids=[x['id'] for x in matrix['scenarios']]
            assert len(ids) == len(set(ids))
