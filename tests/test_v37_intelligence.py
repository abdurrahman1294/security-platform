from pathlib import Path
import json, pytest
from modules.assessment_intelligence_v37 import (
    canonical_asset, asset_identity, dependency_map, normalize_authenticated,
    rank_attack_paths, coverage_gaps, remediation_priority, engagement_state,
)

def seed(tmp_path):
    ev=tmp_path/'evidence'; ev.mkdir()
    (ev/'sample.json').write_text(json.dumps({"assets":[{"asset":"HTTPS://WWW.Example.COM/"},{"asset":"10.0.0.1"}]}))
    (ev/'auth-role-analysis-v35.json').write_text(json.dumps({"tests":[{"role":"user","action":"read-admin","expected":"deny","observed":"allow","asset":"example.com"}]}))
    (ev/'normalized-findings.json').write_text(json.dumps({"findings":[{"normalized_id":"F1","title":"TLS issue","asset":"example.com","severity":"high"},{"normalized_id":"F2","title":"db exposure","asset":"10.0.0.1","severity":"medium"}]}))

def test_canonical_url(): assert canonical_asset('https://WWW.Example.COM/a')=='example.com'
def test_canonical_ip(): assert canonical_asset('10.0.0.1')=='10.0.0.1'
def test_identity(tmp_path):
    seed(tmp_path); assert asset_identity(tmp_path)['identity_count']==2
def test_auth_normalization(tmp_path):
    seed(tmp_path); assert normalize_authenticated(tmp_path)['mismatch_count']==1
def test_dependency_empty_safe(tmp_path):
    seed(tmp_path); asset_identity(tmp_path); assert dependency_map(tmp_path)['edge_count']==0
def test_rank_empty_safe(tmp_path):
    seed(tmp_path); asset_identity(tmp_path); dependency_map(tmp_path); assert rank_attack_paths(tmp_path)['path_count']==0
def test_coverage_reports_gaps(tmp_path):
    seed(tmp_path); out=coverage_gaps(tmp_path); assert out['gap_count']>0
def test_remediation_priority(tmp_path):
    seed(tmp_path); out=remediation_priority(tmp_path); assert out['items'][0]['priority']=='P1'
def test_state_initial(tmp_path): assert engagement_state(tmp_path)['state']=='initialized'
def test_state_running(tmp_path): assert engagement_state(tmp_path,'running')['state']=='running'
def test_state_rejects_bad(tmp_path):
    with pytest.raises(ValueError): engagement_state(tmp_path,'closed')
def test_state_pause(tmp_path):
    engagement_state(tmp_path,'running'); assert engagement_state(tmp_path,'paused')['state']=='paused'
def test_state_resume(tmp_path):
    engagement_state(tmp_path,'running'); engagement_state(tmp_path,'paused'); assert engagement_state(tmp_path,'running')['state']=='running'
def test_state_complete(tmp_path):
    engagement_state(tmp_path,'running'); assert engagement_state(tmp_path,'completed')['state']=='completed'
def test_state_close(tmp_path):
    engagement_state(tmp_path,'running'); engagement_state(tmp_path,'completed'); assert engagement_state(tmp_path,'closed')['state']=='closed'
def test_identity_confidence(tmp_path):
    seed(tmp_path); out=asset_identity(tmp_path); assert all(0 <= x['confidence'] <= 1 for x in out['identities'])
def test_auth_boolean_normalization(tmp_path):
    seed(tmp_path); out=normalize_authenticated(tmp_path); assert out['tests'][0]['observed'] is True
def test_priority_order(tmp_path):
    seed(tmp_path); out=remediation_priority(tmp_path); assert out['items'][0]['priority_score']>=out['items'][1]['priority_score']
def test_dependency_determinism(tmp_path):
    seed(tmp_path); asset_identity(tmp_path); a=dependency_map(tmp_path); b=dependency_map(tmp_path); assert a==b
def test_coverage_determinism(tmp_path):
    seed(tmp_path); a=coverage_gaps(tmp_path); b=coverage_gaps(tmp_path); assert a==b
def test_rank_schema(tmp_path):
    seed(tmp_path); asset_identity(tmp_path); dependency_map(tmp_path); out=rank_attack_paths(tmp_path); assert out['schema_version']=='3.7'
