import json
from pathlib import Path
from modules.unified_specialist_adapter_fabric_v337 import build_v337_fabric, v337_test_matrix
from modules.web_api_assurance_v338 import build_v338_fabric, v338_test_matrix
from modules.fuzz_campaign_fabric_v339 import build_v339_fabric, v339_test_matrix
from modules.engagement_datastore_v340 import index_engagement, v340_test_matrix
from modules.identity_assurance_v341 import build_v341_fabric, v341_test_matrix
from modules.engine_self_security_v335 import build_v335_fabric
from modules.validation_assurance_fabric_v333 import validate_claims


def test_unified_adapter_and_emulation(tmp_path):
    out=build_v337_fabric(tmp_path,target='example.test',capabilities=[{'id':'x','surface':'external_web','specialist':'web','action':'enumerate','risk':'R1'}])
    assert out['schema_version']=='3.37.0'
    assert out['enterprise_emulation']['agent_runtime'] is False
    assert (tmp_path/'evidence'/'unified-specialist-adapters-v337.json').exists()
    assert v337_test_matrix()['scenario_count'] >= 20


def test_web_api_catalog_is_bounded(tmp_path):
    out=build_v338_fabric(tmp_path,target='example.test',endpoints=[{'url':'https://example.test/api'}])
    assert out['test_catalog']
    assert out['governance']['no_destructive_tests'] is True
    assert v338_test_matrix()['scenario_count'] >= 20


def test_fuzz_campaign_is_planning_only(tmp_path):
    out=build_v339_fabric(tmp_path,target='lab.test',campaigns=[{'target_class':'binary','engine':'afl++','max_cases':50}])
    c=out['campaigns'][0]
    assert c['max_cases']==50
    assert c['no_arbitrary_command'] is True
    assert v339_test_matrix()['scenario_count'] >= 15


def test_datastore_index(tmp_path):
    out=index_engagement(tmp_path,client='c',target='t',artifacts=[{'path':'x.json','sha256':'abc'}])
    assert out['artifact_count']==1
    assert out['storage']['multi_engagement'] is True
    assert v340_test_matrix()['scenario_count'] >= 15


def test_identity_assurance(tmp_path):
    out=build_v341_fabric(tmp_path,target='ad.test',identities=[{'id':'operator-1','role':'tester'}])
    assert len(out['protocol_matrix']) == 13
    assert out['governance']['no_secret_collection'] is True
    assert v341_test_matrix()['scenario_count'] >= 20


def test_v333_status_reports_actual_level():
    result=validate_claims(claims=[{'id':'c1','title':'candidate','level':'candidate'}],evidence=[])
    assert result['claims'][0]['claim_status']=='candidate'
    assert result['claims'][0]['achieved_level']=='candidate'


def test_self_security_can_exclude_tests(tmp_path):
    repo=tmp_path/'repo'; (repo/'tests').mkdir(parents=True); (repo/'modules').mkdir()
    (repo/'tests'/'x.py').write_text('import subprocess\nsubprocess.run(["echo","x"])\n')
    (repo/'modules'/'x.py').write_text('x=1\n')
    out=build_v335_fabric(tmp_path,repo_root=repo,include_tests=False)
    assert out['files_scanned']==1
