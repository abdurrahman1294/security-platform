import json
from modules.adaptive_assessment_v28 import build


def seed(tmp_path, text=''):
    (tmp_path/'evidence').mkdir(exist_ok=True)
    (tmp_path/'evidence'/'observations.txt').write_text(text, encoding='utf-8')


def test_01_module_schema(tmp_path):
    seed(tmp_path); d=build(tmp_path); assert d['schema_version']=='2.8'
def test_02_auth_classified(tmp_path):
    seed(tmp_path,'login session cookie OAuth'); d=build(tmp_path); assert any(x['kind']=='auth-state' for x in d['classifications'])
def test_03_api_classified(tmp_path):
    seed(tmp_path,'/api/v1/users swagger OpenAPI'); d=build(tmp_path); assert any(x['kind']=='api-surface' for x in d['classifications'])
def test_04_workflow_classified(tmp_path):
    seed(tmp_path,'checkout approval state transition'); d=build(tmp_path); assert any(x['kind']=='workflow-state' for x in d['classifications'])
def test_05_cloud_classified(tmp_path):
    seed(tmp_path,'AWS IAM S3 security group VPC'); d=build(tmp_path); assert any(x['kind']=='cloud-trust' for x in d['classifications'])
def test_06_mobile_classified(tmp_path):
    seed(tmp_path,'Android APK Manifest WebView'); d=build(tmp_path); assert any(x['kind']=='mobile' for x in d['classifications'])
def test_07_wireless_classified(tmp_path):
    seed(tmp_path,'Wi-Fi SSID BSSID PCAP 802.11'); d=build(tmp_path); assert any(x['kind']=='wireless' for x in d['classifications'])
def test_08_binary_classified(tmp_path):
    seed(tmp_path,'ELF executable .so imports'); d=build(tmp_path); assert any(x['kind']=='binary' for x in d['classifications'])
def test_09_custom_protocol_classified(tmp_path):
    seed(tmp_path,'unknown protocol tcp/9001'); d=build(tmp_path); assert any(x['kind']=='custom-protocol' for x in d['classifications'])
def test_10_hypotheses_not_findings(tmp_path):
    seed(tmp_path,'login session'); d=build(tmp_path); assert d['hypotheses'] and all(x['not_a_finding'] for x in d['hypotheses'])
def test_11_experiment_plan_exists(tmp_path):
    seed(tmp_path,'OpenAPI'); d=build(tmp_path); assert d['experiment_plan']
def test_12_auto_execution_disabled(tmp_path):
    seed(tmp_path,'OpenAPI'); d=build(tmp_path); assert all(not x['auto_execute'] for x in d['experiment_plan'])
def test_13_human_approval_required(tmp_path):
    seed(tmp_path,'OpenAPI'); d=build(tmp_path); assert all(x['human_approval_required'] for x in d['experiment_plan'])
def test_14_unknown_escalates(tmp_path):
    seed(tmp_path,'completely novel artifact with no known marker'); d=build(tmp_path); assert d['escalations']
def test_15_custom_protocol_escalates(tmp_path):
    seed(tmp_path,'unknown protocol tcp/9001'); d=build(tmp_path); assert any('protocol' in x.lower() for x in d['escalations'])
def test_16_binary_boundary(tmp_path):
    seed(tmp_path,'ELF executable'); d=build(tmp_path); assert any('reverse engineering' in x.lower() for x in d['escalations'])
def test_17_no_scope_expansion(tmp_path):
    seed(tmp_path,'AWS IAM'); d=build(tmp_path); assert d['decision_policy']['no_scope_expansion'] is True
def test_18_no_credential_guessing(tmp_path):
    seed(tmp_path,'login password token'); d=build(tmp_path); assert d['decision_policy']['no_credential_guessing'] is True
def test_19_artifact_persisted_and_redacted(tmp_path):
    seed(tmp_path,'token: SUPER-SECRET-VALUE'); d=build(tmp_path); p=tmp_path/'evidence'/'adaptive-assessment-v28.json'; raw=p.read_text(); assert p.exists(); assert 'SUPER-SECRET-VALUE' not in raw
def test_20_deterministic_order(tmp_path):
    seed(tmp_path,'AWS IAM OpenAPI login Wi-Fi ELF'); a=build(tmp_path); b=build(tmp_path); assert [x['kind'] for x in a['classifications']]==[x['kind'] for x in b['classifications']]
