import json
from pathlib import Path
from modules.opsec_v25 import sanitize_for_export, audit_artifacts, build_posture
from security_platform.cli.securityctl import parser


def test_sanitizer_redacts_secrets_and_personal_fields():
    src={"password":"dont-leak", "operator_email":"a@example.test", "note":"Bearer ABCDEFGHIJKLMNOP"}
    out=sanitize_for_export(src)
    dumped=json.dumps(out)
    assert "dont-leak" not in dumped
    assert "a@example.test" not in dumped
    assert "ABCDEFGHIJKLMNOP" not in dumped


def test_artifact_audit_does_not_emit_secret_value(tmp_path):
    p=tmp_path/'evidence'; p.mkdir()
    (p/'x.json').write_text('{"api_token":"TOPSECRET-123456789"}')
    result=audit_artifacts(tmp_path)
    dumped=json.dumps(result)
    assert result['status']=='attention'
    assert 'TOPSECRET-123456789' not in dumped
    assert result['findings']


def test_posture_is_explicitly_not_absolute_anonymity(tmp_path):
    out=build_posture(tmp_path, operator_alias='alice')
    assert out['absolute_anonymity'] is False
    assert out['anti_forensics'] is False
    assert out['network_anonymization']=='not provided'
    saved=json.loads((tmp_path/'evidence/opsec-posture-v25.json').read_text())
    assert saved['accountability_required'] is True


def test_cli_exposes_opsec():
    args=parser().parse_args(['opsec','-c','LAB','-t','127.0.0.1','-o','out'])
    assert args.engine=='opsec'
