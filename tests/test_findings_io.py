import json
from modules.findings_io import load_findings_file


def test_load_findings_file_supports_array_json(tmp_path):
    p = tmp_path / 'findings.json'
    p.write_text(json.dumps([{'template-id': 'a'}, {'template-id': 'b'}]))
    assert [x['template-id'] for x in load_findings_file(p)] == ['a', 'b']


def test_load_findings_file_supports_jsonl(tmp_path):
    p = tmp_path / 'findings.json'
    p.write_text(json.dumps({'template-id': 'a'}) + '\n' + json.dumps({'template-id': 'b'}) + '\n')
    assert [x['template-id'] for x in load_findings_file(p)] == ['a', 'b']


def test_load_findings_file_supports_findings_wrapper(tmp_path):
    p = tmp_path / 'findings.json'
    p.write_text(json.dumps({'findings': [{'id': 'a'}, {'id': 'b'}]}))
    assert [x['id'] for x in load_findings_file(p)] == ['a', 'b']


def test_load_findings_file_supports_single_finding_object(tmp_path):
    p = tmp_path / 'findings.json'
    p.write_text(json.dumps({'template-id': 'single', 'info': {'severity': 'high'}}))
    assert load_findings_file(p)[0]['template-id'] == 'single'
