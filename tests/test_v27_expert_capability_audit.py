import json
from modules.expert_capability_audit_v27 import build


def test_audit_catalog_and_gap_visibility(tmp_path):
    (tmp_path / 'evidence').mkdir()
    data = build(tmp_path, tool_inventory=[{'name':'nmap','status':'ready'}])
    assert data['schema_version'] == '2.7'
    assert data['catalog_size'] >= 50
    assert any(x['status'] == 'gap' for x in data['capabilities'])
    assert any(x['status'] == 'human-required' for x in data['capabilities'])
    assert (tmp_path/'evidence'/'expert-capability-audit-v27.json').exists()


def test_audit_distinguishes_evidence_from_implementation(tmp_path):
    (tmp_path/'evidence').mkdir()
    (tmp_path/'recon').mkdir()
    (tmp_path/'recon'/'subdomains.txt').write_text('app.example.test\n')
    data = build(tmp_path, tool_inventory=[{'name':'subfinder','status':'ready'}, {'name':'assetfinder','status':'ready'}])
    row = next(x for x in data['capabilities'] if x['id'] == 'recon.subdomains')
    assert row['status'] == 'executed-evidence-backed'


def test_audit_marks_missing_tool(tmp_path):
    (tmp_path/'evidence').mkdir()
    data = build(tmp_path, tool_inventory=[])
    row = next(x for x in data['capabilities'] if x['id'] == 'recon.subdomains')
    assert row['status'] == 'implemented-but-tool-missing'
    assert 'subfinder' in row['missing_tools']
