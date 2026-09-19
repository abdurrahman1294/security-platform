import json
from pathlib import Path
from modules.operational_maturity_v26 import artifact_inventory, correlate, coverage, health, build_run_state


def test_artifact_inventory_and_hash(tmp_path):
    (tmp_path / 'evidence').mkdir()
    (tmp_path / 'evidence' / 'x.txt').write_text('hello')
    data = artifact_inventory(tmp_path)
    row = next(x for x in data['files'] if x['path'].endswith('x.txt'))
    assert len(row['sha256']) == 64
    assert (tmp_path/'evidence'/'artifact-inventory-v26.json').exists()


def test_correlation_redacts_and_links(tmp_path):
    (tmp_path/'evidence').mkdir(); (tmp_path/'web').mkdir()
    (tmp_path/'web'/'sample.txt').write_text('https://app.example.test/login')
    (tmp_path/'evidence'/'f.json').write_text(json.dumps({'host':'app.example.test','username':'alice','password':'secret'}))
    data = correlate(tmp_path)
    assert 'https://app.example.test/login' in data['urls']
    assert 'alice' in data['identity_references']
    raw = json.dumps(data)
    assert 'secret' not in raw


def test_coverage_requires_artifact(tmp_path):
    (tmp_path/'recon').mkdir(); (tmp_path/'recon'/'subdomains.txt').write_text('app.example.test\n')
    data = coverage(tmp_path)
    assert data['domains']['recon'] is True
    assert data['domains']['web'] is False


def test_health_degraded_when_tools_missing(tmp_path):
    (tmp_path/'evidence').mkdir()
    data = health(tmp_path, tool_inventory=[{'name':'nmap','available':True}])
    assert data['status'] == 'degraded'
    assert 'nmap' in data['available_tools']


def test_run_state_redacts(tmp_path):
    (tmp_path/'evidence').mkdir()
    data = build_run_state(tmp_path, engine='pentest', phase='credentials', status='completed', details={'token':'secret'})
    assert data['last']['details']['token'] == '[REDACTED]'
