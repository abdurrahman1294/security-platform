from modules.cellular_universal_fabric_v319 import *

def test_version(): assert VERSION == '3.19.0'
def test_surface_all_domains(tmp_path):
    out=build_universal_cellular_surface(tmp_path,'example.test')
    assert len(out['domains']) >= 15
    assert any(x['domain']=='remote_computer' for x in out['domains'])
    assert any(x['domain']=='ot_ics' for x in out['domains'])
def test_probe_requires_port_allowlist():
    assert validate_probe_request('tcp','203.0.113.10',443,approved_ports=[] )['allowed'] is False
    assert validate_probe_request('tcp','203.0.113.10',443,approved_ports=[443])['allowed'] is True
def test_probe_dns_local():
    out=run_probe('dns','localhost')
    assert out['status'] in {'ok','error'}
def test_fabric(tmp_path):
    out=build_v319_fabric(tmp_path,'203.0.113.10',approved_ports=[443])
    assert {'universal_surface','probe_contract','advanced_domains'} <= set(out)
