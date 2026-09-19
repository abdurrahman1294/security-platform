import json
from modules.network_surface_v27 import dns_observe, tls_observe


def test_dns_observation_loopback(tmp_path):
    out = dns_observe(tmp_path, '127.0.0.1')
    assert out['status'] == 'completed'
    assert '127.0.0.1' in out['addresses']
    assert (tmp_path/'evidence'/'dns-observation-v27.json').exists()


def test_tls_invalid_target_rejected(tmp_path):
    try:
        tls_observe(tmp_path, '', port=443)
    except ValueError:
        pass
    else:
        raise AssertionError('invalid TLS target accepted')
