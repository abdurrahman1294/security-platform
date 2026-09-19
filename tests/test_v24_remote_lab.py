from pathlib import Path
from modules.remote_lab_v24 import assess, SCENARIOS
from modules.roe_policy_v18 import ROEPolicy

def test_remote_dry_run(tmp_path):
    out=assess(tmp_path,'http://127.0.0.1:8090')
    assert out['status']=='dry_run' and len(out['results'])==len(SCENARIOS)

def test_remote_blocks_execution_without_roe(tmp_path):
    out=assess(tmp_path,'http://127.0.0.1:8090',execute=True,authorized=True,roe_permitted=False)
    assert out['status']=='blocked'

def test_remote_rejects_non_loopback(tmp_path):
    out=assess(tmp_path,'http://192.0.2.1:8090',execute=True,authorized=True,roe_permitted=True)
    assert out['status']=='blocked'

def test_remote_catalog_is_fixed():
    assert set(SCENARIOS) == {'rce','credential-exposure','command-injection','ssrf','privilege-escalation','persistence','lateral-auth','objective-access','destructive-boundary'}

def test_roe_remote_target_binding():
    r=ROEPolicy.from_dict({'enable_r4':True,'allowed_r4_actions':['controlled_attack_chain_test'],'max_impact':'high','operator':'x','engagement_reference':'y','target':'http://127.0.0.1:8090'})
    assert r.permits('controlled_attack_chain_test',target='http://127.0.0.1:8090')
    assert not r.permits('controlled_attack_chain_test',target='http://127.0.0.1:8091')
