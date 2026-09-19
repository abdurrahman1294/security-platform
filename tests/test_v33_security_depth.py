import json, tarfile
from modules.container_security_v33 import assess_archive
from modules.database_surface_v33 import assess
from modules.network_device_config_v33 import assess as net_assess

def test_container_archive(tmp_path):
    src=tmp_path/'image.tar'; cfg={'config':{'User':'root','Env':['API_TOKEN=do-not-store'], 'ExposedPorts':{'5432/tcp':{} }}}
    f=tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    with tarfile.open(src,'w') as t: t.add(f,arcname='blobs/config.json')
    out=assess_archive(tmp_path,src)
    assert out['status']=='completed'; assert any(x['id']=='CTR-ROOT' for x in out['findings']); assert 'do-not-store' not in (tmp_path/'evidence/container-security-v33.json').read_text()

def test_database_surface(tmp_path):
    p=tmp_path/'services.json'; p.write_text(json.dumps({'services':[{'host':'10.0.0.5','port':5432,'tls':False,'exposed':True}]}))
    out=assess(tmp_path,p); ids={x['id'] for x in out['findings']}; assert {'DB-CLEARTEXT','DB-EXPOSED'}<=ids

def test_network_config_redacts(tmp_path):
    p=tmp_path/'router.cfg'; p.write_text('snmp-server community public\nusername admin secret supersecret\nip http server\n')
    out=net_assess(tmp_path,p); saved=(tmp_path/'evidence/network-device-config-v33.json').read_text(); assert 'supersecret' not in saved; assert any(x['id']=='NET-TELNET' for x in out['findings']) is False; assert any(x['id']=='NET-DEFAULT-SNMP' for x in out['findings'])
