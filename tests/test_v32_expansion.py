import json, zipfile
from pathlib import Path
from modules.cloud_multiplatform_v32 import assess_export, PROVIDERS
from modules.ad_relationships_v32 import analyze
from modules.mobile_ios_v32 import analyze_ipa
from modules.wireless_ble_v32 import assess_export as ble_assess
from modules.expert_capability_audit_v27 import build


def test_cloud_export_is_read_only(tmp_path):
    f=tmp_path/'azure.json'; f.write_text(json.dumps({'resources':[{'type':'Microsoft.Storage/storageAccounts','publicNetworkAccess':'Enabled'}]}))
    out=assess_export(tmp_path,'azure',f)
    assert out['analysis']['read_only'] is True
    assert out['provider']=='azure'


def test_ad_relationship_analysis(tmp_path):
    f=tmp_path/'rels.json'; f.write_text(json.dumps([{'source':'user','target':'group','relation':'GenericAll'},{'source':'svc','target':'dc','label':'Kerberoast'}]))
    out=analyze(tmp_path,f)
    assert out['acl_delegation_candidates']
    assert out['kerberos_candidates']


def test_ios_static(tmp_path):
    ipa=tmp_path/'demo.ipa'
    with zipfile.ZipFile(ipa,'w') as z:
        z.writestr('Payload/Demo.app/Info.plist', __import__('plistlib').dumps({'CFBundleIdentifier':'com.example.demo','NSAppTransportSecurity':{'NSAllowsArbitraryLoads':True}}))
        z.writestr('Payload/Demo.app/Demo', b'\xcf\xfa\xed\xfe https://example.test api_key=SECRET12345678')
    out=analyze_ipa(tmp_path,ipa)
    assert out['status']=='completed'
    assert any(x['id']=='IOS-MACHO' for x in out['findings'])
    saved=json.dumps(json.loads((tmp_path/'evidence/ios-static-v32.json').read_text()))
    assert 'SECRET12345678' not in saved


def test_ble_export(tmp_path):
    f=tmp_path/'ble.json'; f.write_text(json.dumps({'devices':[{'name':'lab','address':'AA:BB:CC:DD:EE:FF'}]}))
    out=ble_assess(tmp_path,f)
    assert out['status']=='completed'
    assert out['device_count']==1


def test_capability_gaps_reduced(tmp_path):
    out=build(tmp_path, tool_inventory=[{'name':'az','status':'ready'},{'name':'gcloud','status':'ready'},{'name':'kubectl','status':'ready'}])
    ids={x['id']:x for x in out['capabilities']}
    assert ids['cloud.azure']['status'] != 'gap'
    assert ids['cloud.gcp']['status'] != 'gap'
    assert ids['cloud.k8s']['status'] != 'gap'
    assert ids['mobile.ios']['status'] == 'implemented-not-executed'
    assert ids['wireless.ble']['status'] == 'implemented-not-executed'


def test_readonly_tool_allowlists():
    from modules.tool_adapter_hardening_v162 import validate_argv
    assert validate_argv('az', ['az','role','assignment','list','--all','--output','json'])[0]
    assert validate_argv('gcloud', ['gcloud','projects','list','--format','json'])[0]
    assert validate_argv('kubectl', ['kubectl','get','pods','--all-namespaces','-o','json'])[0]
    assert not validate_argv('kubectl', ['kubectl','delete','pod','x'])[0]
