import json, zipfile
from pathlib import Path
from security_platform.engines.mobile import MobileEngine
from security_platform.engines.wireless import WirelessEngine
from security_platform.core.engagement import Engagement
from modules.versatility_gap_v23 import build


def test_android_static_fallback(tmp_path):
    apk=tmp_path/'demo.apk'
    manifest='''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo"><uses-permission android:name="android.permission.CAMERA"/><application android:debuggable="true" android:usesCleartextTraffic="true"><activity android:name=".MainActivity" android:exported="true"/></application></manifest>'''
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('AndroidManifest.xml',manifest)
        z.writestr('classes.dex',b'WebView setJavaScriptEnabled http://example.test api_key=SECRET12345678')
    e=Engagement('lab','127.0.0.1',tmp_path,tmp_path/'scope.txt')
    out=MobileEngine(e).android(str(apk))
    assert out['status']=='completed'
    ids={x['id'] for x in out['findings']}
    assert {'AND-DBG','AND-CLEAR','AND-PERM'} <= ids
    assert out['secret_marker_count'] >= 1
    saved=json.loads((tmp_path/'evidence/android-static-v23.json').read_text())
    assert 'SECRET12345678' not in json.dumps(saved)


def test_android_dynamic_blocks_physical_by_default(tmp_path):
    e=Engagement('lab','127.0.0.1',tmp_path,tmp_path/'scope.txt')
    from modules.mobile_android_v23 import dynamic_readonly
    out=dynamic_readonly(tmp_path, serial='USB123', allow_physical=False)
    assert out['status'] in {'blocked','completed'}
    if out['status']=='blocked': assert 'physical' in out['reason'] or 'adb' in out['reason']


def test_wireless_inventory_is_bounded(tmp_path):
    e=Engagement('lab','127.0.0.1',tmp_path,tmp_path/'scope.txt')
    out=WirelessEngine(e).assess('wlan0')
    assert out['schema_version']=='23.0'
    assert 'restricted_actions' in out
    assert 'deauthentication' in out['restricted_actions']


def test_gap_audit(tmp_path):
    out=build(tmp_path)
    assert out['domains']['android_mobile']['priority']=='P0'
    assert out['domains']['wireless']['priority']=='P0'
    assert (tmp_path/'evidence/versatility-gap-v23.json').is_file()
