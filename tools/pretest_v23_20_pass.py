from __future__ import annotations
import json, tempfile, zipfile, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_platform.core.engagement import Engagement
from security_platform.engines import MobileEngine, WirelessEngine
from modules.mobile_android_v23 import analyze_apk
from modules.wireless_v23 import inventory
from modules.versatility_gap_v23 import build as gap


def run():
    root=Path(tempfile.mkdtemp(prefix='v23gate-'))
    checks=[]
    def ck(name, fn):
        try: fn(); checks.append((name,'PASS'))
        except Exception as e: checks.append((name,f'FAIL:{e}'))
    apk=root/'fixture.apk'
    manifest='''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="lab.v23"><uses-permission android:name="android.permission.CAMERA"/><application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true"><activity android:name=".Main" android:exported="true"/></application></manifest>'''
    with zipfile.ZipFile(apk,'w') as z:
        z.writestr('AndroidManifest.xml',manifest); z.writestr('classes.dex',b'WebView setJavaScriptEnabled http://lab.test api_key=V23SECRET12345678')
    e=Engagement('LAB','127.0.0.1',root,root/'scope.txt')
    ck('01 apk accepted',lambda: assert_eq(analyze_apk(root,apk)['status'],'completed'))
    result=analyze_apk(root,apk)
    ck('02 package parsed',lambda: assert_eq(result['package'],'lab.v23'))
    ck('03 permission detected',lambda: assert_in('AND-PERM',{x['id'] for x in result['findings']}))
    ck('04 debuggable detected',lambda: assert_in('AND-DBG',{x['id'] for x in result['findings']}))
    ck('05 cleartext detected',lambda: assert_in('AND-CLEAR',{x['id'] for x in result['findings']}))
    ck('06 exported component detected',lambda: assert_in('AND-EXP',{x['id'] for x in result['findings']}))
    ck('07 secret redacted',lambda: assert_not('V23SECRET12345678',(root/'evidence/android-static-v23.json').read_text()))
    ck('08 invalid apk blocked',lambda: assert_eq(analyze_apk(root,root/'missing.apk')['status'],'blocked'))
    ck('09 mobile engine exposed',lambda: assert_eq(MobileEngine(e).version,'2.6'))
    ck('10 wireless engine exposed',lambda: assert_eq(WirelessEngine(e).version,'2.6'))
    w=inventory(root,'wlan0')
    ck('11 wireless schema',lambda: assert_eq(w['schema_version'],'23.0'))
    ck('12 wireless restrictions',lambda: assert_in('deauthentication',w['restricted_actions']))
    ck('13 wireless injection restricted',lambda: assert_in('frame_injection',w['restricted_actions']))
    ck('14 wireless cracking restricted',lambda: assert_in('credential_cracking',w['restricted_actions']))
    g=gap(root)
    ck('15 Android P0',lambda: assert_eq(g['domains']['android_mobile']['priority'],'P0'))
    ck('16 wireless P0',lambda: assert_eq(g['domains']['wireless']['priority'],'P0'))
    ck('17 gap evidence exists',lambda: (root/'evidence/versatility-gap-v23.json').is_file() or (_ for _ in ()).throw(AssertionError()))
    ck('18 android evidence exists',lambda: (root/'evidence/android-static-v23.json').is_file() or (_ for _ in ()).throw(AssertionError()))
    ck('19 invalid zip blocked',lambda: (root/'bad.apk').write_bytes(b'notzip') and assert_eq(analyze_apk(root,root/'bad.apk')['status'],'blocked'))
    ck('20 no arbitrary shell in new modules',lambda: assert_not('shell=True',Path('modules/mobile_android_v23.py').read_text()+Path('modules/wireless_v23.py').read_text()))
    passed=sum(s=='PASS' for _,s in checks)
    print('\n'.join(f'{n} {s}' for n,s in checks)); print(f'SUMMARY passed={passed} failed={len(checks)-passed} total={len(checks)}')
    return 0 if passed==20 else 1

def assert_eq(a,b):
    assert a==b,(a,b)
def assert_in(a,b): assert a in b,a
def assert_not(a,b): assert a not in b,a
if __name__=='__main__': raise SystemExit(run())
