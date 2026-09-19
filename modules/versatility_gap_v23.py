from __future__ import annotations
import json
from pathlib import Path
from modules.atomic_io import atomic_write_json

VERSION="23.0"
DOMAINS={
 "android_mobile": {"status":"new","priority":"P0","coverage":["APK structure","manifest/permissions","exported components","cleartext/debuggable/backup heuristics","embedded URL/secret markers","native library inventory","read-only emulator inspection"],"next_depth":["runtime instrumentation","network traffic correlation","native memory review","Play Integrity and signing analysis"]},
 "wireless": {"status":"new","priority":"P0","coverage":["radio/interface inventory","driver capability observation","NetworkManager state","PCAP parsing"],"next_depth":["controlled monitor-mode lab capture","802.11 management-frame analysis","rogue AP detection","segmentation validation","BLE inventory"]},
 "network_services": {"status":"partial","priority":"P1","coverage":["TCP discovery","Nmap","service/version discovery"],"next_depth":["UDP/SNMP/NFS/SMTP/DNS/TLS deep checks"]},
 "windows_ad": {"status":"partial","priority":"P1","coverage":["read-only NetExec enumeration","AD relationship analysis"],"next_depth":["Kerberos/ACL/delegation/GPO lab validation"]},
 "cloud": {"status":"partial","priority":"P1","coverage":["AWS read-only inventory","IAM relationships","network/storage inventory"],"next_depth":["Azure/Entra and GCP lab parity","Kubernetes admission/RBAC analysis"]},
 "mobile_ios": {"status":"planned","priority":"P2","coverage":[],"next_depth":["IPA metadata/signing/static analysis","simulator read-only inspection"]},
 "wireless_bluetooth": {"status":"planned","priority":"P2","coverage":[],"next_depth":["BLE advertisement inventory","GATT security review"]},
 "physical_social": {"status":"not_automated","priority":"P3","coverage":["planning/reporting only"],"next_depth":["operator-led exercises with separate governance"]},
}

def build(root):
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    data={"schema_version":VERSION,"domains":DOMAINS,"rule":"Only executed evidence counts as coverage; planned capabilities remain gaps.","focus":"Android/mobile and wireless were promoted to first-class specialist domains."}
    atomic_write_json(ev/"versatility-gap-v23.json",data); return data
