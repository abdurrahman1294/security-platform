"""Passive/read-only BLE assessment from operator-supplied scan exports."""
from __future__ import annotations
import csv,json,re
from pathlib import Path
from modules.atomic_io import atomic_write_json

VERSION="3.2"

def assess_export(root: str | Path, source: str | Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True); p=Path(source)
    if not p.is_file() or p.stat().st_size > 10*1024*1024: return {"status":"blocked","reason":"scan-export-required"}
    text=p.read_text(encoding="utf-8",errors="replace")
    devices=[]
    if p.suffix.lower()==".json":
        try:
            val=json.loads(text); seq=val if isinstance(val,list) else val.get("devices",[]) if isinstance(val,dict) else []
            devices=[x for x in seq if isinstance(x,dict)]
        except json.JSONDecodeError: return {"status":"blocked","reason":"invalid-json"}
    else:
        devices=list(csv.DictReader(text.splitlines()))
    macs=[]
    for d in devices:
        blob=json.dumps(d).lower()
        mac=next(iter(re.findall(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}",blob)),"")
        macs.append(mac)
    data={"schema_version":VERSION,"status":"completed","source":str(p),"device_count":len(devices),"devices":devices[:1000],"mac_addresses":sorted(set(macs)-{""}),"capabilities":["BLE advertisement inventory","GATT/service review from supplied exports"],"limitations":["No active pairing, connection, authentication bypass, jamming, or credential extraction.","Export data does not prove exploitability."]}
    atomic_write_json(ev/"ble-assessment-v32.json",data); return data
