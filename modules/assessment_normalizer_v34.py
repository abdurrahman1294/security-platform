"""V3.4 normalized attack-surface inventory.

Converts existing tool exports into a stable, evidence-friendly asset/service
model. It does not probe, exploit, or expand scope.
"""
from __future__ import annotations
import json, hashlib, re
from pathlib import Path
from modules.atomic_io import atomic_write_json

HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")

def _read_json(p: Path):
    try:
        x=json.loads(p.read_text(encoding="utf-8")); return x
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

def build(root: str|Path, target: str="") -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True,exist_ok=True)
    assets={}; services=[]
    def asset(v, source):
        v=str(v or "").strip()
        if not v or len(v)>255 or not HOST_RE.match(v): return
        key=v.lower(); row=assets.setdefault(key,{"asset":v,"sources":[]})
        if source not in row["sources"]: row["sources"].append(source)
    if target: asset(target,"engagement-target")
    for rel in ["recon/live-hosts.txt","recon/subdomains.txt","ports/naabu.txt"]:
        p=root/rel
        if p.exists():
            for line in p.read_text(encoding="utf-8",errors="ignore").splitlines():
                token=line.strip().split()[0] if line.strip() else ""
                if token: asset(token,rel)
    for rel in ["vulns/findings.json","vulns/findings.normalized.json","evidence/database-surface-v33.json","evidence/cloud-azure-assessment-v32.json","evidence/cloud-gcp-assessment-v32.json","evidence/cloud-kubernetes-assessment-v32.json"]:
        p=root/rel; doc=_read_json(p)
        if doc is None: continue
        rows=doc if isinstance(doc,list) else doc.get("findings",doc.get("services",[])) if isinstance(doc,dict) else []
        if not isinstance(rows,list): continue
        for row in rows:
            if not isinstance(row,dict): continue
            host=row.get("host") or row.get("address") or row.get("matched-at")
            if host:
                asset(host,rel)
            if row.get("port") is not None and host:
                services.append({"asset":str(host),"port":row.get("port"),"service":row.get("service") or row.get("name"),"source":rel})
    data={"schema_version":"3.4","target":target,"asset_count":len(assets),"assets":sorted(assets.values(),key=lambda x:x["asset"].lower()),"services":services,"source_hashes":{}}
    for p in root.rglob("*"):
        if p.is_file() and ("evidence" in p.parts or p.name in {"live-hosts.txt","subdomains.txt"}):
            try: data["source_hashes"][str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError: pass
    atomic_write_json(ev/"normalized-attack-surface-v34.json",data)
    return data
