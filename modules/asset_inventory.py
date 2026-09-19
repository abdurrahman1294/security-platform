#!/usr/bin/env python3
"""Build a conservative asset inventory from engagement artifacts."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from urllib.parse import urlparse
from modules.findings_io import load_findings_file

def _asset(value: str) -> str:
    value = value.strip()
    if not value: return "unknown"
    parsed = urlparse(value if "://" in value else "//" + value)
    return (parsed.hostname or value.split("/")[0]).lower().rstrip(".")

def _add(store, host, source, detail=""):
    host = _asset(host)
    if host in {"unknown", "localhost"}: return
    item = store.setdefault(host, {"asset_id":"A-" + hashlib.sha256(host.encode()).hexdigest()[:10], "hostname":host, "sources":set(), "ports":set(), "urls":set(), "technologies":set()})
    item["sources"].add(source)
    if detail.startswith("port:"): item["ports"].add(detail[5:])
    elif detail.startswith("url:"): item["urls"].add(detail[4:])
    elif detail.startswith("tech:"): item["technologies"].add(detail[5:])

def build_asset_inventory(outdir: str | Path) -> Path:
    root=Path(outdir); store={}
    recon=root/"recon"
    for name in ("subdomains.txt", "live-hosts.txt"):
        p=recon/name
        if p.exists():
            for line in p.read_text(errors="ignore").splitlines():
                if line.strip():
                    token=line.strip().split()[0]; _add(store, token, f"recon/{name}", "url:"+token if "://" in token else "")
    ports=root/"ports"
    for p in ports.glob("*.txt"):
        for line in p.read_text(errors="ignore").splitlines():
            m=re.search(r"(?P<host>[^\s:/]+)(?::(?P<port>\d+))?", line)
            if m: _add(store,m.group("host"),f"ports/{p.name}","port:"+(m.group("port") or ""))
    for rel in ("vulns/findings.json","vulns/authenticated-findings.json","api/api-findings.json","servers/server-findings.json","internal/internal-findings.json"):
        p=root/rel
        for f in load_findings_file(p):
            host=f.get("host") or f.get("matched-at") or f.get("url")
            if host: _add(store,host,rel,"url:"+str(host))
            for tech in (f.get("info") or {}).get("tags",[]) or []:
                _add(store,host or "",rel,"tech:"+str(tech))
    assets=[]
    for x in store.values():
        for k in ("sources","ports","urls","technologies"): x[k]=sorted(x[k])
        assets.append(x)
    assets.sort(key=lambda x:x["hostname"])
    payload={"schema_version":"1.0","asset_count":len(assets),"assets":assets}
    path=root/"evidence"/"assets.json"; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    return path
