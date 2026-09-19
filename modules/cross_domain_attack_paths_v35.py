"""V3.5 cross-domain attack-path hypotheses.

Correlates observed assets/findings/identity/cloud relationships into bounded,
evidence-backed hypotheses. It never executes exploitation, credential use,
pivoting, persistence, or destructive actions.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from modules.atomic_io import atomic_write_json

SURFACE_FILES = {
    "ad": "evidence/ad-relationships-v32.json",
    "azure": "evidence/cloud-azure-assessment-v32.json",
    "gcp": "evidence/cloud-gcp-assessment-v32.json",
    "kubernetes": "evidence/cloud-kubernetes-assessment-v32.json",
    "container": "evidence/container-security-v33.json",
    "database": "evidence/database-surface-v33.json",
    "network": "evidence/network-device-config-v33.json",
}

def _read(p):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}

def _rows(doc):
    if isinstance(doc, list): return doc
    if isinstance(doc, dict):
        for k in ("findings", "relationships", "services", "assets", "resources"):
            if isinstance(doc.get(k), list): return doc[k]
    return []

def build(root: str|Path) -> dict:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True, exist_ok=True)
    observations=[]
    for surface, rel in SURFACE_FILES.items():
        rows=_rows(_read(root/rel))
        for i,row in enumerate(rows):
            if not isinstance(row,dict): continue
            label=str(row.get("title") or row.get("name") or row.get("id") or row.get("relationship") or f"{surface}-{i}")
            asset=str(row.get("asset") or row.get("host") or row.get("address") or row.get("principal") or row.get("resource") or "")
            observations.append({"surface":surface,"label":label,"asset":asset[:255],"source":rel})
    paths=[]
    for i,a in enumerate(observations):
        for b in observations[i+1:]:
            if a["surface"]==b["surface"]: continue
            pair={a["surface"],b["surface"]}
            reason="Cross-domain evidence exists between two independently observed security surfaces."
            confidence=0.35
            if pair & {"ad","azure","gcp","kubernetes"}: confidence += 0.15
            if pair & {"database","container","network"}: confidence += 0.10
            seed="|".join(sorted([a["source"],a["label"],b["source"],b["label"]]))
            pid="AP-"+hashlib.sha256(seed.encode()).hexdigest()[:12]
            paths.append({"id":pid,"from":a,"to":b,"confidence":round(min(confidence,0.75),2),"status":"hypothesis","prerequisites":["Both observations must be independently validated","Both assets must remain in authorized scope","Operator approval is required before any consequential proof"],"rationale":reason})
            if len(paths)>=500: break
        if len(paths)>=500: break
    data={"schema_version":"3.5","status":"completed","observation_count":len(observations),"hypothesis_count":len(paths),"hypotheses":paths,"limitations":["Correlation is not proof of exploitability or reachability","No credentials, pivots, exploitation, persistence, or impact actions are performed"]}
    atomic_write_json(ev/"cross-domain-attack-paths-v35.json",data)
    return data
