"""Evidence-only AD ACL/delegation/Kerberos relationship analysis.

Consumes exported relationship data; it does not query a domain, request
credentials, modify ACLs, forge tickets, or perform lateral movement.
"""
from __future__ import annotations
import csv, json
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json

VERSION = "3.2"
DANGEROUS_RELATIONS = {"genericall", "genericwrite", "writedacl", "writeowner", "forcechangepassword", "addmember", "allextendedrights"}
KERBEROS_MARKERS = {"kerberoast", "asrep", "unconstraineddelegation", "constraineddelegation", "resourcebasedconstraineddelegation", "rbcd"}


def _rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(value, dict):
            for key in ("data", "relationships", "edges", "results"):
                if isinstance(value.get(key), list): return [x for x in value[key] if isinstance(x, dict)]
            return [value]
        return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def analyze(root: str | Path, source: str | Path) -> dict[str, Any]:
    root=Path(root); ev=root/"evidence"; ev.mkdir(parents=True, exist_ok=True)
    p=Path(source)
    if not p.is_file() or p.stat().st_size > 20*1024*1024: raise ValueError("AD export must be an existing file <= 20 MiB")
    rows=_rows(p)
    rels=[]; kerberos=[]
    for r in rows:
        text=" ".join(str(v) for v in r.values()).lower()
        relation=str(r.get("relation") or r.get("label") or r.get("edge") or "").lower().replace(" ", "")
        if relation in DANGEROUS_RELATIONS or any(x in text for x in DANGEROUS_RELATIONS):
            rels.append({"relation": relation or "relationship", "source": r.get("source") or r.get("src") or r.get("principal"), "target": r.get("target") or r.get("dst") or r.get("resource")})
        markers=sorted(k for k in KERBEROS_MARKERS if k in text)
        if markers: kerberos.append({"markers": markers, "record": {k:r[k] for k in list(r)[:8]}})
    data={"schema_version":VERSION,"mode":"offline-relationship-analysis","source":str(p),"records":len(rows),
          "acl_delegation_candidates":rels[:500],"kerberos_candidates":kerberos[:500],
          "limitations":["Relationships are hypotheses until independently validated.","No credential access or ticket operations are performed.","No ACL, delegation, or group membership is changed."]}
    atomic_write_json(ev/"ad-relationships-v32.json",data); return data
