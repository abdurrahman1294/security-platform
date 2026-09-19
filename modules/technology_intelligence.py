#!/usr/bin/env python3
"""V15 technology and asset intelligence.

Passive/derived intelligence only: parses existing engagement artifacts and
never probes or contacts targets.
"""
from __future__ import annotations
import json, re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
from modules.findings_io import load_findings_file

TECH_RE = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9_.-]{1,30})[/: ](?P<ver>v?\d+(?:\.\d+){0,3})", re.I)
KNOWN = ["nginx","apache","iis","node.js","express","react","next.js","wordpress","php","postgresql","mysql","redis","mongodb","docker","kubernetes","graphql","jwt","aws","azure","cloudflare"]

def _read_lines(path):
    if not path.exists(): return []
    return [x.strip() for x in path.read_text(errors="ignore").splitlines() if x.strip()]

def _host(value):
    s=str(value).strip()
    if not s: return ""
    # httpx output may include status/title/tech metadata after the URL.
    s=s.split()[0]
    p=urlparse(s if "://" in s else "//"+s)
    return (p.hostname or s.split("/",1)[0]).lower().rstrip(".")

_load_jsonl = load_findings_file

def build(root: str|Path):
    root=Path(root); evidence=root/"evidence"; evidence.mkdir(parents=True,exist_ok=True)
    assets=defaultdict(lambda:{"asset":"","observations":set(),"technologies":set(),"sources":set()})
    for p in [root/"recon"/"subdomains.txt", root/"recon"/"live-hosts.txt"]:
        for line in _read_lines(p):
            h=_host(line)
            if h: assets[h].update(asset=h)
            if h: assets[h]["observations"].add(line); assets[h]["sources"].add(p.name)
    for p in [root/"vulns"/"findings.json",root/"vulns"/"authenticated-findings.json",root/"api"/"api-findings.json",root/"servers"/"server-findings.json"]:
        for f in _load_jsonl(p):
            h=_host(f.get("host") or f.get("matched-at")); info=f.get("info") or {}
            text=" ".join(str(x) for x in [info.get("name"),info.get("description")," ".join(info.get("tags",[]) or []),f.get("template-id"),f.get("host")]).lower()
            if not h: continue
            a=assets[h]; a.update(asset=h); a["sources"].add(p.name)
            for tech in KNOWN:
                if tech in text: a["technologies"].add(tech)
            for m in TECH_RE.finditer(text):
                a["technologies"].add(m.group("name").lower()+" "+m.group("ver"))
            a["observations"].add(str(info.get("name") or f.get("template-id") or "finding"))
    result=[]
    for h,a in sorted(assets.items()):
        result.append({"asset":h,"technologies":sorted(a["technologies"]),"observations":sorted(a["observations"]),"sources":sorted(a["sources"])})
    payload={"schema_version":"1.0","mode":"artifact-derived","asset_count":len(result),"assets":result}
    path=evidence/"technology-inventory.json"; path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# Technology & Asset Intelligence","","> Derived from existing engagement artifacts. No network activity is performed.",""]
    for a in result:
        lines.append(f"## `{a['asset']}`")
        lines.append("- Technologies: " + (", ".join(a["technologies"]) if a["technologies"] else "not confidently identified"))
        lines.append("- Sources: " + ", ".join(a["sources"]))
        lines.append("")
    (root/"reports"/"technology-intelligence.md").write_text("\n".join(lines),encoding="utf-8")
    return path
