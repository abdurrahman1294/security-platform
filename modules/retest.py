#!/usr/bin/env python3
"""Retest ledger for remediation verification.

This records a tester's manual retest decision and evidence references. It does
not perform network requests or exploit actions.
"""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from pathlib import Path

RESULTS={"fixed","partially-fixed","still-present","inconclusive"}

def record(root: str|Path, finding_id: str, result: str, note: str="", evidence: list[str]|None=None, approved: bool=False):
    if not approved: raise PermissionError("Explicit operator approval is required for a retest record")
    result=result.lower().strip()
    if result not in RESULTS: raise ValueError("Invalid retest result")
    root=Path(root); path=root/"evidence"/"retest-ledger.json"; path.parent.mkdir(parents=True,exist_ok=True)
    entries=[]
    if path.exists():
        try: entries=json.loads(path.read_text(encoding="utf-8")); entries=entries if isinstance(entries,list) else []
        except json.JSONDecodeError: entries=[]
    entry={"retest_id":"RT-"+uuid.uuid4().hex[:10].upper(),"finding_id":finding_id,"result":result,"note":note.strip(),"evidence":list(evidence or []),"timestamp":datetime.now(timezone.utc).isoformat(),"execution":"manual-record-only"}
    entries.append(entry); path.write_text(json.dumps(entries,indent=2),encoding="utf-8")
    rp=root/"reports"/"retest-report.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    lines=["# Retest Report","","| Retest | Finding | Result | Timestamp |","|---|---|---|---|"]
    for x in entries: lines.append(f"| `{x['retest_id']}` | `{x['finding_id']}` | `{x['result']}` | `{x['timestamp']}` |")
    lines += ["","## Latest notes",""]
    for x in entries[-10:]:
        lines.append(f"- **{x['finding_id']}** — `{x['result']}` — {x.get('note') or 'No note'}")
    rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return entry,path
