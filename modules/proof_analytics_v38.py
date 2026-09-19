#!/usr/bin/env python3
"""V38 proof coverage and outcome analytics."""
from __future__ import annotations
import json
from .atomic_io import load_json
from pathlib import Path
from collections import Counter
from modules.exploit_adapter_v33 import REGISTRY
import modules.exploit_adapters_v33, modules.exploit_adapters_v36


def build(root: str|Path):
    root=Path(root)
    p=root/"evidence"/"proof-execution-ledger.json"
    rows=[]
    if p.exists():
        rows=load_json(p, [])
    rows=rows if isinstance(rows,list) else []
    adapter_counts=Counter(r.get("adapter_id") for r in rows)
    result_counts=Counter(r.get("result") for r in rows)
    registered=REGISTRY.list()
    report={"schema_version":"38.0", "registered_adapter_count":len(registered),
            "registered_adapters":[s["adapter_id"] for s in registered],
            "executions":len(rows), "executions_by_adapter":dict(adapter_counts),
            "results":dict(result_counts),
            "coverage": {"registered_with_execution": sum(1 for s in registered if s["adapter_id"] in adapter_counts),
                         "registered_without_execution": sum(1 for s in registered if s["adapter_id"] not in adapter_counts)}}
    ep=root/"evidence"/"proof-analytics-v38.json"; ep.parent.mkdir(parents=True,exist_ok=True); ep.write_text(json.dumps(report,indent=2),encoding="utf-8")
    rp=root/"reports"/"proof-analytics-v38.md"; rp.parent.mkdir(parents=True,exist_ok=True)
    lines=["# Proof Coverage & Validation Analytics (V38)","",f"- Registered adapters: **{report['registered_adapter_count']}**",f"- Guarded proof executions: **{report['executions']}**",f"- Adapters exercised: **{report['coverage']['registered_with_execution']}**",f"- Adapters not yet exercised: **{report['coverage']['registered_without_execution']}**","","## Results"]
    for k,v in sorted(result_counts.items()): lines.append(f"- `{k}`: {v}")
    rp.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return ep
