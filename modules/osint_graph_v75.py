"""V75 OSINT entity graph and confidence-aware correlation."""
import json, re
from pathlib import Path

def build(outdir):
    outdir=Path(outdir); src=outdir/"evidence"/"osint-plan-v74.json"; data=json.loads(src.read_text()) if src.exists() else {}
    seed=data.get("seed","")
    nodes=[{"id":"seed","type":data.get("seed_type","entity"),"value":seed,"confidence":"high"}]
    for i,q in enumerate(data.get("search_pivots",[])):
        nodes.append({"id":f"pivot-{i+1}","type":"search_pivot","value":q,"confidence":"planning"})
    edges=[{"from":"seed","to":n["id"],"relationship":"investigation-pivot","status":"unverified"} for n in nodes[1:]]
    out={"version":"V75","nodes":nodes,"edges":edges,"correlation_rule":"independent-source confirmation required before high-confidence attribution","attribution":"never infer identity/ownership from a single weak signal"}
    p=outdir/"evidence"/"osint-graph-v75.json"; p.write_text(json.dumps(out,indent=2)); return p
