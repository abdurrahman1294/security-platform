"""V77 Security Brain: deterministic, auditable routing across platform capabilities."""
from pathlib import Path
import json

CAPABILITIES = {
    "pentest": ["recon","pipeline","web_api","authz","session","api","business_logic","infra","cloud","ad","evidence","reporting"],
    "bugbounty": ["program_policy","passive_discovery","safe_assessment","triage","evidence","reporting"],
    "osint": ["public_sources","search_pivots","entity_graph","correlation","confidence"],
    "auto": ["pentest","bugbounty","osint"],
}

def _artifact_inventory(outdir):
    outdir=Path(outdir); items=[]
    for root in (outdir/"evidence", outdir/"reports"):
        if root.exists():
            for p in root.rglob("*"):
                if p.is_file(): items.append(str(p.relative_to(outdir)))
    return sorted(items)

def build(outdir, mode, target, objective="general"):
    outdir=Path(outdir); (outdir/"evidence").mkdir(parents=True,exist_ok=True); (outdir/"reports").mkdir(parents=True,exist_ok=True)
    mode=mode.lower(); caps=CAPABILITIES.get(mode, CAPABILITIES["auto"])
    data={"version":"V77","component":"security-brain","mode":mode,"target":target,"objective":objective,
          "capabilities":caps,"artifact_count":len(_artifact_inventory(outdir)),
          "decision_model":"deterministic-evidence-aware-routing","human_approval_required":True,
          "forbidden_autonomy":["credential_theft","persistence","lateral_movement","exfiltration","destructive_actions","unrestricted_exploitation"]}
    p=outdir/"evidence"/"security-brain-v77.json"; p.write_text(json.dumps(data,indent=2))
    (outdir/"reports"/"security-brain-v77.md").write_text("# Security Brain\n\nMode: `%s`\nTarget: `%s`\nObjective: `%s`\n\nThe brain routes work between registered assessment capabilities using auditable rules. Consequential actions remain operator-approved.\n"%(mode,target,objective))
    return p
