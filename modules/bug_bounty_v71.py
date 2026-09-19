"""V71 Bug Bounty Program Intelligence.
Scope-first planning for authorized bug-bounty programs; no exploitation.
"""
import json, re
from pathlib import Path

DEFAULT_RULES = {
    "allowed_testing": ["passive_recon", "in_scope_http", "safe_scanner_checks", "manual_validation"],
    "forbidden": ["credential_theft", "spam", "dos", "destructive_actions", "persistence", "lateral_movement", "data_exfiltration"],
    "requires_operator_approval": ["state_change", "authenticated_testing", "proof_of_impact", "submission"],
}

def _clean_host(s):
    return re.sub(r"^https?://", "", str(s).strip()).split("/")[0].lower().strip(".")

def build(outdir, program="", policy_file="", targets=None, exclusions=None):
    outdir = Path(outdir); (outdir/"evidence").mkdir(parents=True, exist_ok=True); (outdir/"reports").mkdir(parents=True, exist_ok=True)
    policy = dict(DEFAULT_RULES)
    if policy_file and Path(policy_file).exists():
        try: policy.update(json.loads(Path(policy_file).read_text()))
        except (OSError, json.JSONDecodeError, TypeError): pass
    data = {
        "version":"V71", "mode":"bug-bounty", "program":program or "unspecified",
        "targets":sorted({_clean_host(x) for x in (targets or []) if x}),
        "exclusions":sorted({_clean_host(x) for x in (exclusions or []) if x}),
        "rules":policy,
        "authorization_model":"program-policy-and-scope-first",
        "operator_approval_required":True,
        "workflow":["policy_ingest","scope_normalize","passive_discovery","in_scope_validation","safe_assessment","triage","evidence_review","report_draft","operator_submission"],
    }
    p=outdir/"evidence"/"bug-bounty-program-v71.json"; p.write_text(json.dumps(data,indent=2))
    (outdir/"reports"/"bug-bounty-program-v71.md").write_text("# Bug Bounty Program Intelligence\n\nProgram: %s\n\nScope-first workflow: %s\n\nSubmission and consequential testing remain operator-approved.\n"%(data["program"], " → ".join(data["workflow"])))
    return p
