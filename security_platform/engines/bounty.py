from __future__ import annotations
from security_platform.core.engagement import Engagement
from modules.bug_bounty_program_v238 import build as policy
from modules.bug_bounty_planner_v239 import build as plan
from modules.bug_bounty_quality_v240 import build as quality
from modules.research_exhaustion_v241 import build as exhaustion
from modules.atomic_io import load_json
from pathlib import Path

class BugBountyEngine:
    name="bounty"
    def __init__(self, engagement: Engagement): self.e=engagement
    def intelligence(self, program_name="", policy_file="", assets=(), execute=False, authorized=False):
        assets=list(assets)
        # Candidate assets must never expand the authoritative program scope.
        # The policy file remains the source of truth for active bounty work.
        p=policy(self.e.output,program_name,policy_file,assets)
        plan(self.e.output,self.e.target); q=quality(self.e.output); exhaustion(self.e.output,self.e.target)
        # Active execution remains a separate, explicit path. The policy module
        # and the global authorization gate must both approve it.
        execution = {"requested": bool(execute), "started": False}
        if execute:
            from modules.security import require_authorization
            policy_data = load_json(self.e.output / "evidence" / "bug-bounty-program-v238.json", {})
            rules = policy_data.get("rules", {}) if isinstance(policy_data, dict) else {}
            program_scope = rules.get("scope", []) if isinstance(rules, dict) else []
            forbidden = rules.get("forbidden", []) if isinstance(rules, dict) else []
            exclusions = rules.get("exclusions", []) if isinstance(rules, dict) else []
            from modules.security import in_scope
            if not program_scope:
                execution["blocked_reason"] = "program-scope-empty"
                return {"engine":"bounty","program":program_name,"policy_loaded":p.get("policy_loaded",False),"quality_decision":q.get("decision"),"execution":execution}
            if not p.get("policy_loaded"):
                execution["blocked_reason"] = "program-policy-not-loaded"
                return {"engine":"bounty","program":program_name,"policy_loaded":False,"quality_decision":q.get("decision"),"execution":execution}
            if not in_scope(self.e.target, program_scope) or in_scope(self.e.target, exclusions):
                execution["blocked_reason"] = "target-not-in-program-scope"
                return {"engine":"bounty","program":program_name,"policy_loaded":True,"quality_decision":q.get("decision"),"execution":execution}
            allowed_testing = rules.get("allowed_testing", [])
            if isinstance(allowed_testing, str):
                allowed_testing = [allowed_testing]
            if not isinstance(allowed_testing, list) or not allowed_testing:
                execution["blocked_reason"] = "active-testing-permission-not-explicit"
                return {"engine":"bounty","program":program_name,"policy_loaded":True,"quality_decision":q.get("decision"),"execution":execution}
            forbidden_text = " ".join(str(x).lower() for x in forbidden) if isinstance(forbidden, list) else str(forbidden).lower()
            phases = ["recon", "probe", "ports", "web", "api", "authenticated", "intelligence", "final"]
            allowed_text = " ".join(str(x).lower() for x in allowed_testing)
            phase_aliases = {
                "recon": ("recon", "reconnaissance", "discovery"),
                "probe": ("probe", "http", "web"),
                "ports": ("ports", "port scanning", "port scan"),
                "web": ("web", "vulnerability scanning", "automated scanning", "scanner"),
                "api": ("api", "api testing"),
                "authenticated": ("authenticated", "authenticated testing", "auth"),
                "intelligence": ("triage", "analysis", "intelligence"),
                "final": ("report", "reporting", "submission preparation"),
            }
            selected = []
            for phase in phases:
                aliases = phase_aliases[phase]
                if any(a in allowed_text for a in aliases) and not any(a in forbidden_text for a in aliases):
                    selected.append(phase)
            if not selected:
                execution["blocked_reason"] = "policy-does-not-permit-supported-active-phases"
                return {"engine":"bounty","program":program_name,"policy_loaded":True,"quality_decision":q.get("decision"),"execution":execution}
            # Materialize the authoritative program scope as the only scope used
            # by the delegated pentest engine. Candidate assets never enter it.
            scope_path = self.e.output / "evidence" / "bounty-policy-scope.txt"
            scope_path.write_text("\n".join(program_scope) + "\n", encoding="utf-8")
            from security_platform.core.policy import ScopePolicy
            from security_platform.engines.pentest import PentestEngine
            scoped_policy = ScopePolicy.from_file(scope_path, self.e.target)
            if not authorized:
                require_authorization()
            delegated = PentestEngine(self.e, scoped_policy).run(tuple(selected), require_authorization=False)
            execution["started"] = True
            execution["delegated_pentest"] = {"status": delegated.get("status"), "phases": selected}
        return {"engine":"bounty","program":program_name,"policy_loaded":p.get("policy_loaded",False),"quality_decision":q.get("decision"),"execution":execution}
