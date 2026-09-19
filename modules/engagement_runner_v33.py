#!/usr/bin/env python3
"""Full authorized engagement runner (phase ledger + resume)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from modules.auth_assessment_v33 import build_role_matrix, write_session_bundle
from modules.evidence_graph_v33 import EvidenceGraph
from modules.false_positive_engine_v33 import reduce_outdir
from modules.operator_cockpit_v33 import build_cockpit
from modules.retest_closure_v33 import closure_checklist, init_retest_tracker
from modules.task_prioritizer import write_priority_queue


PHASES = [
    "preflight",
    "session",
    "recon_seed",
    "normalize",
    "service_intelligence",
    "fp_reduce",
    "prioritize",
    "auth_matrix",
    "graph",
    "cross_domain_paths",
    "auth_role_analysis",
    "cockpit",
    "retest_init",
    "report_draft",
    "closure",
    "remediation_tracking",
    "evidence_quality",
    "intelligence_fabric",
    "adaptive_next_steps",
    "continuous_snapshot",
    "report_pack",
    "asset_identity",
    "dependency_map",
    "authenticated_evidence",
    "attack_path_ranking",
    "coverage_gaps",
    "remediation_priority",
    "state_running",
    "v38_asset_context",
    "v38_multi_hop_paths",
    "v38_confidence_calibration",
    "v38_provenance_chain",
    "v38_remediation_dependencies",
    "v38_session_model",
    "v38_plugin_contract",
    "v38_coverage",
]


class EngagementRunner:
    def __init__(
        self,
        outdir: str | Path,
        target: str,
        *,
        authorized: bool = False,
        in_scope: bool = False,
        dry_run: bool = True,
        executor: Callable[[str, str, Path], dict[str, Any]] | None = None,
    ):
        self.root = Path(outdir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.target = target
        self.authorized = authorized
        self.in_scope = in_scope
        self.dry_run = dry_run
        self.executor = executor
        self.ledger_path = self.root / "evidence" / "engagement-ledger.json"
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger = self._load_ledger()

    def _load_ledger(self) -> dict[str, Any]:
        if self.ledger_path.exists():
            try:
                return json.loads(self.ledger_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {"target": self.target, "phases": {}, "updated_at": None}

    def _save_ledger(self) -> None:
        self.ledger["updated_at"] = time.time()
        tmp = self.ledger_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.ledger, indent=2), encoding="utf-8")
        tmp.replace(self.ledger_path)

    def _set_phase(self, name: str, status: str, **meta: Any) -> None:
        self.ledger["phases"][name] = {"status": status, "ts": time.time(), **meta}
        self._save_ledger()

    def run(self, resume: bool = True) -> dict[str, Any]:
        if not self.authorized or not self.in_scope:
            return {
                "status": "blocked",
                "reason": "engagement runner requires authorized=True and in_scope=True",
            }

        for phase in PHASES:
            prev = (self.ledger.get("phases") or {}).get(phase, {})
            if resume and prev.get("status") == "ok":
                continue
            try:
                result = self._run_phase(phase)
                self._set_phase(phase, "ok", result=result)
            except Exception as exc:  # noqa: BLE001
                self._set_phase(phase, "error", error=str(exc))
                return {
                    "status": "error",
                    "failed_phase": phase,
                    "error": str(exc),
                    "ledger": self.ledger,
                }

        return {"status": "ok", "target": self.target, "ledger": self.ledger, "dry_run": self.dry_run}

    def _run_phase(self, phase: str) -> Any:
        if phase == "preflight":
            return {"authorized": self.authorized, "in_scope": self.in_scope, "target": self.target}
        if phase == "session":
            return {"path": str(write_session_bundle(self.root))}
        if phase == "mission_plan":
            from modules.mission_planner_v34 import build
            return build(self.root, self.target, authorized=self.authorized)
        if phase == "recon_seed":
            # Seed host list; optional executor for real recon when not dry_run.
            recon = self.root / "recon"
            recon.mkdir(exist_ok=True)
            hosts = recon / "live-hosts.txt"
            if not hosts.exists():
                hosts.write_text(self.target + "\n", encoding="utf-8")
            if not self.dry_run and self.executor:
                for action in ("subdomain_enum", "http_probe", "port_scan"):
                    try:
                        self.executor(action, self.target, self.root)
                    except Exception as exc:  # noqa: BLE001
                        return {"seed": str(hosts), "executor_warning": str(exc)}
            return {"seed": str(hosts)}
        if phase == "normalize":
            # collect hosts into graph later
            return {"ok": True}
        if phase == "service_intelligence":
            from modules.service_protocol_intelligence_v35 import build
            return build(self.root)
        if phase == "fp_reduce":
            return reduce_outdir(self.root)
        if phase == "prioritize":
            path = write_priority_queue(self.root, self.target)
            return {"path": str(path)}
        if phase == "auth_matrix":
            return {"path": str(build_role_matrix(self.root))}
        if phase == "graph":
            g = EvidenceGraph(self.root)
            hosts = []
            p = self.root / "recon" / "live-hosts.txt"
            if p.exists():
                hosts = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
            g.ingest_hosts(hosts or [self.target])
            for rel in ["vulns/findings.normalized.json", "vulns/findings.json"]:
                fp = self.root / rel
                if not fp.exists():
                    continue
                try:
                    data = json.loads(fp.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    continue
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            g.ingest_finding(item, state=str(item.get("_state") or "observed"))
            path = g.save()
            return {"path": str(path), "summary": g.summary()}
        if phase == "cross_domain_paths":
            from modules.cross_domain_attack_paths_v35 import build
            return build(self.root)
        if phase == "auth_role_analysis":
            from modules.auth_role_analysis_v35 import build
            return build(self.root)
        if phase == "cockpit":
            return build_cockpit(self.root, self.target)
        if phase == "retest_init":
            return {"path": str(init_retest_tracker(self.root))}
        if phase == "report_draft":
            reports = self.root / "reports"
            reports.mkdir(exist_ok=True)
            draft = reports / "report-draft.md"
            gsum = EvidenceGraph(self.root).summary()
            draft.write_text(
                f"# Assessment Report Draft\n\nTarget: {self.target}\n\nGraph: {gsum}\n\nStatus: draft\n",
                encoding="utf-8",
            )
            return {"path": str(draft)}
        if phase == "closure":
            return closure_checklist(self.root)
        if phase == "remediation_tracking":
            from modules.remediation_tracking_v35 import build
            return build(self.root)
        if phase == "evidence_quality":
            from modules.evidence_quality_v34 import build
            return build(self.root)
        if phase == "intelligence_fabric":
            from modules.intelligence_fabric_v36 import build
            return build(self.root)
        if phase == "adaptive_next_steps":
            from modules.adaptive_next_steps_v36 import build
            return build(self.root)
        if phase == "continuous_snapshot":
            from modules.continuous_diff_v36 import snapshot
            return snapshot(self.root)
        if phase == "report_pack":
            from modules.report_pack_v34 import build
            return build(self.root, self.target)
        if phase == "asset_identity":
            from modules.assessment_intelligence_v37 import asset_identity
            return asset_identity(self.root)
        if phase == "dependency_map":
            from modules.assessment_intelligence_v37 import dependency_map
            return dependency_map(self.root)
        if phase == "authenticated_evidence":
            from modules.assessment_intelligence_v37 import normalize_authenticated
            return normalize_authenticated(self.root)
        if phase == "attack_path_ranking":
            from modules.assessment_intelligence_v37 import rank_attack_paths
            return rank_attack_paths(self.root)
        if phase == "coverage_gaps":
            from modules.assessment_intelligence_v37 import coverage_gaps
            return coverage_gaps(self.root)
        if phase == "remediation_priority":
            from modules.assessment_intelligence_v37 import remediation_priority
            return remediation_priority(self.root)
        if phase == "state_running":
            from modules.assessment_intelligence_v37 import engagement_state
            return engagement_state(self.root, "running")
        if phase == "v38_asset_context":
            from modules.intelligence_fabric_v38 import asset_context
            return asset_context(self.root)
        if phase == "v38_multi_hop_paths":
            from modules.intelligence_fabric_v38 import multi_hop_paths
            return multi_hop_paths(self.root)
        if phase == "v38_confidence_calibration":
            from modules.intelligence_fabric_v38 import calibrate_findings
            return calibrate_findings(self.root)
        if phase == "v38_provenance_chain":
            from modules.intelligence_fabric_v38 import provenance_chain
            return provenance_chain(self.root)
        if phase == "v38_remediation_dependencies":
            from modules.intelligence_fabric_v38 import remediation_dependencies
            return remediation_dependencies(self.root)
        if phase == "v38_session_model":
            from modules.intelligence_fabric_v38 import session_model
            return session_model(self.root)
        if phase == "v38_plugin_contract":
            from modules.intelligence_fabric_v38 import plugin_contract
            return plugin_contract(self.root)
        if phase == "v38_coverage":
            from modules.intelligence_fabric_v38 import coverage
            return coverage(self.root)
        raise ValueError(f"unknown phase {phase}")
