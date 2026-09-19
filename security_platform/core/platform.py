"""Top-level coordinator for the specialist security engines.

The platform coordinates; specialist engines own methodology. Handoffs are
untrusted data and never confer authorization or expand scope.
"""
from __future__ import annotations
from pathlib import Path
from typing import Iterable
from .engagement import Engagement
from .registry import all_specs, get
from .artifacts import write_json
from .preflight import check

class SecurityPlatform:
    def __init__(self, engagement: Engagement):
        self.engagement = engagement

    def catalog(self):
        return [{
            "name": s.name, "description": s.description, "active": s.active,
            "version": s.version, "capabilities": list(s.capabilities)
        } for s in all_specs()]

    def toolchain(self):
        from .tools import inventory
        return [x.__dict__ for x in inventory()]

    def write_manifest(self):
        manifest = {
            "schema_version": "platform-3.8",
            "client": self.engagement.client,
            "target": self.engagement.target,
            "engines": self.catalog(),
            "principles": [
                "specialist engines are independently executable",
                "shared core owns common infrastructure, not methodology",
                "cross-engine handoffs are structured and untrusted",
                "consuming engines re-apply authorization and scope",
                "privacy hygiene minimizes accidental operator-data disclosure without defeating accountability",
                "no engine can grant another engine permission to act",
                "adaptive assessment reasons from observed evidence without expanding scope or authority",
                "V3.8 intelligence fabric produces hypotheses and triage context; it never grants authority",
                "V3.11 superior capability fabric composes specialist evidence without inheriting specialist authority",
                "V3.12 adaptive controller selects the next specialist from evidence and replans after each result",
                "V3.12 capability fusion prefers composed workflows over isolated scanner output",
                "V3.13 governed mission execution requires authorization, scope, and exact-action single-use approval",
                "V3.13 workflow coverage distinguishes implemented composition from external specialist capabilities",
                "V3.14 adds nonlinear branch search, persistent clue graphs, exposure/control verdicts, continuous revalidation, and remediation-retest loops",
                "V3.16 adds governed embedded/IoT/OT/ICS/automotive/hardware/network-device security composition",
                "V3.17 adds remote endpoint/mobile assessment plus advanced firmware, reverse-engineering, fuzzing, digital-twin and physical-interface correlation",
                "V3.18 adds governed specialist execution adapters, explicit remote file-access evidence contracts, and cellular-network assessment perspectives",
                "V3.19 makes cellular origin a universal assessment perspective across every specialist domain with bounded external probe contracts",
                "V3.20 adds a universal attack-surface taxonomy, multi-perspective assessment matrix, security-factor graph, and governed functional execution plan",
                "V3.21 adds functional bounded R0-R2 execution across registered adapters with complete coverage accounting and perspective-aware reachability",
                "V3.24 adds universal assessment intelligence: cross-domain correlation, evidence quality, state/staleness, competing hypotheses, exposure-to-impact chains, attack-path ranking, remediation/retest, detection validation, mission planning, and professional reporting",
                "V3.30 unifies assessment state and evidence-driven lifecycle planning",
                "V3.31 hardens execution with transactional state, recovery, budgets, atomic artifacts, and invariants",
                "V3.32 measures actual coverage and explicit capability gaps across surfaces and perspectives",
                "V3.33 separates candidate, observed, supported, validated, and impact-validated claims",
                "V3.34 generates evidence-faithful professional reporting without fabricating conclusions",
                "V3.35 audits the engine source tree for unsafe execution and secret-like literals without touching targets",
                "V3.37 unifies specialist adapters under a canonical governed assessment lifecycle",
                "V3.38 adds a broad bounded web/API assurance corpus",
                "V3.39 adds bounded fuzz-campaign planning and crash-triage metadata",
                "V3.40 adds durable local engagement indexing and assessment analytics",
                "V3.41 adds identity protocol assurance without secret collection or credential spraying",
                "V3.42 closes the capability taxonomy with concrete governed contracts and deterministic lab envelopes for dangerous behaviors",
                "V3.49 adds an end-to-end local range assurance gate with regression baselines and specialist-tool readiness reporting",
                "V3.50 adds specialist conformance auditing across the complete multi-target domain matrix without adding a generic execution path",
                "V3.54 adds disposable isolated specialist targets across 16 domains with interface-first discovery, hidden ground truth, and end-to-end accounting",
                "V3.57 adds canonical SQLite engagement reasoning state and deterministic replanning",
                "V3.60 closes the autonomous-control-plane gaps with task convergence, single-owner leases, scope/authorization-bound receipts, final capability closure, and provider-independent reasoning seams",
                "V3.61 adds evidence-ranked exploitation assurance, differential proof planning, exploit-candidate graphs, and convergence-ready technique selection behind existing approval and scope gates",
                "V3.62 adds a deterministic exploitation loop, broader exploit-class reasoning, source/dynamic correlation, branch convergence, and local benchmark scoring without bypassing execution governance",
                "V3.67 adds persistent conversational security workspace, autonomous attack-path intelligence, case-based rare-case reasoning, competing hypotheses, and novel hypothesis generation without granting execution authority",
                "V5.0 fuses documented HexStrike/PentestGPT capabilities through an original governed control plane: large tool catalog, specialist agents, adaptive selection, durable task leases, provider routing, MCP inspection/planning, coverage convergence, and failure-recovery contracts",
            ],
        }
        return write_json(self.engagement.output, "platform-manifest.json", manifest)

    def maturity(self) -> dict:
        from modules.operational_maturity_v26 import artifact_inventory, correlate, coverage, health
        from modules.expert_capability_audit_v27 import build as capability_audit
        from .tools import inventory
        tools = [x.__dict__ for x in inventory()]
        return {
            "schema_version": "3.7",
            "health": health(self.engagement.output, tool_inventory=tools),
            "coverage": coverage(self.engagement.output),
            "correlation": correlate(self.engagement.output),
            "artifacts": artifact_inventory(self.engagement.output),
            "capability_audit": capability_audit(self.engagement.output, tool_inventory=tools),
            "adaptive_assessment": self.adaptive_assessment(),
            "adaptive_investigation": self.adaptive_investigation(),
            "mission_plan": self.mission_plan(),
            "intelligence_v37": self.intelligence_v37(),
            "intelligence_v38": self.intelligence_v38(),
            "superior_capability_fabric_v311": self.superior_capability_fabric(),
            "governed_mission_fabric_v313": self.governed_mission_fabric(),
            "exposure_validation_fabric_v314": self.exposure_validation_fabric(),
            "specialist_domain_fabric_v315": self.specialist_domain_fabric(),
            "embedded_ot_automotive_fabric_v316": self.embedded_ot_automotive_fabric(),
            "remote_endpoint_advanced_fabric_v317": self.remote_endpoint_advanced_fabric(),
            "remote_execution_cellular_fabric_v318": self.remote_execution_cellular_fabric(),
            "cellular_universal_fabric_v319": self.cellular_universal_fabric(),
            "universal_attack_surface_fabric_v320": self.universal_attack_surface_fabric(),
            "universal_assessment_intelligence_v324": self.universal_assessment_intelligence(),
            "universal_coverage_assurance_v332": self.universal_coverage_assurance(),
            "validation_assurance_v333": self.validation_assurance(),
            "evidence_reporting_v334": self.evidence_reporting(),
            "engine_self_security_v335": self.engine_self_security(),
            "capability_benchmark_v336": self.capability_benchmark(),
            "capability_closure_v342": self.capability_closure(),
            "complete_testing_lab_v343": self.complete_testing_lab(),
            "multi_target_integration_v348": self.multi_target_campaign(),
            "range_assurance_gate_v349": self.range_assurance_gate(),
            "specialist_conformance_v350": self.specialist_conformance(),
            "specialist_isolated_range_v354": self.specialist_isolated_range(),
            "final_engine_closure_v360": self.final_engine_closure(objective="final-engine"),
            "exploitation_loop_v362": self.exploitation_loop_v362(),
            "capability_fusion_v500": self.capability_fusion_v500(),
        }

    def capability_fusion_v500(self, *, objective: str = "full-assessment", authorized: bool = False) -> dict:
        """Expose the V5.0 capability fusion/control plane through the core platform."""
        from modules.ai_capability_fusion_v500 import FusionEngine
        return FusionEngine(self.engagement.output).build(
            self.engagement.target, objective, authorized=authorized
        )

    def mcp_bridge_v500(self):
        """Return the governed MCP-compatible inspection/planning bridge."""
        from modules.ai_capability_fusion_v500 import FusionEngine, MCPBridge
        return MCPBridge(FusionEngine(self.engagement.output))

    def exploitation_loop_v362(self) -> dict:
        from modules.exploitation_loop_v362 import build_loop
        import json
        findings_path = self.engagement.output / "evidence" / "normalized-findings.json"
        if findings_path.is_file():
            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
                if isinstance(findings, dict): findings = findings.get("findings", [])
                if not isinstance(findings, list): findings = []
            except Exception:
                findings = []
        else:
            findings = []
        return build_loop(findings)

    def adaptive_investigation(self, *, authorized: bool = False, max_iterations: int = 1) -> dict:
        from modules.adaptive_investigation_v29 import build
        return build(self.engagement.output, target=self.engagement.target,
                     scope=str(self.engagement.scope_file), authorized=authorized,
                     max_iterations=max_iterations)

    def adaptive_assessment(self, *, authorized: bool = False) -> dict:
        from modules.adaptive_assessment_v28 import build
        return build(self.engagement.output, target=self.engagement.target,
                     scope=str(self.engagement.scope_file), authorized=authorized)


    def mission_plan(self, *, authorized: bool = False) -> dict:
        from modules.mission_planner_v34 import build
        return build(self.engagement.output, self.engagement.target, authorized=authorized)

    def intelligence_v37(self) -> dict:
        from modules.assessment_intelligence_v37 import asset_identity, dependency_map, normalize_authenticated, rank_attack_paths, coverage_gaps, remediation_priority
        asset_identity(self.engagement.output)
        dependency_map(self.engagement.output)
        normalize_authenticated(self.engagement.output)
        rank_attack_paths(self.engagement.output)
        coverage_gaps(self.engagement.output)
        return remediation_priority(self.engagement.output)


    def intelligence_v38(self) -> dict:
        from modules.engagement_orchestration_v38 import build
        return build(self.engagement.output)

    def adaptive_mission(self, *, objective: str = "general", authorized: bool = False, max_steps: int = 12) -> dict:
        from modules.adaptive_mission_controller_v312 import build_adaptive_mission
        return build_adaptive_mission(self.engagement.output, self.engagement.target, objective, max_steps, authorized)

    def capability_fusion(self) -> dict:
        from modules.adaptive_mission_controller_v312 import build_capability_fusion_matrix
        return build_capability_fusion_matrix(self.engagement.output)

    def governed_mission_fabric(self, *, objective: str = "general", max_steps: int = 8) -> dict:
        from modules.governed_mission_fabric_v313 import build_workflow_coverage, build_governed_execution_plan
        return {
            "workflow_coverage": build_workflow_coverage(self.engagement.output),
            "execution_plan": build_governed_execution_plan(self.engagement.output, self.engagement.target, objective, max_steps),
        }

    def exposure_validation_fabric(self, *, objective: str = "general") -> dict:
        from modules.exposure_validation_fabric_v314 import build_v314_fabric
        return build_v314_fabric(self.engagement.output, self.engagement.target, objective)

    def specialist_domain_fabric(self, *, objective: str = "general", observations=None) -> dict:
        from modules.specialist_domain_fabric_v315 import build_v315_fabric
        return build_v315_fabric(self.engagement.output, self.engagement.target, objective, observations or [])

    def embedded_ot_automotive_fabric(self, *, objective: str = "general") -> dict:
        from modules.embedded_ot_automotive_fabric_v316 import build_v316_fabric
        return build_v316_fabric(self.engagement.output, self.engagement.target, objective)

    def remote_endpoint_advanced_fabric(self, *, objective: str = "full-assessment", platform: str = "auto", artifact: str = "") -> dict:
        from modules.remote_endpoint_and_advanced_fabric_v317 import build_v317_fabric
        return build_v317_fabric(self.engagement.output, self.engagement.target, objective, platform, artifact)

    def remote_execution_cellular_fabric(self, *, objective: str = "full-assessment", platform: str = "auto", artifact: str = "", approved_paths=(), write_probe: bool = False) -> dict:
        from modules.remote_endpoint_and_advanced_fabric_v318 import build_v318_fabric
        return build_v318_fabric(self.engagement.output, self.engagement.target, objective, platform, artifact, approved_paths, write_probe)

    def cellular_universal_fabric(self, *, objective: str = "full-cellular-perspective", approved_ports=(), approved_urls=()) -> dict:
        from modules.cellular_universal_fabric_v319 import build_v319_fabric
        return build_v319_fabric(self.engagement.output, self.engagement.target, objective, approved_ports, approved_urls)

    def universal_attack_surface_fabric(self, *, perspective: str = "internet_ipv4", authorized: bool = False, observed=None, requested_surfaces=None) -> dict:
        from modules.universal_attack_surface_fabric_v320 import build_v320_fabric
        return build_v320_fabric(self.engagement.output, target=self.engagement.target, perspective=perspective, authorized=authorized, observed=observed or [], requested_surfaces=requested_surfaces)

    def universal_specialist_router(self, *, perspective: str = "internet_ipv4", objective: str = "full-assessment", authorized: bool = False, execute: bool = False, requested_surfaces=None, max_steps: int = 12, timeout: int = 600) -> dict:
        from modules.universal_specialist_router_v322 import execute_universal_router
        return execute_universal_router(self.engagement.output, target=self.engagement.target, scope_file=self.engagement.scope_file, perspective=perspective, authorized=authorized, execute=execute, surfaces=requested_surfaces, max_steps=max_steps, timeout=timeout, objective=objective)

    def r4_capability_matrix(self, *, surfaces=None) -> dict:
        from modules.universal_specialist_router_v322 import build_r4_capability_matrix
        return build_r4_capability_matrix(self.engagement.output, target=self.engagement.target, surfaces=surfaces)

    def universal_execution_graph(self, *, objective: str = "full-assessment", perspective: str = "internet_ipv4", observations=None, requested_surfaces=None, completed=None, failed=None, max_candidates: int = 12) -> dict:
        from modules.universal_execution_graph_v323 import build_execution_graph
        return build_execution_graph(self.engagement.output, target=self.engagement.target, observations=observations or [], surfaces=requested_surfaces, perspectives=[perspective], completed=completed or [], failed=failed or [], objective=objective, max_candidates=max_candidates)

    def universal_assessment_intelligence(self, *, objective: str = "full-assessment", observations=None, baseline=None, max_paths: int = 12) -> dict:
        from modules.universal_assessment_intelligence_v324 import build_v324_fabric
        return build_v324_fabric(self.engagement.output, target=self.engagement.target, observations=observations or [], baseline=baseline, objective=objective, max_paths=max_paths)

    def adversarial_self_assessment(self, *, objective: str = "full-self-assessment", assets=None, observations=None) -> dict:
        from modules.adversarial_self_assessment_v326 import build_chain_analysis
        return build_chain_analysis(self.engagement.output, target=self.engagement.target, assets=assets, observations=observations, objective=objective)

    def adversarial_deep_reasoning(self, *, objective: str = "full-self-assessment", assets=None, observations=None) -> dict:
        from modules.adversarial_reasoning_v327 import build_deep_reasoning
        from modules.adversarial_self_assessment_v326 import default_personal_surface, build_asset_dependency_graph
        normalized = assets if assets is not None else default_personal_surface()
        graph = build_asset_dependency_graph(normalized)
        return build_deep_reasoning(self.engagement.output, target=self.engagement.target, assets=normalized, observations=observations or [], dependency_graph=graph, objective=objective)

    def adversarial_reasoning_suite(self) -> dict:
        from modules.adversarial_reasoning_v327 import adversarial_reasoning_test_suite
        return adversarial_reasoning_test_suite()

    def assessment_intelligence(self, *, objective: str = "full-assessment", observations=None, baseline=None, max_paths: int = 12) -> dict:
        from modules.universal_assessment_intelligence_v324 import build_v324_fabric
        return build_v324_fabric(self.engagement.output, target=self.engagement.target, observations=observations or [], baseline=baseline, objective=objective, max_paths=max_paths)

    def universal_assessment(self, *, perspective: str = "internet_ipv4", authorized: bool = False, execute: bool = False, requested_surfaces=None, max_steps: int = 12, timeout: int = 600) -> dict:
        from modules.universal_assessment_runner_v321 import execute_universal_assessment
        return execute_universal_assessment(self.engagement.output, target=self.engagement.target, scope_file=self.engagement.scope_file, perspective=perspective, authorized=authorized, execute=execute, surfaces=requested_surfaces, max_steps=max_steps, timeout=timeout)

    def superior_capability_fabric(self, *, objective: str = "general") -> dict:
        from modules.superior_capability_fabric_v311 import build_agentic_plan, build_model_routing_plan, build_continuous_assurance, build_benchmark_metrics
        return {
            "agentic_plan": build_agentic_plan(self.engagement.output, self.engagement.target, objective),
            "model_routing": build_model_routing_plan(self.engagement.output, objective),
            "continuous_assurance": build_continuous_assurance(self.engagement.output),
            "benchmark_metrics": build_benchmark_metrics(self.engagement.output),
            "adaptive_mission_v312": self.adaptive_mission(objective=objective),
            "capability_fusion_v312": self.capability_fusion(),
        }

    def temporal_digital_twin(self, *, objective: str = "temporal-self-assessment", assets=None, chains=None, timeline=None) -> dict:
        from modules.temporal_digital_twin_v328 import build_v328_fabric
        if assets is None:
            from modules.adversarial_self_assessment_v326 import default_personal_surface
            assets = default_personal_surface()
        return build_v328_fabric(self.engagement.output, target=self.engagement.target, assets=assets, chains=chains or [], timeline=timeline or [], objective=objective)

    def payload_assurance_catalog(self) -> list[dict]:
        from modules.temporal_digital_twin_v328 import payload_assurance_catalog
        return payload_assurance_catalog()

    def adversary_simulation(self, *, objective: str = "unified-authorized-adversary-simulation", assets=None, observations=None, chains=None, timeline=None, perspective: str = "internet_ipv4", perspectives=None, authorized: bool = False, execute: bool = False, scope_locked: bool = True, authorization_current=None, max_hypotheses: int = 20) -> dict:
        from modules.adversary_simulation_planner_v329 import build_v329_fabric
        if assets is None:
            from modules.adversarial_self_assessment_v326 import default_personal_surface
            assets = default_personal_surface()
        return build_v329_fabric(self.engagement.output, target=self.engagement.target, assets=assets, observations=observations or [], chains=chains or [], timeline=timeline or [], perspective=perspective, perspectives=perspectives, objective=objective, authorized=authorized, execute=execute, scope_locked=scope_locked, authorization_current=authorization_current, max_hypotheses=max_hypotheses)

    def adversary_simulation_suite(self) -> dict:
        from modules.adversary_simulation_planner_v329 import v329_test_matrix
        return v329_test_matrix()

    def unified_assessment_execution(self, *, objective: str = "full-assessment", assets=None, evidence=None, hypotheses=None, perspectives=None, timeline=None, capabilities=None, completed=None, failures=None, remediation=None, authorized: bool = False, execute: bool = False, scope_locked: bool = True, authorization_current=None, max_steps: int = 12) -> dict:
        from modules.unified_assessment_execution_fabric_v330 import build_v330_fabric
        return build_v330_fabric(self.engagement.output, target=self.engagement.target, objective=objective, assets=assets, evidence=evidence, hypotheses=hypotheses, perspectives=perspectives, timeline=timeline, capabilities=capabilities, completed=completed, failures=failures, remediation=remediation, authorized=authorized, execute=execute, scope_locked=scope_locked, authorization_current=authorization_current, max_steps=max_steps)

    def unified_assessment_execution_suite(self) -> dict:
        from modules.unified_assessment_execution_fabric_v330 import v330_test_matrix
        return v330_test_matrix()

    def reliability_execution_integrity(self, *, objective: str = "full-assessment", canonical_state=None, authorized: bool = False, execute: bool = False, scope_locked: bool = True, authorization_current=None, max_steps: int = 12, deadline_seconds: float = 600, tool_budget: int = 100, concurrency: int = 1, operations=None, failures=None) -> dict:
        from modules.reliability_execution_integrity_v331 import build_v331_fabric
        return build_v331_fabric(self.engagement.output, target=self.engagement.target, objective=objective, canonical_state=canonical_state, authorized=authorized, execute=execute, scope_locked=scope_locked, authorization_current=authorization_current, max_steps=max_steps, deadline_seconds=deadline_seconds, tool_budget=tool_budget, concurrency=concurrency, operations=operations, failures=failures)

    def reliability_execution_integrity_suite(self) -> dict:
        from modules.reliability_execution_integrity_v331 import v331_test_matrix
        return v331_test_matrix()

    def universal_coverage_assurance(self, *, objective: str = "full-assessment", surfaces=None, perspectives=None, observations=None, completed=None) -> dict:
        from modules.universal_coverage_assurance_v332 import build_v332_fabric
        return build_v332_fabric(self.engagement.output, target=self.engagement.target, objective=objective, surfaces=surfaces, perspectives=perspectives, observations=observations, completed=completed)

    def universal_coverage_assurance_suite(self) -> dict:
        from modules.universal_coverage_assurance_v332 import v332_test_matrix
        return v332_test_matrix()

    def validation_assurance(self, *, objective: str = "full-assessment", claims=None, evidence=None) -> dict:
        from modules.validation_assurance_fabric_v333 import build_v333_fabric
        return build_v333_fabric(self.engagement.output, target=self.engagement.target, objective=objective, claims=claims, evidence=evidence)

    def validation_assurance_suite(self) -> dict:
        from modules.validation_assurance_fabric_v333 import v333_test_matrix
        return v333_test_matrix()

    def evidence_reporting(self, *, objective: str = "full-assessment", claims=None, evidence=None, remediation=None, retests=None, coverage=None, validation=None, timeline=None) -> dict:
        from modules.evidence_reporting_fabric_v334 import build_v334_fabric
        return build_v334_fabric(self.engagement.output, target=self.engagement.target, objective=objective, claims=claims, evidence=evidence, remediation=remediation, retests=retests, coverage=coverage, validation=validation, timeline=timeline)

    def evidence_reporting_suite(self) -> dict:
        from modules.evidence_reporting_fabric_v334 import v334_test_matrix
        return v334_test_matrix()

    def engine_self_security(self, *, repo_root=None, include_tests: bool = True) -> dict:
        from modules.engine_self_security_v335 import build_v335_fabric
        return build_v335_fabric(self.engagement.output, repo_root=repo_root, include_tests=include_tests)

    def engine_self_security_suite(self) -> dict:
        from modules.engine_self_security_v335 import v335_test_matrix
        return v335_test_matrix()

    def capability_benchmark(self, *, objective: str = "professional-capability-benchmark") -> dict:
        from modules.capability_benchmark_v336 import build_v336_fabric
        return build_v336_fabric(self.engagement.output, objective=objective)

    def capability_benchmark_suite(self) -> dict:
        from modules.capability_benchmark_v336 import v336_test_matrix
        return v336_test_matrix()

    def unified_specialist_adapters(self, *, objective: str = "full-assessment") -> dict:
        from modules.unified_specialist_adapter_fabric_v337 import build_v337_fabric
        from modules.capability_runtime_v325 import capability_catalog
        return build_v337_fabric(self.engagement.output, capabilities=capability_catalog(), target=self.engagement.target, objective=objective)

    def web_api_assurance(self, *, objective: str = "web-api-assurance", endpoints=None) -> dict:
        from modules.web_api_assurance_v338 import build_v338_fabric
        return build_v338_fabric(self.engagement.output, target=self.engagement.target, endpoints=endpoints, objective=objective)

    def fuzz_campaign_fabric(self, *, campaigns=None) -> dict:
        from modules.fuzz_campaign_fabric_v339 import build_v339_fabric
        return build_v339_fabric(self.engagement.output, target=self.engagement.target, campaigns=campaigns)

    def engagement_datastore(self, *, artifacts=None) -> dict:
        from modules.engagement_datastore_v340 import index_engagement
        return index_engagement(self.engagement.output, client=self.engagement.client, target=self.engagement.target, artifacts=artifacts)

    def identity_assurance(self, *, identities=None) -> dict:
        from modules.identity_assurance_v341 import build_v341_fabric
        return build_v341_fabric(self.engagement.output, target=self.engagement.target, identities=identities)

    def final_engine_closure(self, *, objective: str = "final-engine") -> dict:
        from modules.final_capability_closure_v360 import build_final_closure
        import hashlib
        scope_hash = hashlib.sha256(Path(self.engagement.scope_file).read_bytes()).hexdigest() if Path(self.engagement.scope_file).is_file() else "missing-scope"
        authorization_epoch = hashlib.sha256(f"{self.engagement.client}|{self.engagement.target}|{scope_hash}".encode()).hexdigest()
        return build_final_closure(self.engagement.output, target=self.engagement.target, scope_hash=scope_hash, authorization_epoch=authorization_epoch, objective=objective)

    def capability_closure(self, *, objective: str = "full-capability-closure") -> dict:
        from modules.capability_closure_fabric_v342 import build_v342_fabric
        return build_v342_fabric(self.engagement.output, target=self.engagement.target, objective=objective)

    def integration_validation_range(self) -> dict:
        from modules.integration_validation_range_v345 import build_range
        return build_range(self.engagement.output)

    def integration_validation_campaign(self) -> dict:
        from modules.integration_validation_range_v345 import run_integration_range
        return run_integration_range(self.engagement.output)

    def campaign_quality(self, report=None) -> dict:
        from modules.campaign_quality_resilience_v346 import build_quality_artifact
        if report is None:
            from modules.integration_validation_range_v345 import run_integration_range
            report = run_integration_range(self.engagement.output)
        return build_quality_artifact(self.engagement.output, report)

    def campaign_resilience(self) -> dict:
        from modules.campaign_resilience_v347 import run_resilience_checks
        return run_resilience_checks(self.engagement.output)

    def multi_target_integration(self) -> dict:
        from modules.multi_target_integration_v348 import build_multi_target_range
        return build_multi_target_range(self.engagement.output)

    def multi_target_campaign(self) -> dict:
        from modules.multi_target_integration_v348 import run_multi_target_campaign
        return run_multi_target_campaign(self.engagement.output)

    def multi_target_suite(self) -> dict:
        from modules.multi_target_integration_v348 import v348_test_matrix
        return v348_test_matrix()

    def specialist_conformance(self, *, repo_root=None) -> dict:
        from modules.specialist_conformance_v350 import build_conformance
        return build_conformance(self.engagement.output, repo_root=repo_root)

    def specialist_conformance_suite(self) -> dict:
        from modules.specialist_conformance_v350 import v350_test_matrix
        return v350_test_matrix()

    def specialist_isolated_range(self, *, execute: bool = True) -> dict:
        from modules.specialist_isolated_range_v354 import run_specialist_range
        return run_specialist_range(self.engagement.output, execute=execute)

    def specialist_isolated_range_suite(self) -> dict:
        from modules.specialist_isolated_range_v354 import v354_test_matrix
        return v354_test_matrix()

    def specialist_tool_integration(self, *, execute: bool = True) -> dict:
        from modules.specialist_tool_integration_v351 import run_tool_integration
        return run_tool_integration(self.engagement.output, execute=execute)

    def specialist_tool_integration_suite(self) -> dict:
        from modules.specialist_tool_integration_v351 import v351_test_matrix
        return v351_test_matrix()

    def tool_evidence_normalization(self, *, inputs=None) -> dict:
        from modules.tool_evidence_normalization_v352 import normalize_files
        return normalize_files(self.engagement.output, inputs or [])

    def tool_evidence_normalization_suite(self) -> dict:
        from modules.tool_evidence_normalization_v352 import v352_test_matrix
        return v352_test_matrix()

    def tool_aware_specialist_plan(self, *, domains=None) -> dict:
        from modules.tool_aware_specialist_planner_v353 import build_plan
        return build_plan(self.engagement.output, domains=domains)

    def tool_aware_specialist_plan_suite(self) -> dict:
        from modules.tool_aware_specialist_planner_v353 import v353_test_matrix
        return v353_test_matrix()

    def range_assurance_gate(self, *, repo_root=None) -> dict:
        from modules.range_assurance_gate_v349 import build_gate
        return build_gate(self.engagement.output, repo_root=repo_root)

    def range_assurance_gate_suite(self) -> dict:
        from modules.range_assurance_gate_v349 import v349_test_matrix
        return v349_test_matrix()

    def realistic_vulnerability_lab(self) -> dict:
        from modules.realistic_vulnerability_lab_v344 import build_realistic_lab
        return build_realistic_lab(self.engagement.output)

    def realistic_vulnerability_campaign(self) -> dict:
        from modules.realistic_vulnerability_lab_v344 import run_realistic_campaign
        return run_realistic_campaign(self.engagement.output)

    def realistic_vulnerability_lab_suite(self) -> dict:
        from modules.realistic_vulnerability_lab_v344 import v344_test_matrix
        return v344_test_matrix()

    def capability_closure_suite(self) -> dict:
        from modules.capability_closure_fabric_v342 import v342_test_matrix
        return v342_test_matrix()

    def complete_testing_lab(self, *, target: str = "127.0.0.1", authorized: bool = True, objective: str = "complete-engine-validation") -> dict:
        from modules.complete_testing_lab_v343 import build_complete_lab
        return build_complete_lab(self.engagement.output, target=target, authorized=authorized, objective=objective)

    def complete_testing_lab_suite(self) -> dict:
        from modules.complete_testing_lab_v343 import v343_test_matrix
        return v343_test_matrix()

    def assurance_stack(self, *, objective: str = "full-assessment", repo_root=None) -> dict:
        coverage = self.universal_coverage_assurance(objective=objective)
        validation = self.validation_assurance(objective=objective, claims=[], evidence=[])
        report = self.evidence_reporting(objective=objective, claims=validation.get("claims", []), evidence=validation.get("evidence", []), coverage=coverage.get("coverage", {}), validation=validation)
        self_audit = self.engine_self_security(repo_root=repo_root, include_tests=False)
        adapters = self.unified_specialist_adapters(objective=objective)
        web_api = self.web_api_assurance(objective="web-api-assurance")
        fuzz = self.fuzz_campaign_fabric()
        datastore = self.engagement_datastore()
        identity = self.identity_assurance()
        closure = self.capability_closure(objective=objective)
        isolated = self.specialist_isolated_range()
        return {"schema_version":"3.55.0", "target":self.engagement.target, "coverage":coverage, "validation":validation, "report":report, "self_security":self_audit, "unified_specialist_adapters":adapters, "web_api_assurance":web_api, "fuzz_campaign":fuzz, "engagement_datastore":datastore, "identity_assurance":identity, "capability_closure":closure, "specialist_isolated_range":isolated}

    def normalize_attack_surface(self) -> dict:
        from modules.assessment_normalizer_v34 import build
        return build(self.engagement.output, self.engagement.target)

    def evidence_quality(self) -> dict:
        from modules.evidence_quality_v34 import build
        return build(self.engagement.output)

    def preflight(self, *, active: bool = True) -> dict:
        pf = check(self.engagement.target, self.engagement.scope_file, active=active)
        data = pf.to_dict()
        write_json(self.engagement.output, "platform-preflight.json", data)
        return data

    def run_selected(self, names: Iterable[str], *, pentest_phases=(), osint_objective="general",
                     osint_inputs=(), public_osint=True, bounty_program="",
                     bounty_policy="", bounty_assets=(), bounty_execute=False, mobile_apk="", mobile_dynamic=False, mobile_serial="", mobile_allow_physical=False, wireless_interface="", wireless_pcap="", remote_scenarios="", remote_internal_target="", remote_execute=False):

        """Run selected specialists in a deterministic order.

        This is optional orchestration. Each specialist remains independently
        invokable and owns its own policy/authorization decisions.
        """
        requested = list(dict.fromkeys(names))
        unknown = [n for n in requested if n not in {s.name for s in all_specs()}]
        if unknown:
            raise ValueError(f"Unknown engine(s): {', '.join(unknown)}")
        self.write_manifest()
        # Only active specialists require the active-testing preflight. Passive
        # OSINT and bounty planning must remain independently usable without
        # accidentally inheriting the pentest scope requirement.
        active_requested = "pentest" in requested or bounty_execute
        self.preflight(active=active_requested)
        results = []
        if "osint" in requested:
            from security_platform.engines import OSINTEngine
            results.append(OSINTEngine(self.engagement).run(
                osint_objective, osint_inputs, public_osint))
        if "pentest" in requested:
            from security_platform.core.policy import ScopePolicy
            from security_platform.engines import PentestEngine
            phases = tuple(pentest_phases) or ("recon", "probe", "ports", "dns", "tls", "web", "api", "authenticated", "credentials", "intelligence", "final")
            try:
                policy = ScopePolicy.from_file(self.engagement.scope_file, self.engagement.target)
                results.append(PentestEngine(self.engagement, policy).run(phases))
            except ValueError as exc:
                results.append({"engine": "pentest", "status": "blocked", "target": self.engagement.target,
                                "blockers": [str(exc)]})
        if "bounty" in requested:
            from security_platform.engines import BugBountyEngine
            results.append(BugBountyEngine(self.engagement).intelligence(
                bounty_program, bounty_policy, bounty_assets, execute=bounty_execute))
        if "mobile" in requested:
            if not mobile_apk:
                results.append({"engine":"mobile","status":"blocked","reason":"apk-required"})
            else:
                from security_platform.engines import MobileEngine
                results.append(MobileEngine(self.engagement).android(mobile_apk, dynamic=mobile_dynamic, serial=mobile_serial, allow_physical=mobile_allow_physical))
        if "wireless" in requested:
            from security_platform.engines import WirelessEngine
            results.append(WirelessEngine(self.engagement).assess(wireless_interface, wireless_pcap))
        if "remote" in requested:
            from security_platform.engines import RemoteEngine
            from modules.roe_policy_v18 import ROEPolicy
            roe = ROEPolicy()
            results.append(RemoteEngine(self.engagement).assess(tuple(x.strip() for x in remote_scenarios.split(",") if x.strip()), execute=remote_execute, authorized=False, roe_permitted=roe.permits("controlled_attack_chain_test", target=self.engagement.target), internal_target=remote_internal_target))
        combined = {"platform": "3.4", "target": self.engagement.target, "engines": results}
        write_json(self.engagement.output, "platform-run.json", combined)
        return combined
