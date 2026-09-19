"""V3.22 universal specialist routing and governed R4 capability fabric.

This layer connects the universal surface inventory to the specialist engines
already present in the platform. It never grants authority: R0-R2 use the
V3.21 runner, R3 uses existing bounded proof adapters, and R4 is represented by
explicit operator-approved procedure contracts. Actual high-impact execution
is available only through registered lab/specialist adapters; no unrestricted
payload, shell, credential theft, persistence, propagation, or destructive
primitive is introduced.
"""
from __future__ import annotations
import hashlib, time
from pathlib import Path
from typing import Any, Iterable
from modules.atomic_io import atomic_write_json
from modules.universal_attack_surface_fabric_v320 import ATTACK_SURFACES, PERSPECTIVES
from modules.universal_assessment_runner_v321 import execute_universal_assessment

VERSION = "3.22.0"

SPECIALIST_ROUTES = {
    "external_web": "web_api",
    "api": "web_api",
    "dns_certificate": "internet_infrastructure",
    "internet_services": "network_infrastructure",
    "remote_access": "remote_endpoint",
    "endpoint_windows": "remote_endpoint",
    "endpoint_linux": "remote_endpoint",
    "endpoint_macos": "remote_endpoint",
    "identity_directory": "identity_ad",
    "cloud": "cloud",
    "saas": "cloud_saas",
    "containers": "container_kubernetes",
    "virtualization": "virtualization",
    "network_devices": "network_device",
    "wireless": "wireless",
    "mobile_android": "mobile_android",
    "mobile_ios": "mobile_ios",
    "iot": "iot_network",
    "firmware": "firmware_reverse_engineering",
    "hardware_debug": "hardware_lab",
    "ot_ics": "ot_ics",
    "automotive": "automotive_lab",
    "databases": "database",
    "storage_backup": "storage_backup",
    "email_collaboration": "email_identity",
    "supply_chain": "supply_chain",
    "source_code_ci_cd": "source_ci",
    "secrets_keys": "secrets",
    "observability_management": "management_plane",
    "third_party_integrations": "third_party",
    "client_browser_desktop": "client_application",
    "human_social": "human_led",
    "physical_facility": "physical_authorized",
    "ai_ml": "ai_ml",
    "cellular_telecom": "cellular_external",
}

# R4 is a capability/procedure vocabulary, not a payload catalogue.
R4_PROCEDURES = {
    "controlled_privilege_escalation_test": {"surfaces": ["endpoint_windows","endpoint_linux","endpoint_macos","identity_directory","cloud","containers"], "mode": "specialist_or_lab", "requires": ["roe","approval","scope"]},
    "controlled_persistence_test": {"surfaces": ["endpoint_windows","endpoint_linux","endpoint_macos","mobile_android","mobile_ios"], "mode": "specialist_or_lab", "requires": ["roe","approval","scope"], "lab_default": True},
    "controlled_lateral_movement_test": {"surfaces": ["identity_directory","remote_access","network_devices","cloud","containers"], "mode": "specialist_or_lab", "requires": ["roe","approval","scope"]},
    "controlled_credential_access_test": {"surfaces": ["identity_directory","endpoint_windows","endpoint_linux","endpoint_macos","cloud","secrets_keys"], "mode": "specialist_or_lab", "requires": ["roe","approval","scope"], "fake_data_only": True},
    "controlled_objective_access_test": {"surfaces": list(ATTACK_SURFACES), "mode": "specialist_or_lab", "requires": ["roe","approval","scope"]},
    "controlled_attack_chain_test": {"surfaces": list(ATTACK_SURFACES), "mode": "lab_or_registered_specialist", "requires": ["roe","approval","scope"], "lab_default": True},
}


def _write(root: Path, name: str, data: dict[str, Any]):
    root.joinpath("evidence").mkdir(parents=True, exist_ok=True)
    return atomic_write_json(root / "evidence" / name, data)


def _hash(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def build_specialist_router(root: str | Path, *, target: str, perspective: str = "internet_ipv4", surfaces: Iterable[str] | None = None, objective: str = "full-assessment") -> dict[str, Any]:
    root = Path(root)
    if perspective not in PERSPECTIVES:
        raise ValueError(f"unknown perspective: {perspective}")
    selected = list(dict.fromkeys(s for s in (surfaces or ATTACK_SURFACES) if s in ATTACK_SURFACES))
    routes = []
    for surface in selected:
        routes.append({"surface": surface, "specialist": SPECIALIST_ROUTES.get(surface, "unmapped"), "tests": ATTACK_SURFACES[surface]["tests"], "perspective": perspective, "remote_capable": perspective not in {"local_host", "physical_adjacent", "physical_lab"} or surface in {"wireless","hardware_debug","physical_facility"}, "route_id": "RTE-" + _hash(target, perspective, surface)})
    data = {"schema_version": VERSION, "target": target, "objective": objective, "perspective": perspective, "routes": routes, "coverage": {"selected": len(selected), "routed": sum(x["specialist"] != "unmapped" for x in routes), "unmapped": sum(x["specialist"] == "unmapped" for x in routes)}, "principle": "routing selects registered specialist capability; it never grants authority or expands scope"}
    _write(root, "universal-specialist-router-v322.json", data)
    return data


def build_r4_capability_matrix(root: str | Path, *, target: str, surfaces: Iterable[str] | None = None) -> dict[str, Any]:
    root = Path(root); selected = set(surfaces or ATTACK_SURFACES)
    rows = []
    for action, spec in R4_PROCEDURES.items():
        applicable = sorted(selected.intersection(spec["surfaces"]))
        rows.append({"action": action, **spec, "applicable_surfaces": applicable, "status": "governed-capability" if applicable else "not-applicable"})
    data = {"schema_version": VERSION, "target": target, "r4": rows, "execution_boundary": "R4 requires exact ROE permission, exact-action single-use approval, scope recheck, and a registered specialist/lab adapter", "not_implemented": ["unrestricted_rce","destructive_impact","covert_c2","uncontrolled_propagation","real_data_exfiltration","credential_spraying_at_scale","carrier_bypass"]}
    _write(root, "r4-capability-matrix-v322.json", data)
    return data


def execute_universal_router(root: str | Path, *, target: str, scope_file: str | Path, perspective: str = "internet_ipv4", authorized: bool = False, execute: bool = False, surfaces: Iterable[str] | None = None, max_steps: int = 12, timeout: int = 600, objective: str = "full-assessment") -> dict[str, Any]:
    root = Path(root)
    router = build_specialist_router(root, target=target, perspective=perspective, surfaces=surfaces, objective=objective)
    safe_surfaces = [x["surface"] for x in router["routes"] if x["specialist"] in {"web_api","internet_infrastructure","network_infrastructure","network_device","cloud","container_kubernetes","identity_ad","remote_endpoint","cellular_external"}]
    universal = execute_universal_assessment(root, target=target, scope_file=scope_file, perspective=perspective, authorized=authorized, execute=execute, surfaces=safe_surfaces, max_steps=max_steps, timeout=timeout)
    delegated = [{"surface": x["surface"], "specialist": x["specialist"], "status": "delegated", "reason": "specialist owns domain methodology and execution contract"} for x in router["routes"] if x["surface"] not in safe_surfaces]
    result = {"schema_version": VERSION, "status": universal.get("status"), "target": target, "perspective": perspective, "router": router, "universal_safe_execution": universal, "specialist_delegation": delegated, "r4": build_r4_capability_matrix(root, target=target, surfaces=surfaces), "timestamp": time.time()}
    _write(root, "universal-router-execution-v322.json", result)
    return result



def execute_r4_controlled(root: str | Path, *, target: str, scope_file: str | Path, action: str, authorized: bool, roe_permitted: bool, approval_token: str = "", approval_request_id: str = "", perspective: str = "testbed", internal_target: str = "") -> dict[str, Any]:
    """Execute only registered controlled R4 procedures.

    Real high-impact targets are delegated to an engagement-specific adapter.
    The built-in executor is deliberately restricted to the disposable
    loopback lab, where existing benign proof modules can exercise R4-shaped
    workflows without real persistence, credential theft, lateral propagation,
    or destructive impact.
    """
    root = Path(root)
    if action not in R4_PROCEDURES:
        return {"status": "blocked", "reason": "unknown_r4_action", "action": action}
    if not authorized:
        return {"status": "blocked", "reason": "explicit_authorization_required", "action": action}
    if not roe_permitted:
        return {"status": "blocked", "reason": "exact_r4_roe_permission_required", "action": action}
    if not approval_token or not approval_request_id:
        return {"status": "blocked", "reason": "request_bound_single_use_approval_required", "action": action}
    # R4 built-in execution is lab-only. The target must be loopback and the
    # scope file must explicitly contain it; no remote high-impact executor is
    # synthesized here.
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return {"status": "specialist-required", "action": action, "target": target, "perspective": perspective, "reason": "real-target R4 requires a registered engagement-specific specialist adapter"}
    if not scope_file or not Path(scope_file).is_file():
        return {"status": "blocked", "reason": "authoritative_scope_required", "action": action}
    try:
        from modules.scope import load_scope
        from modules.security import in_scope
        allowed = load_scope(str(scope_file))
        if not allowed or not in_scope(target, allowed):
            return {"status": "blocked", "reason": "target_out_of_scope", "action": action}
    except Exception as exc:
        return {"status": "blocked", "reason": f"scope_check_failed:{exc}", "action": action}

    from modules.approval_queue import ApprovalQueue
    queue = ApprovalQueue(root / "evidence")
    if not queue.consume_token(approval_request_id, approval_token, action, target):
        return {"status": "blocked", "reason": "invalid_or_consumed_approval_token", "action": action, "request_id": approval_request_id}

    if action == "controlled_attack_chain_test":
        from modules.attack_chain_lab_v20 import run_lab_attack_chain
        if not internal_target:
            internal_target = "http://127.0.0.1:8082"
        return run_lab_attack_chain(root, initial_url=target, internal_url=internal_target, authorized=True, execute=True, approval_token=approval_token, roe_permitted=True, scope_file=scope_file)

    if action == "controlled_privilege_escalation_test":
        from modules.controlled_validation_v21 import validate
        return {"status": "completed", "action": action, "lab": validate(root, target, ["config_exposure"]), "fake_data_only": True}
    if action == "controlled_persistence_test":
        from modules.persistence_lab_v21 import run
        return {"status": "completed", "action": action, "lab": run(root, target), "fake_data_only": True}
    if action == "controlled_lateral_movement_test":
        from modules.lateral_movement_lab_v21 import run
        if not internal_target:
            return {"status": "blocked", "reason": "distinct_internal_lab_target_required", "action": action}
        return {"status": "completed", "action": action, "lab": run(root, target, internal_target), "fake_data_only": True}
    if action == "controlled_credential_access_test":
        return {"status": "completed", "action": action, "lab": True, "fake_data_only": True, "evidence": "use the existing credential-intelligence lab workflow; no real credential capture/theft is implemented"}
    if action == "controlled_objective_access_test":
        from modules.lab_http import base, request
        url = base(target) + "/lab/objective"
        r = request(url, method="GET", headers={"X-Lab-Objective": "OBJECTIVE-LAB-OK"})
        return {"status": "completed", "action": action, "lab_only": True, "http_status": r.get("http_status"), "body_prefix": str(r.get("body", ""))[:200], "fake_data_only": True}
    return {"status": "specialist-required", "action": action, "reason": "no registered built-in procedure"}

def build_v322_fabric(root: str | Path, *, target: str, perspective: str = "internet_ipv4", objective: str = "full-assessment") -> dict[str, Any]:
    return {"schema_version": VERSION, "target": target, "perspective": perspective, "objective": objective, "router": build_specialist_router(root, target=target, perspective=perspective, objective=objective), "r4": build_r4_capability_matrix(root, target=target), "status": "completed"}
