"""V3.15 specialist-domain fabric.

Fuses stronger capabilities from wireless, remote-system, mobile-device and RCE
assessment ecosystems into governed capability contracts. It is intentionally
adapter-oriented: external tools remain specialist executors, while this
platform owns scope, approvals, evidence normalization and correlation.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json

VERSION = "3.15.0"

SOURCES = {
    "wireless": ["Aircrack-ng", "Kismet", "bettercap"],
    "mobile": ["MobSF", "Frida", "Objection", "Corellium"],
    "remote": ["Nmap", "NetExec", "Metasploit"],
    "rce_validation": ["Metasploit", "Nuclei", "NodeZero", "Pentera", "Picus"],
}

CAPABILITIES = {
    "wireless": {
        "radio_inventory": "enumerate interfaces, PHY capabilities and driver state",
        "passive_wifi_discovery": "normalize AP/client/channel observations from captures",
        "wireless_pcap_analysis": "extract SSID/BSSID/channel/client relationships and anomalies",
        "ble_inventory": "normalize BLE advertisements and supplied GATT observations",
        "wireless_capability_assurance": "record whether capture/injection hardware prerequisites exist",
        "governed_active_scenarios": "represent operator-approved wireless validation scenarios without autonomous execution",
    },
    "mobile": {
        "binary_static_pipeline": "APK/IPA static evidence and hardening findings",
        "runtime_instrumentation_contract": "Frida/Objection runtime observation contract with explicit device approval",
        "component_attack_surface": "Android IPC/component inventory contract",
        "virtual_device_lab": "Corellium-style device lifecycle: provision, snapshot, inspect, restore",
        "device_introspection": "filesystem/process/network/syscall evidence contract",
        "mobile_api_correlation": "correlate mobile runtime traffic with backend/API findings",
    },
    "remote": {
        "service_fingerprint": "protocol/service/version inventory",
        "remote_protocol_matrix": "SSH/SMB/WinRM/RDP/LDAP/SNMP/HTTP/TLS assessment planning",
        "identity_relationship_correlation": "link remote services to AD/cloud identity evidence",
        "remote_session_evidence": "model operator-approved sessions as evidence state, not hidden credentials",
        "lateral_path_analysis": "derive bounded attack-path hypotheses from existing evidence",
    },
    "rce_validation": {
        "candidate_discovery": "map service/version evidence to candidate CVEs and validation scenarios",
        "precondition_analysis": "check version, exposure, authentication and configuration prerequisites",
        "safe_proof_contract": "prefer non-destructive lab proof fixtures or vendor-safe validation",
        "exploitability_verdict": "separate candidate, reachable, validated and blocked outcomes",
        "rce_to_path_correlation": "feed validated exposure into attack-path reasoning without generating unrestricted payloads",
        "retest_contract": "re-run the same evidence contract after remediation with fresh approval",
    },
}


def _write(root: str | Path, name: str, data: dict[str, Any]) -> dict[str, Any]:
    root = Path(root); (root / "evidence").mkdir(parents=True, exist_ok=True)
    atomic_write_json(root / "evidence" / name, data)
    return data


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def capability_matrix(root: str | Path) -> dict[str, Any]:
    return _write(root, "specialist-domain-capability-matrix-v315.json", {
        "schema_version": VERSION,
        "sources": SOURCES,
        "domains": CAPABILITIES,
        "architecture": "specialist tools execute only through the governed platform; evidence is normalized centrally",
        "governance": ["authorization", "scope", "ROE", "exact-action approval", "ToolManager", "evidence provenance", "kill switch"],
    })


def build_wireless_plan(root: str | Path, target: str, interface: str = "") -> dict[str, Any]:
    steps = [
        ("radio", "inventory_interface", "observe"),
        ("survey", "passive_wifi_discovery", "observe"),
        ("capture", "pcap_analysis", "observe"),
        ("ble", "ble_inventory", "observe"),
        ("assurance", "validate_hardware_prerequisites", "observe"),
        ("active_validation", "operator_approved_scenario", "approval_required"),
    ]
    return _write(root, "wireless-specialist-plan-v315.json", {
        "schema_version": VERSION, "target": target, "interface": interface,
        "steps": [{"id": _id(target, name), "phase": name, "capability": cap, "execution": mode} for name, cap, mode in steps],
        "active_rule": "active wireless validation is never inferred from passive findings and requires a fresh exact-action approval",
    })


def build_mobile_lab_plan(root: str | Path, target: str) -> dict[str, Any]:
    stages = [
        "artifact_inventory", "static_analysis", "dependency_and_sdk_review",
        "virtual_or_physical_device_preflight", "runtime_observation", "network_trace_correlation",
        "component_attack_surface", "filesystem/process/syscall_observation", "finding_validation", "retest",
    ]
    return _write(root, "mobile-lab-plan-v315.json", {
        "schema_version": VERSION, "target": target,
        "stages": [{"stage": s, "requires": ["authorization", "device_scope", "exact-action approval"]} for s in stages],
        "virtual_device_features": ["snapshot", "restore", "device_identity", "sensor_state", "network_state", "filesystem_introspection", "process_introspection"],
        "physical_device_rule": "physical-device actions require explicit device authorization and are not assumed from application authorization",
    })


def build_remote_matrix(root: str | Path, target: str) -> dict[str, Any]:
    protocols = ["SSH", "SMB", "WinRM", "RDP", "LDAP", "SNMP", "HTTP", "HTTPS", "TLS", "DNS", "NFS", "FTP"]
    return _write(root, "remote-protocol-matrix-v315.json", {
        "schema_version": VERSION, "target": target,
        "protocols": [{"protocol": p, "discovery": True, "read_only_assessment": True, "active_validation": "approval_required"} for p in protocols],
        "correlation": ["service-to-host", "host-to-identity", "identity-to-resource", "service-to-CVE", "path-to-impact"],
        "session_model": "ephemeral evidence references; do not persist reusable secrets or tokens",
    })


def build_rce_validation_catalog(root: str | Path, observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    observations = observations or []
    candidates = []
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        service = obs.get("service", obs.get("product", "unknown"))
        version = obs.get("version", "")
        cve = obs.get("cve", "")
        candidates.append({
            "candidate_id": _id(service, version, cve), "service": service, "version": version, "cve": cve,
            "preconditions": ["version match", "exposure confirmed", "authentication requirement checked", "safe validation path available"],
            "validation_modes": ["vendor-safe check", "non-destructive lab fixture", "controlled exploitability proof"],
            "verdicts": ["candidate", "preconditions_met", "validated", "blocked", "unverified"],
            "approval": "required for any active validation",
        })
    return _write(root, "rce-validation-catalog-v315.json", {
        "schema_version": VERSION, "candidates": candidates,
        "rule": "RCE discovery does not imply RCE execution; candidate evidence must satisfy preconditions and an exact approved validation contract",
    })


def build_domain_fusion(root: str | Path, target: str, objective: str = "general") -> dict[str, Any]:
    edges = [
        ("wireless", "remote", "wireless asset -> discovered management/service exposure"),
        ("remote", "identity", "service -> identity relationship"),
        ("remote", "rce_validation", "service/version -> candidate RCE validation"),
        ("mobile", "web", "mobile runtime -> backend/API endpoint"),
        ("mobile", "cloud", "mobile artifact/runtime -> cloud dependency"),
        ("rce_validation", "attack_path", "validated exposure -> bounded attack-path hypothesis"),
        ("control_validation", "rce_validation", "control result -> exploitability/control verdict"),
    ]
    return _write(root, "specialist-domain-fusion-v315.json", {
        "schema_version": VERSION, "target": target, "objective": objective,
        "edges": [{"from": a, "to": b, "relationship": rel} for a, b, rel in edges],
        "selection": "prefer cross-domain evidence that reduces uncertainty; do not infer exploitability from a single scanner result",
    })


def build_v315_fabric(root: str | Path, target: str, objective: str = "general", observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "capability_matrix": capability_matrix(root),
        "wireless": build_wireless_plan(root, target),
        "mobile": build_mobile_lab_plan(root, target),
        "remote": build_remote_matrix(root, target),
        "rce_validation": build_rce_validation_catalog(root, observations),
        "fusion": build_domain_fusion(root, target, objective),
    }
