"""V3.26 Adversarial Self-Assessment & Chain Reasoning Fabric.

Models a person-centric, internet-facing attack surface (cellular origin,
computer, phone, social accounts, identity/recovery, cloud/SaaS and physical
context) and reasons about multi-step exposure chains. It produces governed
assessment hypotheses and bounded validation plans; it never creates
credential theft, phishing, persistence, covert C2, destructive, or arbitrary
remote-execution procedures.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import hashlib, json, re, time

VERSION = "3.26.0"
DENIED = {
    "credential_theft", "phishing", "credential_spraying_at_scale",
    "unrestricted_rce", "persistence", "covert_c2", "real_data_exfiltration",
    "uncontrolled_propagation", "destructive_impact", "carrier_bypass",
}

ASSET_TYPES = {
    "cellular_connection", "public_ip", "dns_identity", "email_identity",
    "social_account", "cloud_account", "computer", "mobile_phone",
    "browser", "password_manager", "recovery_channel", "home_network",
    "router", "vpn", "application", "third_party_service", "physical_context",
    "human_trust_boundary", "backup", "source_code", "api_token",
}

@dataclass(frozen=True)
class Asset:
    id: str
    type: str
    label: str
    exposure: str
    trust_zone: str
    dependencies: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()

@dataclass(frozen=True)
class Hypothesis:
    id: str
    title: str
    chain: tuple[str, ...]
    prerequisites: tuple[str, ...]
    signals: tuple[str, ...]
    validation: str
    safety_class: str
    confidence: float
    priority: float


def _write(root: str | Path, name: str, obj: Any) -> Path:
    p = Path(root) / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _norm(v: Any) -> str:
    return re.sub(r"[^a-z0-9_:-]+", "_", str(v).strip().lower()).strip("_")


def normalize_assets(assets: Iterable[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(assets or []):
        if not isinstance(raw, dict):
            continue
        typ = _norm(raw.get("type", raw.get("asset_type", "")))
        if typ not in ASSET_TYPES:
            continue
        label = str(raw.get("label", raw.get("name", typ)))
        out.append(asdict(Asset(
            id=str(raw.get("id") or f"asset-{i+1}"), type=typ, label=label,
            exposure=_norm(raw.get("exposure", "unknown")),
            trust_zone=_norm(raw.get("trust_zone", "personal")),
            dependencies=tuple(str(x) for x in (raw.get("dependencies") or [])),
            evidence_ids=tuple(str(x) for x in (raw.get("evidence_ids") or [])),
        )))
    return out


def default_personal_surface() -> list[dict[str, Any]]:
    return normalize_assets([
        {"type":"cellular_connection","label":"cellular internet origin","exposure":"internet-facing","trust_zone":"carrier"},
        {"type":"public_ip","label":"current public egress","exposure":"internet-facing","trust_zone":"carrier"},
        {"type":"dns_identity","label":"domain/DNS footprint","exposure":"internet-facing","trust_zone":"public"},
        {"type":"email_identity","label":"primary email identity","exposure":"internet-facing","trust_zone":"identity"},
        {"type":"social_account","label":"social media accounts","exposure":"internet-facing","trust_zone":"identity"},
        {"type":"cloud_account","label":"cloud/SaaS accounts","exposure":"internet-facing","trust_zone":"identity"},
        {"type":"computer","label":"primary computer","exposure":"reachable-through-services","trust_zone":"endpoint"},
        {"type":"mobile_phone","label":"primary mobile phone","exposure":"reachable-through-apps-services","trust_zone":"endpoint"},
        {"type":"browser","label":"browser session boundary","exposure":"application-facing","trust_zone":"endpoint"},
        {"type":"password_manager","label":"credential-management boundary","exposure":"high-value-control","trust_zone":"identity"},
        {"type":"recovery_channel","label":"account recovery channels","exposure":"internet-facing","trust_zone":"identity"},
        {"type":"home_network","label":"home/LAN environment","exposure":"private","trust_zone":"network"},
        {"type":"router","label":"home router","exposure":"internet-facing","trust_zone":"network"},
        {"type":"backup","label":"backup/recovery assets","exposure":"private","trust_zone":"data"},
        {"type":"third_party_service","label":"trusted integrations","exposure":"internet-facing","trust_zone":"integration"},
        {"type":"human_trust_boundary","label":"human/social trust boundary","exposure":"human-mediated","trust_zone":"human"},
    ])


def build_asset_dependency_graph(assets: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = [{"id":a["id"], "type":a["type"], "label":a["label"], "exposure":a["exposure"], "trust_zone":a["trust_zone"]} for a in assets]
    edges = []
    by_type: dict[str, list[str]] = {}
    for a in assets:
        by_type.setdefault(str(a["type"]), []).append(str(a["id"]))
    def edge(a: str, b: str, relation: str):
        for src in by_type.get(a, []):
            for dst in by_type.get(b, []):
                edges.append({"from":src, "to":dst, "relation":relation})
    edge("cellular_connection", "public_ip", "provides-egress")
    edge("public_ip", "router", "may-expose-or-identify")
    edge("email_identity", "social_account", "recovery-or-trust")
    edge("email_identity", "cloud_account", "identity-provider-or-recovery")
    edge("recovery_channel", "social_account", "recovery-control")
    edge("recovery_channel", "cloud_account", "recovery-control")
    edge("browser", "cloud_account", "session-boundary")
    edge("mobile_phone", "social_account", "application-boundary")
    edge("mobile_phone", "recovery_channel", "recovery-boundary")
    edge("computer", "browser", "host-boundary")
    edge("password_manager", "cloud_account", "credential-control")
    edge("password_manager", "social_account", "credential-control")
    edge("third_party_service", "cloud_account", "integration-trust")
    edge("human_trust_boundary", "social_account", "human-mediated-trust")
    edge("human_trust_boundary", "email_identity", "human-mediated-trust")
    edge("home_network", "computer", "network-reachability")
    edge("home_network", "mobile_phone", "network-reachability")
    edge("router", "home_network", "gateway")
    return {"nodes":nodes,"edges":edges}


def _evidence_index(observations: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    out={}
    for i,o in enumerate(observations or []):
        if isinstance(o,dict): out[str(o.get("id",f"obs-{i+1}"))]=o
    return out


def generate_hypotheses(assets: list[dict[str, Any]], observations: Iterable[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    idx=_evidence_index(observations)
    types={a["type"] for a in assets}
    hypotheses=[]
    def add(title, chain, prereq, signals, validation, safety, confidence, priority):
        hypotheses.append(asdict(Hypothesis(_id(title,*chain),title,tuple(chain),tuple(prereq),tuple(signals),validation,safety,confidence,priority)))
    if {"email_identity","social_account","recovery_channel"} <= types:
        add("Identity recovery concentration",
            ["public_identity","account_recovery","identity_change","downstream_account_access"],
            ["recovery controls exist","recovery channel is reachable"],
            ["shared recovery email/phone","weak recovery controls","recovery events"],
            "Review recovery settings, MFA strength, notification history, trusted devices, and provider security logs; use provider-approved recovery testing only.",
            "R2_non_destructive_verify", .62, .93)
    if {"mobile_phone","social_account","email_identity"} <= types:
        add("Mobile-to-identity trust chain",
            ["mobile_application","session_or_identity_signal","account_control_effect"],
            ["mobile app is authenticated","identity provider trusts device/session"],
            ["unusual sessions","new device events","unexpected token/session invalidation"],
            "Review device security posture, app permissions, session inventory, MFA events, and provider telemetry; validate only with benign test accounts where required.",
            "R2_non_destructive_verify", .58, .90)
    if {"computer","browser","cloud_account"} <= types:
        add("Endpoint-to-cloud session chain",
            ["endpoint_exposure","browser_or_application_state","session_boundary","cloud_account"],
            ["browser session exists","cloud account is used from endpoint"],
            ["stale sessions","weak session controls","suspicious device/browser state"],
            "Review browser/session inventory, MFA/session policy, device posture, extension inventory, and account sign-in telemetry.",
            "R2_non_destructive_verify", .64, .92)
    if {"social_account","human_trust_boundary","email_identity"} <= types:
        add("Human-to-identity trust chain",
            ["public_information","human_trust_signal","identity_recovery_or_authorization","downstream_account"],
            ["public profile information exists","support/recovery process accepts human-mediated signals"],
            ["overshared recovery information","reused public identifiers","weak support verification"],
            "Perform an authorized exposure review of public information and recovery policy; do not contact or deceive third parties as part of automated execution.",
            "R1_bounded_discovery", .55, .88)
    if {"cellular_connection","public_ip","router"} <= types:
        add("Cellular-origin network exposure chain",
            ["cellular_egress","public_addressing","internet_reachability","service_or_management_plane"],
            ["carrier provides routable or observable egress","service is exposed"],
            ["unexpected inbound reachability","stable exposed service","management interface exposure"],
            "Measure source identity, IPv4/IPv6 reachability, DNS, approved TCP/TLS/HTTP targets, and compare observations over time; cellular is a vantage point, not a bypass.",
            "R1_bounded_discovery", .60, .95)
    if {"password_manager","email_identity","cloud_account"} <= types:
        add("Credential-control concentration",
            ["credential_control","identity_provider","cloud_or_social_accounts","account_recovery"],
            ["central credential control exists","accounts depend on common identity"],
            ["single point of failure","weak MFA on identity provider","recovery concentration"],
            "Audit password-manager security, MFA, recovery codes, session inventory, device trust, and provider alerts without retrieving or exposing credential values.",
            "R2_non_destructive_verify", .67, .96)
    # Evidence can strengthen or weaken, but never turns a scanner result into an exploit claim.
    for h in hypotheses:
        text=" ".join(h["signals"]).lower()
        supporting=sum(1 for o in idx.values() if any(term in str(o).lower() for term in text.split()[:4]))
        h["evidence_support"] = min(1.0, supporting / 3.0)
        h["priority"] = round(min(1.0, h["priority"] + .08*h["evidence_support"]),4)
        h["confidence"] = round(min(1.0, h["confidence"] + .06*h["evidence_support"]),4)
        h["do_not_claim_compromise"] = True
    return sorted(hypotheses,key=lambda x:(-x["priority"],-x["confidence"],x["id"]))


def build_chain_analysis(root: str | Path, *, target: str, assets: Iterable[dict[str, Any]] | None = None,
                         observations: Iterable[dict[str, Any]] | None = None, objective: str = "full-self-assessment") -> dict[str, Any]:
    normalized=normalize_assets(list(assets) if assets is not None else default_personal_surface())
    graph=build_asset_dependency_graph(normalized)
    hypotheses=generate_hypotheses(normalized, observations)
    state={"schema_version":VERSION,"status":"ready","target":target,"objective":objective,
           "asset_count":len(normalized),"assets":normalized,"dependency_graph":graph,"hypotheses":hypotheses,
           "perspectives":["cellular_ipv4","cellular_ipv6","internet_ipv4","internet_ipv6","local_host","authenticated_user","physical_adjacent"],
           "reasoning":{"multi_step":True,"cross_domain":True,"competing_hypotheses":True,"small-signal_review":True,
                        "stale_evidence_revalidation":True,"scanner_result_is_not_compromise":True},
           "governance":{"authorized_scope_required":True,"operator_approval_for_consequential_tests":True,
                         "automation_denied":sorted(DENIED),"bounded_validation":"existing R0-R2 and governed lab procedures"},
           "created_at":time.time()}
    _write(root,"adversarial-self-assessment-v326.json",state)
    return state


def adversarial_test_matrix() -> dict[str, Any]:
    scenarios=[
        "contradictory_evidence","stale_evidence","missing_telemetry","partial_tool_failure",
        "scope_change","authorization_revocation","perspective_change","duplicate_finding",
        "cyclic_prerequisite","interrupted_execution","resume_after_failure","false_positive_chain",
        "weak_signal_correlation","cross_domain_identity_dependency","cellular_ipv4_ipv6_divergence",
        "account_recovery_concentration","endpoint_to_cloud_session_chain","mobile_to_identity_chain",
        "human_trust_boundary","third_party_integration_dependency",
    ]
    return {"schema_version":VERSION,"suite":"adversarial-control-plane","scenario_count":len(scenarios),
            "scenarios":[{"id":_id(s),"name":s,"expected":"safe-degrade-or-replan"} for s in scenarios],
            "invariants":["never_expand_scope","never_execute_denied_class","never treat weak evidence as compromise",
                           "recheck_authorization_before_execution","preserve provenance","invalidate stale conclusions",
                           "resume without duplicate consequential actions"]}
