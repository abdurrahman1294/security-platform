#!/usr/bin/env python3
"""Autonomy policy, risk classes, and default-deny decisions.

This module defines what the engine may do unattended. High-impact actions
require explicit human approval tokens. Nothing here enables unrestricted
exploitation, lateral movement, persistence, or credential spraying.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskClass(str, Enum):
    R0 = "R0"  # passive / local metadata only
    R1 = "R1"  # active in-scope discovery
    R2 = "R2"  # non-destructive verification
    R3 = "R3"  # proof / stateful testing (approval required)
    R4 = "R4"  # high-impact, explicit ROE + approval required
    R5 = "R5"  # permanently forbidden


class Decision(str, Enum):
    ALLOW_AUTO = "allow_auto"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


# Profiles control which risk classes may run without approval.
PROFILES: dict[str, set[RiskClass]] = {
    "observe": {RiskClass.R0},
    "recon": {RiskClass.R0, RiskClass.R1},
    "assess": {RiskClass.R0, RiskClass.R1},
    "safe-verify": {RiskClass.R0, RiskClass.R1, RiskClass.R2},
    "assisted": {RiskClass.R0, RiskClass.R1, RiskClass.R2},  # R3/R4 remain approval-gated
}

# Default action catalogue. Unknown actions deny.
ACTION_RISK: dict[str, RiskClass] = {
    # R0
    "preflight": RiskClass.R0,
    "tool_inventory": RiskClass.R0,
    "normalize_assets": RiskClass.R0,
    "dedupe_evidence": RiskClass.R0,
    "coverage_analysis": RiskClass.R0,
    "draft_report": RiskClass.R0,
    "prioritize_tasks": RiskClass.R0,
    "load_state": RiskClass.R0,
    # R1
    "subdomain_enum": RiskClass.R1,
    "http_probe": RiskClass.R1,
    "port_scan": RiskClass.R1,
    "service_enum": RiskClass.R1,
    "web_crawl": RiskClass.R1,
    "vuln_candidate_scan": RiskClass.R1,
    "api_discovery": RiskClass.R1,
    "cloud_read_inventory": RiskClass.R1,
    "ad_read_enum": RiskClass.R1,
    # R2
    "safe_http_observe": RiskClass.R2,
    "header_verification": RiskClass.R2,
    "endpoint_recheck": RiskClass.R2,
    "tls_observation": RiskClass.R2,
    "reflection_check": RiskClass.R2,
    # R3
    "controlled_validation": RiskClass.R3,
    "proof_adapter": RiskClass.R3,
    "authenticated_invasive_check": RiskClass.R3,
    # R4: high-impact actions are governed by an engagement ROE.
    "controlled_privilege_escalation_test": RiskClass.R4,
    "controlled_persistence_test": RiskClass.R4,
    "controlled_lateral_movement_test": RiskClass.R4,
    "controlled_credential_access_test": RiskClass.R4,
    "controlled_objective_access_test": RiskClass.R4,
    "controlled_attack_chain_test": RiskClass.R4,
    # R5: permanently denied regardless of authorization.
    "destructive_payload": RiskClass.R5,
    "unrestricted_rce": RiskClass.R5,
    "uncontrolled_propagation": RiskClass.R5,
    "real_data_exfiltration": RiskClass.R5,
    "ransomware_simulation": RiskClass.R5,
    "credential_spraying_at_scale": RiskClass.R5,
    "automatic_bounty_submission": RiskClass.R5,
    # Legacy/high-risk aliases remain permanently denied.
    "password_spray": RiskClass.R5,
    "credential_stuffing": RiskClass.R5,
    "exploit_rce": RiskClass.R5,
    "lateral_movement": RiskClass.R5,
    "persistence": RiskClass.R5,
    "exfiltration": RiskClass.R5,
}


@dataclass
class Budget:
    max_tasks: int = 50
    max_seconds: int = 3600
    max_requests: int = 5000
    max_hosts: int = 500

    def __post_init__(self):
        limits = {"max_tasks": (1, 10000), "max_seconds": (1, 86400), "max_requests": (1, 1000000), "max_hosts": (1, 100000)}
        for name, (lo, hi) in limits.items():
            value = int(getattr(self, name))
            if not lo <= value <= hi:
                raise ValueError(f"{name} must be between {lo} and {hi}")
            setattr(self, name, value)

    def exhausted(self, tasks: int, seconds: float, requests: int, hosts: int) -> bool:
        return (
            tasks >= self.max_tasks
            or seconds >= self.max_seconds
            or requests >= self.max_requests
            or hosts >= self.max_hosts
        )


@dataclass
class AutonomyPolicy:
    profile: str = "assess"
    budgets: Budget = field(default_factory=Budget)
    require_scope: bool = True
    require_authorization: bool = True
    kill_switch: bool = False

    def normalized_profile(self) -> str:
        p = (self.profile or "assess").strip().lower()
        return p if p in PROFILES else "assess"

    def auto_risks(self) -> set[RiskClass]:
        return set(PROFILES[self.normalized_profile()])

    def risk_for(self, action: str) -> RiskClass:
        key = (action or "").strip().lower()
        return ACTION_RISK.get(key, RiskClass.R5)

    def decide(
        self,
        action: str,
        *,
        authorized: bool,
        in_scope: bool,
        approval_token: str | None = None,
        roe_permitted: bool = False,
    ) -> Decision:
        """Default-deny policy decision."""
        if self.kill_switch:
            return Decision.DENY
        if self.require_authorization and not authorized:
            return Decision.DENY
        if self.require_scope and not in_scope:
            return Decision.DENY

        risk = self.risk_for(action)
        if risk == RiskClass.R5:
            return Decision.DENY
        if risk == RiskClass.R4:
            if not roe_permitted or not approval_token:
                return Decision.NEEDS_APPROVAL
            return Decision.ALLOW_AUTO
        if risk == RiskClass.R3:
            return Decision.NEEDS_APPROVAL if not approval_token else Decision.ALLOW_AUTO
        if risk in self.auto_risks():
            return Decision.ALLOW_AUTO
        # Known R2 under profiles that don't include it, or unknown mapped to deny path
        if risk == RiskClass.R2:
            return Decision.NEEDS_APPROVAL
        return Decision.DENY

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.normalized_profile(),
            "auto_risks": sorted(r.value for r in self.auto_risks()),
            "budgets": {
                "max_tasks": self.budgets.max_tasks,
                "max_seconds": self.budgets.max_seconds,
                "max_requests": self.budgets.max_requests,
                "max_hosts": self.budgets.max_hosts,
            },
            "require_scope": self.require_scope,
            "require_authorization": self.require_authorization,
            "kill_switch": self.kill_switch,
            "r4_mode": "roe_controlled",
            "r5_mode": "permanently_denied",
        }


def validate_action_name(action: str) -> bool:
    return isinstance(action, str) and bool(action.strip()) and len(action) < 128
