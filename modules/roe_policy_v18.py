#!/usr/bin/env python3
"""Strict machine-readable Rules of Engagement policy.

R4 actions are governance-gated: the engagement ROE must explicitly allow the
specific action and an approval token must be presented at execution time.
R5 actions remain permanently denied by the autonomy policy.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import json
from typing import Any

R4_ACTIONS = {
    "controlled_privilege_escalation_test", "controlled_persistence_test",
    "controlled_lateral_movement_test", "controlled_credential_access_test",
    "controlled_objective_access_test", "controlled_attack_chain_test",
}
R5_ACTIONS = {
    "destructive_payload", "unrestricted_rce", "uncontrolled_propagation",
    "real_data_exfiltration", "ransomware_simulation", "credential_spraying_at_scale",
    "automatic_bounty_submission",
}
_ALLOWED_IMPACT = {"low", "medium", "high"}


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "yes", "1", "on"}: return True
        if v in {"false", "no", "0", "off"}: return False
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    return default

@dataclass(frozen=True)
class ROEPolicy:
    enabled: bool = False
    allowed_actions: frozenset[str] = field(default_factory=frozenset)
    max_impact: str = "high"
    fake_data_only: bool = True
    production_change_allowed: bool = False
    third_party_assets_allowed: bool = False
    time_window: str | None = None
    emergency_stop: bool = False
    operator: str = ""
    engagement_reference: str = ""
    target: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ROEPolicy":
        if not isinstance(raw, dict):
            raise ValueError("ROE must be a JSON object")
        # Reuse the exact file parser rules without writing a temporary file.
        raw_actions = raw.get("allowed_r4_actions", [])
        if not isinstance(raw_actions, (list, tuple, set)):
            raise ValueError("allowed_r4_actions must be a list")
        actions = frozenset(str(x).strip().lower() for x in raw_actions if str(x).strip())
        unknown = actions - R4_ACTIONS
        if unknown: raise ValueError(f"ROE contains unknown R4 actions: {sorted(unknown)}")
        impact = str(raw.get("max_impact", "high")).strip().lower()
        if impact not in _ALLOWED_IMPACT: raise ValueError(f"max_impact must be one of {sorted(_ALLOWED_IMPACT)}")
        enabled = _bool(raw.get("enable_r4", False))
        operator, reference = str(raw.get("operator", "")).strip(), str(raw.get("engagement_reference", "")).strip()
        if enabled and (not operator or not reference): raise ValueError("enabled R4 ROE requires operator and engagement_reference")
        if enabled and impact != "high": raise ValueError("enabled R4 ROE requires max_impact='high'")
        return cls(enabled=enabled, allowed_actions=actions, max_impact=impact,
                   fake_data_only=_bool(raw.get("fake_data_only", True), True),
                   production_change_allowed=_bool(raw.get("production_change_allowed", False)),
                   third_party_assets_allowed=_bool(raw.get("third_party_assets_allowed", False)),
                   time_window=str(raw.get("time_window")).strip() if raw.get("time_window") else None,
                   emergency_stop=_bool(raw.get("emergency_stop", False)), operator=operator,
                   engagement_reference=reference, target=str(raw.get("target", "")).strip())

    @classmethod
    def from_file(cls, path: str | Path | None) -> "ROEPolicy":
        if not path:
            return cls()
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise ValueError(f"ROE file does not exist: {p}")
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid ROE file: {p}") from exc
        if not isinstance(raw, dict):
            raise ValueError("ROE must be a JSON object")
        raw_actions = raw.get("allowed_r4_actions", [])
        if not isinstance(raw_actions, (list, tuple, set)):
            raise ValueError("allowed_r4_actions must be a list")
        actions = frozenset(str(x).strip().lower() for x in raw_actions if str(x).strip())
        unknown = actions - R4_ACTIONS
        if unknown:
            raise ValueError(f"ROE contains unknown R4 actions: {sorted(unknown)}")
        impact = str(raw.get("max_impact", "high")).strip().lower()
        if impact not in _ALLOWED_IMPACT:
            raise ValueError(f"max_impact must be one of {sorted(_ALLOWED_IMPACT)}")
        enabled = _bool(raw.get("enable_r4", False))
        operator = str(raw.get("operator", "")).strip()
        reference = str(raw.get("engagement_reference", "")).strip()
        if enabled and (not operator or not reference):
            raise ValueError("enabled R4 ROE requires operator and engagement_reference")
        if enabled and impact != "high":
            raise ValueError("enabled R4 ROE requires max_impact='high'")
        return cls(
            enabled=enabled, allowed_actions=actions, max_impact=impact,
            fake_data_only=_bool(raw.get("fake_data_only", True), True),
            production_change_allowed=_bool(raw.get("production_change_allowed", False)),
            third_party_assets_allowed=_bool(raw.get("third_party_assets_allowed", False)),
            time_window=str(raw.get("time_window")).strip() if raw.get("time_window") else None,
            emergency_stop=_bool(raw.get("emergency_stop", False)),
            operator=operator, engagement_reference=reference,
            target=str(raw.get("target", "")).strip(),
        )

    def permits(self, action: str, *, target: str | None = None) -> bool:
        action = (action or "").strip().lower()
        if not (self.enabled and not self.emergency_stop and action in self.allowed_actions and action in R4_ACTIONS):
            return False
        if self.max_impact != "high":
            return False
        if self.target and target and self.target.strip().lower() != target.strip().lower():
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "enable_r4": self.enabled, "allowed_r4_actions": sorted(self.allowed_actions),
            "max_impact": self.max_impact, "fake_data_only": self.fake_data_only,
            "production_change_allowed": self.production_change_allowed,
            "third_party_assets_allowed": self.third_party_assets_allowed,
            "time_window": self.time_window, "emergency_stop": self.emergency_stop,
            "operator": self.operator, "engagement_reference": self.engagement_reference,
            "target": self.target,
        }

def default_roe_template() -> dict[str, Any]:
    return {
        "enable_r4": False, "allowed_r4_actions": [], "max_impact": "high",
        "fake_data_only": True, "production_change_allowed": False,
        "third_party_assets_allowed": False, "time_window": None,
        "emergency_stop": False, "operator": "", "engagement_reference": "", "target": "",
    }
