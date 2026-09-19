#!/usr/bin/env python3
"""Operator-controlled high-risk capability gates.

Default: all high-risk capabilities are DISABLED.
They can be enabled only with:
1) explicit written-authorization assertion
2) machine-readable ROE allowlist
3) multi-step operator confirmation phrases
4) non-expired session enablement token
5) kill switch not active

This module is a control plane. It does not implement unrestricted
autonomous exploitation chains by itself.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


HIGH_RISK_ACTIONS = {
    "rce_chain": {
        "title": "RCE chaining (authorized)",
        "risk": "critical",
        "description": "Multi-step remote code execution proof under ROE",
    },
    "password_spray": {
        "title": "Password spraying (authorized)",
        "risk": "high",
        "description": "Low-and-slow credential spraying only if ROE explicitly allows",
    },
    "lateral_movement": {
        "title": "Lateral movement (authorized)",
        "risk": "critical",
        "description": "Movement between hosts only on authorized paths",
    },
    "persistence": {
        "title": "Persistence (authorized)",
        "risk": "critical",
        "description": "Persistence techniques only when ROE explicitly requires/allows",
    },
    "exfiltration_simulation": {
        "title": "Exfiltration simulation (authorized)",
        "risk": "critical",
        "description": "Controlled proof of data access/exfil path without uncontrolled bulk theft",
    },
}

# Operator must type these exact phrases (multi-step).
CONFIRM_PHRASES = {
    "rce_chain": "I AUTHORIZE RCE CHAIN UNDER ROE",
    "password_spray": "I AUTHORIZE PASSWORD SPRAY UNDER ROE",
    "lateral_movement": "I AUTHORIZE LATERAL MOVEMENT UNDER ROE",
    "persistence": "I AUTHORIZE PERSISTENCE UNDER ROE",
    "exfiltration_simulation": "I AUTHORIZE EXFIL SIMULATION UNDER ROE",
}

MASTER_PHRASE = "I ACCEPT FULL RESPONSIBILITY FOR HIGH-RISK ACTIONS"


@dataclass
class HighRiskSession:
    enabled_actions: set[str] = field(default_factory=set)
    tokens: dict[str, str] = field(default_factory=dict)
    expires_at: dict[str, float] = field(default_factory=dict)
    kill_switch: bool = False
    authorized: bool = False
    roe_path: str | None = None
    audit: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled_actions": sorted(self.enabled_actions),
            "kill_switch": self.kill_switch,
            "authorized": self.authorized,
            "roe_path": self.roe_path,
            "expires_at": self.expires_at,
            "tokens_present": sorted(self.tokens.keys()),
        }


class HighRiskController:
    def __init__(self, root: str | Path, ttl_seconds: int = 1800):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "evidence" / "high-risk-session.json"
        self.audit_path = self.root / "evidence" / "high-risk-audit.jsonl"
        self.ttl = max(300, int(ttl_seconds))
        self.session = HighRiskSession()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self.session.kill_switch = bool(raw.get("kill_switch"))
        self.session.authorized = bool(raw.get("authorized"))
        self.session.roe_path = raw.get("roe_path")
        self.session.enabled_actions = set(raw.get("enabled_actions") or [])
        self.session.expires_at = {k: float(v) for k, v in (raw.get("expires_at") or {}).items()}
        # tokens intentionally not reloaded from disk
        self.session.tokens = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.session.to_dict()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def _audit(self, event: str, **kwargs: Any) -> None:
        row = {"ts": time.time(), "event": event, **kwargs}
        self.session.audit.append(row)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")

    def engage_kill_switch(self) -> None:
        self.session.kill_switch = True
        self.session.enabled_actions.clear()
        self.session.tokens.clear()
        self.session.expires_at.clear()
        self._save()
        self._audit("kill_switch_engaged")

    def clear_kill_switch(self, *, master_phrase: str) -> bool:
        if master_phrase != MASTER_PHRASE:
            self._audit("kill_switch_clear_denied")
            return False
        self.session.kill_switch = False
        self._save()
        self._audit("kill_switch_cleared")
        return True

    def load_roe(self, roe_path: str | Path) -> dict[str, Any]:
        path = Path(roe_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("ROE must be a JSON object")
        self.session.roe_path = str(path)
        self._save()
        self._audit("roe_loaded", path=str(path))
        return data

    def _roe_allows(self, action: str) -> bool:
        if not self.session.roe_path:
            return False
        path = Path(self.session.roe_path)
        if not path.exists():
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = data.get("allow_high_risk_actions") or data.get("high_risk_allow") or []
        if not isinstance(allowed, list):
            return False
        return action in allowed or "*" in allowed

    def enable_action(
        self,
        action: str,
        *,
        authorized: bool,
        master_phrase: str,
        action_phrase: str,
    ) -> dict[str, Any]:
        if action not in HIGH_RISK_ACTIONS:
            return {"status": "denied", "reason": "unknown_action"}
        if self.session.kill_switch:
            return {"status": "denied", "reason": "kill_switch_active"}
        if not authorized:
            return {"status": "denied", "reason": "authorization_flag_required"}
        if master_phrase != MASTER_PHRASE:
            self._audit("enable_denied", action=action, reason="bad_master_phrase")
            return {"status": "denied", "reason": "master_phrase_mismatch"}
        if action_phrase != CONFIRM_PHRASES[action]:
            self._audit("enable_denied", action=action, reason="bad_action_phrase")
            return {"status": "denied", "reason": "action_phrase_mismatch"}
        if not self._roe_allows(action):
            self._audit("enable_denied", action=action, reason="roe_disallows")
            return {"status": "denied", "reason": "roe_does_not_allow_action"}

        token = secrets.token_urlsafe(24)
        exp = time.time() + self.ttl
        self.session.authorized = True
        self.session.enabled_actions.add(action)
        self.session.tokens[action] = token
        self.session.expires_at[action] = exp
        self._save()
        self._audit("action_enabled", action=action, expires_at=exp)
        return {
            "status": "enabled",
            "action": action,
            "token": token,
            "expires_at": exp,
            "ttl_seconds": self.ttl,
            "title": HIGH_RISK_ACTIONS[action]["title"],
            "control": "operator can disable via kill-switch at any time",
        }

    def disable_action(self, action: str) -> bool:
        self.session.enabled_actions.discard(action)
        self.session.tokens.pop(action, None)
        self.session.expires_at.pop(action, None)
        self._save()
        self._audit("action_disabled", action=action)
        return True

    def is_allowed(self, action: str, token: str | None = None) -> tuple[bool, str]:
        if self.session.kill_switch:
            return False, "kill_switch_active"
        if action not in self.session.enabled_actions:
            return False, "action_not_enabled"
        exp = self.session.expires_at.get(action, 0)
        if exp <= time.time():
            self.disable_action(action)
            return False, "enablement_expired"
        if not self._roe_allows(action):
            return False, "roe_does_not_allow_action"
        expected = self.session.tokens.get(action)
        if expected is None:
            # token not in memory (process restart) — require re-enable
            return False, "reauthorization_required_after_reload"
        if not token or token != expected:
            return False, "token_mismatch"
        return True, "ok"

    def status(self) -> dict[str, Any]:
        # expire stale
        now = time.time()
        for action, exp in list(self.session.expires_at.items()):
            if exp <= now:
                self.disable_action(action)
        return {
            "kill_switch": self.session.kill_switch,
            "authorized": self.session.authorized,
            "roe_path": self.session.roe_path,
            "enabled_actions": sorted(self.session.enabled_actions),
            "available_actions": HIGH_RISK_ACTIONS,
            "confirm_phrases": CONFIRM_PHRASES,
            "master_phrase": MASTER_PHRASE,
            "ttl_seconds": self.ttl,
        }


def default_roe_template() -> dict[str, Any]:
    return {
        "engagement": "replace-me",
        "written_authorization": False,
        "scope_file": "config/scope.example.txt",
        "allow_high_risk_actions": [
            # Explicitly list actions if authorized. Empty means none.
            # "password_spray",
            # "rce_chain",
            # "lateral_movement",
            # "persistence",
            # "exfiltration_simulation",
        ],
        "notes": "Empty allow list is safest. Only add actions explicitly permitted by ROE.",
    }
