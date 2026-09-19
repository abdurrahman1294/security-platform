#!/usr/bin/env python3
"""Durable, single-use human approval queue.

Raw approval tokens are never persisted. Only a SHA-256 digest is stored, so
an approved request can safely survive a CLI/process restart.
"""
from __future__ import annotations
import hashlib, json, secrets, time, threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from modules.atomic_io import atomic_write_json, load_json

@dataclass
class ApprovalRequest:
    request_id: str
    action: str
    target: str
    reason: str
    risk: str
    created_at: float
    expires_at: float
    status: str = "pending"
    token_hash: str | None = None
    used_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id, "action": self.action, "target": self.target,
            "reason": self.reason, "risk": self.risk, "created_at": self.created_at,
            "expires_at": self.expires_at, "status": self.status,
            "has_token": bool(self.token_hash), "used_at": self.used_at,
        }

class ApprovalQueue:
    def __init__(self, root: str | Path, default_ttl_seconds: int = 3600):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "approval-queue.json"
        self.default_ttl = max(60, min(int(default_ttl_seconds), 86400))
        self._items: dict[str, ApprovalRequest] = {}
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        raw = load_json(self.path, {"items": []})
        rows = raw.get("items", []) if isinstance(raw, dict) else []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict): continue
            try:
                rid = str(row.get("request_id") or "").strip()
                if not rid: continue
                self._items[rid] = ApprovalRequest(
                    request_id=rid, action=str(row.get("action") or "").strip(),
                    target=str(row.get("target") or "").strip(), reason=str(row.get("reason") or "")[:500],
                    risk=str(row.get("risk") or "R3"), created_at=float(row.get("created_at") or 0),
                    expires_at=float(row.get("expires_at") or 0), status=str(row.get("status") or "pending"),
                    token_hash=str(row.get("token_hash")) if row.get("token_hash") else None,
                    used_at=float(row["used_at"]) if row.get("used_at") is not None else None,
                )
            except (TypeError, ValueError):
                continue

    def _save(self) -> None:
        atomic_write_json(self.path, {"items": [r.to_dict() | {"token_hash": r.token_hash} for r in self._items.values()]})

    def _expire(self) -> None:
        now = time.time(); changed = False
        for req in self._items.values():
            if req.status in {"pending", "approved"} and req.expires_at <= now:
                req.status = "expired"; req.token_hash = None; changed = True
        if changed: self._save()

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def submit(self, action: str, target: str, reason: str, risk: str = "R3") -> ApprovalRequest:
        with self._lock:
            self._expire(); now = time.time()
            rid = secrets.token_hex(12)
            req = ApprovalRequest(rid, action.strip(), str(target).strip(), reason.strip()[:500], risk, now, now + self.default_ttl)
            self._items[rid] = req; self._save(); return req

    def approve(self, request_id: str) -> str | None:
        with self._lock:
            self._expire(); req = self._items.get(str(request_id))
            if not req or req.status != "pending": return None
            token = secrets.token_urlsafe(32)
            req.status = "approved"; req.token_hash = self._hash(token); req.expires_at = time.time() + min(self.default_ttl, 1800)
            self._save(); return token

    def deny(self, request_id: str) -> bool:
        with self._lock:
            self._expire(); req = self._items.get(str(request_id))
            if not req or req.status != "pending": return False
            req.status = "denied"; req.token_hash = None; self._save(); return True

    def consume_token(self, request_id: str, token: str, action: str, target: str) -> bool:
        with self._lock:
            self._expire(); req = self._items.get(str(request_id))
            if not req or req.status != "approved" or not req.token_hash or not token: return False
            if not secrets.compare_digest(req.token_hash, self._hash(token)): return False
            if req.action != str(action).strip() or req.target != str(target).strip(): return False
            req.token_hash = None; req.status = "consumed"; req.used_at = time.time(); self._save(); return True

    def consume(self, token: str, action: str, target: str) -> bool:
        """Consume a single-use approved token without exposing request storage."""
        with self._lock:
            self._expire()
            for req in self._items.values():
                if req.status == "approved" and req.token_hash and req.action == str(action).strip() and req.target == str(target).strip():
                    if secrets.compare_digest(req.token_hash, self._hash(token or "")):
                        req.token_hash = None; req.status = "consumed"; req.used_at = time.time(); self._save(); return True
        return False

    def find_active(self, action: str, target: str) -> ApprovalRequest | None:
        self._expire()
        action, target = str(action).strip(), str(target).strip()
        for req in self._items.values():
            if req.status in {"pending", "approved"} and req.action == action and req.target == target:
                return req
        return None

    def find_pending(self, action: str, target: str) -> ApprovalRequest | None:
        req = self.find_active(action, target)
        return req if req and req.status == "pending" else None

    def list_pending(self) -> list[dict[str, Any]]:
        self._expire(); return [r.to_dict() for r in self._items.values() if r.status == "pending"]
