#!/usr/bin/env python3
"""Authenticated assessment depth helpers (session import + role matrix)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def load_session_from_env() -> dict[str, str]:
    sess = {}
    if os.getenv("PENTEST_AUTH_COOKIE"):
        sess["cookie"] = os.environ["PENTEST_AUTH_COOKIE"]
    if os.getenv("PENTEST_AUTH_BEARER"):
        sess["bearer"] = os.environ["PENTEST_AUTH_BEARER"]
    if os.getenv("PENTEST_JWT"):
        sess["jwt"] = os.environ["PENTEST_JWT"]
    if os.getenv("PENTEST_AUTH_HEADER"):
        sess["header"] = os.environ["PENTEST_AUTH_HEADER"]
    return sess


def write_session_bundle(outdir: str | Path, session: dict[str, str] | None = None) -> Path:
    root = Path(outdir)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    sess = session if session is not None else load_session_from_env()
    # Redact values in on-disk bundle metadata, keep presence flags only by default.
    safe = {k: ("[PRESENT]" if v else "[MISSING]") for k, v in sess.items()}
    path = evidence / "auth-session.json"
    path.write_text(
        json.dumps({"present": safe, "raw_in_env": bool(sess), "note": "raw secrets kept in env, not duplicated"}, indent=2),
        encoding="utf-8",
    )
    return path


def build_role_matrix(outdir: str | Path, roles: list[str] | None = None) -> Path:
    root = Path(outdir)
    roles = roles or ["anonymous", "user", "admin"]
    matrix = {
        "roles": roles,
        "tests": [
            {"id": "horizontal-object-access", "description": "Access peer object IDs as role A/B"},
            {"id": "vertical-admin-function", "description": "Call admin functions as lower role"},
            {"id": "session-logout-invalidation", "description": "Reuse session after logout"},
            {"id": "token-tamper-role-claim", "description": "Observe server response to altered role claims"},
        ],
        "status": "planned",
        "note": "Matrix is guidance for authenticated assessment; execution remains operator-approved.",
    }
    path = root / "evidence" / "role-matrix.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    md = root / "evidence" / "AUTH-ROLE-MATRIX.md"
    lines = ["# Authenticated Role Matrix", "", f"Roles: {', '.join(roles)}", ""]
    for t in matrix["tests"]:
        lines.append(f"- [{t['id']}] {t['description']}")
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
