"""V3.57 canonical engagement state.

SQLite is the durable source of truth for reasoning state.  This module stores
observations, hypotheses, planned tasks, and execution episodes only.  It never
executes security actions and never grants authorization.
"""
from __future__ import annotations

import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Any

VERSION = "3.57.0"

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    artifact TEXT,
    value_json TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    rationale TEXT NOT NULL,
    confidence REAL NOT NULL,
    priority REAL NOT NULL,
    status TEXT NOT NULL,
    basis_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    score REAL NOT NULL,
    risk TEXT NOT NULL,
    status TEXT NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 1,
    basis_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase TEXT NOT NULL,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fp(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(x) for x in parts).encode()).hexdigest()


class EngagementState:
    """Small transactional state kernel used by the V3.57 reasoning layer."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "state" / "engagement.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(_SCHEMA)
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (VERSION,))

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def observation(self, *, kind: str, source: str, value: Any,
                    artifact: str = "", confidence: float = 0.5) -> bool:
        fp = _fp(kind, source, artifact, _json(value))
        with self.connect() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO observations(fingerprint,kind,source,artifact,value_json,confidence) VALUES(?,?,?,?,?,?)",
                (fp, kind, source, artifact, _json(value), max(0.0, min(1.0, float(confidence))))
            )
            return cur.rowcount == 1

    def hypothesis(self, *, title: str, rationale: str, confidence: float,
                   priority: float, status: str = "candidate", basis: Any = ()) -> bool:
        fp = _fp(title, rationale)
        with self.connect() as db:
            cur = db.execute(
                """INSERT INTO hypotheses(fingerprint,title,rationale,confidence,priority,status,basis_json)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(fingerprint) DO UPDATE SET confidence=excluded.confidence,
                   priority=excluded.priority,status=excluded.status,basis_json=excluded.basis_json,
                   updated_at=CURRENT_TIMESTAMP""",
                (fp, title, rationale, float(confidence), float(priority), status, _json(basis))
            )
            return cur.rowcount == 1

    def task(self, *, action: str, target: str, reason: str, score: float,
             risk: str, status: str = "planned", requires_approval: bool = True,
             basis: Any = ()) -> bool:
        fp = _fp(action, target, reason)
        with self.connect() as db:
            cur = db.execute(
                """INSERT INTO tasks(fingerprint,action,target,reason,score,risk,status,requires_approval,basis_json)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(fingerprint) DO UPDATE SET score=excluded.score,
                   risk=excluded.risk,status=excluded.status,requires_approval=excluded.requires_approval,
                   basis_json=excluded.basis_json,updated_at=CURRENT_TIMESTAMP""",
                (fp, action, target, reason, float(score), risk, status, int(bool(requires_approval)), _json(basis))
            )
            return cur.rowcount == 1

    def episode(self, phase: str, status: str, details: Any) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO episodes(phase,status,details_json) VALUES(?,?,?)", (phase, status, _json(details)))

    def snapshot(self, limit: int = 50) -> dict[str, Any]:
        with self.connect() as db:
            def rows(table: str, order: str) -> list[dict[str, Any]]:
                rs = db.execute(f"SELECT * FROM {table} ORDER BY {order} LIMIT ?", (limit,)).fetchall()
                out = []
                for r in rs:
                    d = dict(r)
                    for k in ("value_json", "basis_json", "details_json"):
                        if k in d:
                            try: d[k[:-5] if k.endswith("_json") else k] = json.loads(d.pop(k))
                            except json.JSONDecodeError: pass
                    out.append(d)
                return out
            return {
                "schema_version": VERSION,
                "observations": rows("observations", "id DESC"),
                "hypotheses": rows("hypotheses", "priority DESC, id DESC"),
                "tasks": rows("tasks", "score DESC, id DESC"),
                "episodes": rows("episodes", "id DESC"),
            }
