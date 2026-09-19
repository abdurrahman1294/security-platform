#!/usr/bin/env python3
"""Unified evidence graph for assessment state."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


def _id(kind: str, value: str) -> str:
    h = hashlib.sha256(f"{kind}|{value}".encode()).hexdigest()[:12]
    return f"{kind}:{h}"


class EvidenceGraph:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "evidence" / "evidence-graph.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = {
            "nodes": {},
            "edges": [],
            "updated_at": None,
        }
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.data["nodes"] = raw.get("nodes") or {}
                    self.data["edges"] = raw.get("edges") or []
            except (OSError, json.JSONDecodeError):
                pass

    def save(self) -> Path:
        self.data["updated_at"] = time.time()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        return self.path

    def add_node(self, kind: str, key: str, **meta: Any) -> str:
        nid = _id(kind, key)
        node = self.data["nodes"].get(nid, {"id": nid, "kind": kind, "key": key})
        node.update({k: v for k, v in meta.items() if v is not None})
        self.data["nodes"][nid] = node
        return nid

    def add_edge(self, src: str, dst: str, rel: str) -> None:
        edge = {"src": src, "dst": dst, "rel": rel}
        if edge not in self.data["edges"]:
            self.data["edges"].append(edge)

    def ingest_hosts(self, hosts: list[str]) -> None:
        for h in hosts:
            h = (h or "").strip()
            if not h:
                continue
            self.add_node("asset", h, value=h)

    def ingest_finding(self, finding: dict[str, Any], state: str = "observed") -> str:
        name = str((finding.get("info") or {}).get("name") or finding.get("name") or "finding")
        host = str(finding.get("matched-at") or finding.get("host") or "")
        fid = self.add_node(
            "finding",
            f"{name}|{host}",
            name=name,
            host=host,
            severity=str((finding.get("info") or {}).get("severity") or "info"),
            state=state,
        )
        if host:
            aid = self.add_node("asset", host, value=host)
            self.add_edge(aid, fid, "has_finding")
        return fid

    def set_finding_state(self, finding_id: str, state: str) -> None:
        node = self.data["nodes"].get(finding_id)
        if node:
            node["state"] = state

    def summary(self) -> dict[str, Any]:
        kinds: dict[str, int] = {}
        states: dict[str, int] = {}
        for n in self.data["nodes"].values():
            kinds[n.get("kind", "?")] = kinds.get(n.get("kind", "?"), 0) + 1
            if n.get("kind") == "finding":
                st = n.get("state", "observed")
                states[st] = states.get(st, 0) + 1
        return {
            "nodes": len(self.data["nodes"]),
            "edges": len(self.data["edges"]),
            "kinds": kinds,
            "finding_states": states,
        }
