#!/usr/bin/env python3
"""Next-best-task prioritizer.

Produces ordered investigation tasks from current evidence/gaps.
Does not execute actions by itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(order=True)
class RankedTask:
    score: float
    action: str
    target: str
    reason: str
    risk: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "risk": self.risk,
        }


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _hosts_from_outdir(outdir: Path) -> list[str]:
    hosts: list[str] = []
    for rel in [
        "recon/live-hosts.txt",
        "recon/subdomains.txt",
        "web/urls.txt",
    ]:
        p = outdir / rel
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                part = line.strip().split()[0] if line.strip() else ""
                if part:
                    hosts.append(part)
    # unique preserve order
    seen = set()
    out = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def prioritize(outdir: str | Path, target: str) -> list[RankedTask]:
    root = Path(outdir)
    tasks: list[RankedTask] = []

    hosts = _hosts_from_outdir(root)
    findings = []
    for rel in [
        "vulns/findings.json",
        "api/api-findings.json",
        "servers/network-findings.txt",
    ]:
        p = root / rel
        if not p.exists():
            continue
        if p.suffix == ".json":
            data = _load_json(p)
            if isinstance(data, list):
                findings.extend(x for x in data if isinstance(x, dict))
            elif isinstance(data, dict):
                findings.append(data)
        else:
            # text findings imply candidates exist
            if p.read_text(encoding="utf-8", errors="ignore").strip():
                findings.append({"info": {"name": "text-findings", "severity": "medium"}, "host": target})

    # Discovery gaps
    if not hosts:
        tasks.append(RankedTask(100.0, "subdomain_enum", target, "No hosts discovered yet", "R1"))
        tasks.append(RankedTask(95.0, "http_probe", target, "Need live HTTP surface", "R1"))
        tasks.append(RankedTask(90.0, "port_scan", target, "Need open services", "R1"))
    else:
        tasks.append(RankedTask(70.0, "coverage_analysis", target, f"{len(hosts)} hosts known; analyze gaps", "R0"))
        if not (root / "vulns/findings.json").exists():
            tasks.append(RankedTask(85.0, "vuln_candidate_scan", target, "No vulnerability candidates yet", "R1"))
        if not (root / "web/urls.txt").exists():
            tasks.append(RankedTask(80.0, "web_crawl", hosts[0], "No crawled URLs yet", "R1"))

    # Finding-driven verification suggestions (approval-gated typically)
    sev_weight = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 1}
    for f in findings[:50]:
        info = f.get("info") if isinstance(f, dict) else {}
        if not isinstance(info, dict):
            info = {}
        sev = str(info.get("severity") or "info").lower()
        host = str(f.get("matched-at") or f.get("host") or target)
        name = str(info.get("name") or "finding")
        score = 60 + sev_weight.get(sev, 1)
        tasks.append(
            RankedTask(
                float(score),
                "controlled_validation",
                host,
                f"Validate candidate: {name}",
                "R3",
            )
        )

    # Always useful low-risk ops
    tasks.append(RankedTask(40.0, "draft_report", target, "Keep report artifacts current", "R0"))
    tasks.append(RankedTask(35.0, "normalize_assets", target, "Normalize discovered assets", "R0"))

    # Sort by score desc
    tasks.sort(key=lambda t: (-t.score, t.action, t.target, t.reason))

    # Dedup by action+target
    seen = set()
    ranked: list[RankedTask] = []
    for t in tasks:
        key = (t.action, t.target)
        if key in seen:
            continue
        seen.add(key)
        ranked.append(t)
    return ranked


def write_priority_queue(outdir: str | Path, target: str) -> Path:
    root = Path(outdir)
    root.mkdir(parents=True, exist_ok=True)
    ranked = prioritize(root, target)
    path = root / "evidence" / "next-tasks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([t.to_dict() for t in ranked], indent=2), encoding="utf-8")
    return path
