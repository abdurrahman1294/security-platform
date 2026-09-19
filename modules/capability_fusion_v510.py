"""V5.1 Capability Fusion extensions.

Original implementation informed by publicly documented architecture of:
  - PentestGPT (MIT): PTT, reasoning/generation/parsing roles, episode walkthrough
  - HexStrike AI (MIT): findings importers, process ledger, two-phase port planning, SARIF

Explicitly NOT implemented (Xanthorox / criminal tooling):
  malware/ransomware generation, phishing/BEC content generation, deepfake fraud,
  unrestricted payload factories, covert C2, or any unauthorized attack capability.

All execution remains behind authorization, scope, and registered adapters.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

VERSION = "5.1.0"


def _fp(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _json_dump(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _safe_read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Pentesting Task Tree (PentestGPT-inspired, original structure)
# ---------------------------------------------------------------------------

@dataclass
class PTTNode:
    node_id: str
    title: str
    phase: str
    status: str = "pending"  # pending|active|done|blocked|skipped
    parent_id: str = ""
    findings: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class PentestingTaskTree:
    """Attributed task tree: maintains global strategy without LLM context loss."""

    PHASES = ("recon", "enumeration", "vulnerability", "validation", "reporting")

    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / "state" / "ptt-v510.json"
        self.nodes: dict[str, PTTNode] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            raw = _safe_read_json(self.path) or {}
            for n in raw.get("nodes", []):
                self.nodes[n["node_id"]] = PTTNode(**{k: n[k] for k in PTTNode.__dataclass_fields__ if k in n})

    def save(self) -> Path:
        payload = {
            "schema_version": VERSION,
            "nodes": [asdict(n) for n in sorted(self.nodes.values(), key=lambda x: x.created_at)],
            "updated_at": time.time(),
        }
        _json_dump(self.path, payload)
        return self.path

    def ensure_root(self, target: str, objective: str) -> str:
        rid = "root-" + _fp(target, objective)
        if rid not in self.nodes:
            self.nodes[rid] = PTTNode(
                node_id=rid,
                title=f"Engagement: {target}",
                phase="recon",
                status="active",
                notes=objective[:500],
            )
            for ph in self.PHASES:
                cid = f"{rid}:{ph}"
                self.nodes[cid] = PTTNode(
                    node_id=cid,
                    title=ph,
                    phase=ph,
                    parent_id=rid,
                    status="pending",
                )
            self.save()
        return rid

    def add_task(self, parent_id: str, title: str, phase: str, tools: Iterable[str] = ()) -> str:
        nid = "t-" + _fp(parent_id, title, time.time())
        self.nodes[nid] = PTTNode(
            node_id=nid,
            title=title[:200],
            phase=phase,
            parent_id=parent_id,
            tools=list(tools)[:12],
            status="pending",
        )
        self.save()
        return nid

    def set_status(self, node_id: str, status: str, finding: str = "") -> None:
        n = self.nodes.get(node_id)
        if not n:
            return
        n.status = status
        n.updated_at = time.time()
        if finding:
            n.findings.append(finding[:500])
        self.save()

    def snapshot(self) -> dict[str, Any]:
        by_phase: dict[str, list[dict]] = {p: [] for p in self.PHASES}
        for n in self.nodes.values():
            if n.phase in by_phase and n.parent_id:
                by_phase[n.phase].append(asdict(n))
        return {
            "schema_version": VERSION,
            "node_count": len(self.nodes),
            "by_phase": by_phase,
            "active": [asdict(n) for n in self.nodes.values() if n.status == "active"],
            "blocked": [asdict(n) for n in self.nodes.values() if n.status == "blocked"],
        }


# ---------------------------------------------------------------------------
# Reasoning / Generation / Parsing cycle (roles, not mandatory external LLM)
# ---------------------------------------------------------------------------

class ReasoningModule:
    """Lead-tester role: maintain PTT and choose next high-level focus."""

    def plan_next(self, tree: PentestingTaskTree, evidence_summary: dict[str, Any]) -> dict[str, Any]:
        open_nodes = [n for n in tree.nodes.values() if n.status in ("pending", "active") and n.parent_id]
        # Prefer recon → enumeration → vulnerability → validation → reporting
        order = {p: i for i, p in enumerate(PentestingTaskTree.PHASES)}
        open_nodes.sort(key=lambda n: (order.get(n.phase, 99), n.created_at))
        focus = open_nodes[0] if open_nodes else None
        return {
            "role": "reasoning",
            "focus_node": asdict(focus) if focus else None,
            "rationale": "phase-priority-deterministic",
            "evidence_keys": sorted(evidence_summary.keys())[:20],
            "requires_llm": False,
        }


class GenerationModule:
    """Junior-tester role: expand focus into concrete, scoped tool suggestions."""

    DEFAULT_TOOLS = {
        "recon": ["subfinder", "httpx", "naabu"],
        "enumeration": ["nmap", "katana", "gobuster"],
        "vulnerability": ["nuclei", "nikto"],
        "validation": ["curl", "httpx"],
        "reporting": [],
    }

    def expand(self, focus: dict[str, Any] | None, target: str, installed: set[str]) -> dict[str, Any]:
        phase = (focus or {}).get("phase", "recon")
        candidates = self.DEFAULT_TOOLS.get(phase, [])
        selected = [t for t in candidates if t in installed] or candidates[:2]
        steps = []
        for tool in selected:
            steps.append({
                "tool": tool,
                "target": target,
                "intent": f"{phase}:{tool}",
                "risk": "R1",
                "requires_registered_adapter": True,
                "command_template": f"#{tool} against {target} — execute only via registered adapter",
            })
        return {
            "role": "generation",
            "phase": phase,
            "steps": steps,
            "note": "Templates only; no shell execution from this module.",
        }


class ParsingModule:
    """Parser role: compress tool output into structured findings."""

    def parse_text(self, tool: str, text: str) -> dict[str, Any]:
        text = text or ""
        findings = []
        # Conservative patterns only
        for m in re.finditer(r"(?i)(critical|high|medium|low)\s*[:=-]?\s*([^\n]{5,120})", text):
            findings.append({"severity": m.group(1).lower(), "summary": m.group(2).strip(), "source": tool})
        ports = sorted(set(int(x) for x in re.findall(r"\b(\d{1,5})/tcp\b", text) if 1 <= int(x) <= 65535))[:50]
        urls = sorted(set(re.findall(r"https?://[^\s\"'<>]{5,200}", text)))[:50]
        return {
            "role": "parsing",
            "tool": tool,
            "finding_count": len(findings),
            "findings": findings[:30],
            "ports": ports,
            "urls": urls,
            "chars_in": len(text),
        }


class AgentCycle:
    """One deterministic reason → generate → parse episode."""

    def __init__(self, output: Path):
        self.output = Path(output)
        self.tree = PentestingTaskTree(self.output)
        self.reason = ReasoningModule()
        self.generate = GenerationModule()
        self.parse = ParsingModule()
        self.journal_path = self.output / "evidence" / "walkthrough-v510.jsonl"

    def run_episode(self, target: str, objective: str, installed_tools: Iterable[str] = (),
                    raw_tool_output: str = "", tool_name: str = "") -> dict[str, Any]:
        self.tree.ensure_root(target, objective)
        evidence = {"artifacts": [p.name for p in (self.output / "evidence").glob("*.json")][:40]} if (self.output / "evidence").exists() else {}
        r = self.reason.plan_next(self.tree, evidence)
        g = self.generate.expand(r.get("focus_node"), target, set(installed_tools))
        p = self.parse.parse_text(tool_name or "none", raw_tool_output) if raw_tool_output else {"role": "parsing", "finding_count": 0}
        episode = {
            "schema_version": VERSION,
            "ts": time.time(),
            "target": target,
            "reasoning": r,
            "generation": g,
            "parsing": p,
        }
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(episode, default=str) + "\n")
        _json_dump(self.output / "evidence" / "agent-cycle-v510.json", episode)
        _json_dump(self.output / "evidence" / "ptt-snapshot-v510.json", self.tree.snapshot())
        return episode


# ---------------------------------------------------------------------------
# Findings auto-import (HexStrike-inspired parsers — original code)
# ---------------------------------------------------------------------------

class FindingsImporter:
    def __init__(self, output: Path):
        self.output = Path(output)
        self.out = self.output / "evidence" / "imported-findings-v510.json"

    def import_nmap_xml(self, path: Path) -> list[dict]:
        findings = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except Exception as e:
            return [{"error": f"nmap-parse-failed: {e}"}]
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else ""
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") != "open":
                    continue
                svc = port.find("service")
                findings.append({
                    "source": "nmap",
                    "host": ip,
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": (svc.get("name") if svc is not None else ""),
                    "product": (svc.get("product") if svc is not None else ""),
                    "severity": "info",
                })
        return findings

    def import_nuclei_jsonl(self, path: Path) -> list[dict]:
        findings = []
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                info = obj.get("info") or {}
                findings.append({
                    "source": "nuclei",
                    "template": obj.get("template-id") or obj.get("templateID") or "",
                    "name": info.get("name", ""),
                    "severity": (info.get("severity") or "unknown"),
                    "host": obj.get("host") or obj.get("matched-at") or "",
                    "matched": obj.get("matched-at") or obj.get("match") or "",
                })
        except Exception as e:
            return [{"error": f"nuclei-parse-failed: {e}"}]
        return findings

    def import_httpx_json(self, path: Path) -> list[dict]:
        findings = []
        raw = path.read_text(encoding="utf-8", errors="replace")
        # JSONL or JSON array
        lines = [raw] if raw.strip().startswith("[") else raw.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                objs = json.loads(line)
                if not isinstance(objs, list):
                    objs = [objs]
            except Exception:
                continue
            for obj in objs:
                if not isinstance(obj, dict):
                    continue
                findings.append({
                    "source": "httpx",
                    "url": obj.get("url") or obj.get("input") or "",
                    "status_code": obj.get("status_code") or obj.get("status-code"),
                    "title": obj.get("title") or "",
                    "webserver": obj.get("webserver") or obj.get("server") or "",
                    "severity": "info",
                })
        return findings

    def run(self, paths: Iterable[str | Path]) -> dict[str, Any]:
        all_f: list[dict] = []
        for p in paths:
            path = Path(p)
            if not path.is_file():
                all_f.append({"error": f"missing:{path}"})
                continue
            name = path.name.lower()
            if path.suffix.lower() == ".xml" or "nmap" in name:
                all_f.extend(self.import_nmap_xml(path))
            elif "nuclei" in name or path.suffix.lower() in (".jsonl",):
                all_f.extend(self.import_nuclei_jsonl(path))
            elif "httpx" in name or path.suffix.lower() == ".json":
                # try nuclei jsonl first if looks like line-delimited
                sample = path.read_text(encoding="utf-8", errors="replace")[:200]
                if '"template-id"' in sample or '"templateID"' in sample:
                    all_f.extend(self.import_nuclei_jsonl(path))
                else:
                    all_f.extend(self.import_httpx_json(path))
            else:
                all_f.append({"error": f"unsupported:{path.name}"})
        report = {
            "schema_version": VERSION,
            "imported": len([x for x in all_f if "error" not in x]),
            "errors": len([x for x in all_f if "error" in x]),
            "findings": all_f[:500],
        }
        _json_dump(self.out, report)
        return report


# ---------------------------------------------------------------------------
# Process ledger (HexStrike-inspired — tracking only, no new shell)
# ---------------------------------------------------------------------------

class ProcessLedger:
    def __init__(self, output: Path):
        self.db_path = Path(output) / "state" / "process-ledger-v510.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS runs(
              run_id TEXT PRIMARY KEY,
              tool TEXT,
              target TEXT,
              pid INTEGER,
              status TEXT,
              started REAL,
              finished REAL,
              timeout_s INTEGER,
              exit_code INTEGER,
              evidence TEXT
            )""")

    def _db(self):
        return sqlite3.connect(self.db_path)

    def start(self, tool: str, target: str, timeout_s: int = 3600, pid: int = 0) -> str:
        rid = str(uuid.uuid4())
        with self._db() as c:
            c.execute(
                "INSERT INTO runs(run_id,tool,target,pid,status,started,finished,timeout_s,exit_code,evidence) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (rid, tool, target, pid, "running", time.time(), None, timeout_s, None, ""),
            )
        return rid

    def finish(self, run_id: str, status: str = "completed", exit_code: int = 0, evidence: str = "") -> None:
        with self._db() as c:
            c.execute(
                "UPDATE runs SET status=?, finished=?, exit_code=?, evidence=? WHERE run_id=?",
                (status, time.time(), exit_code, evidence[:1000], run_id),
            )

    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._db() as c:
            rows = c.execute(
                "SELECT run_id,tool,target,pid,status,started,finished,timeout_s,exit_code FROM runs ORDER BY started DESC LIMIT ?",
                (limit,),
            ).fetchall()
        keys = ["run_id", "tool", "target", "pid", "status", "started", "finished", "timeout_s", "exit_code"]
        return [dict(zip(keys, r)) for r in rows]


# ---------------------------------------------------------------------------
# Two-phase port pipeline planner (metadata only)
# ---------------------------------------------------------------------------

def plan_two_phase_port_scan(target: str, installed: Iterable[str] = ()) -> dict[str, Any]:
    inst = set(installed)
    fast = "naabu" if "naabu" in inst else ("rustscan" if "rustscan" in inst else "nmap")
    deep = "nmap"
    return {
        "schema_version": VERSION,
        "target": target,
        "pipeline": [
            {
                "phase": 1,
                "name": "fast-port-discovery",
                "tool": fast,
                "purpose": "Discover open ports quickly",
                "requires_registered_adapter": True,
            },
            {
                "phase": 2,
                "name": "service-detection",
                "tool": deep,
                "purpose": "Service/version detection only on discovered ports",
                "depends_on": "fast-port-discovery",
                "requires_registered_adapter": True,
            },
        ],
        "note": "Plan only — execution requires registered adapters + authorization + scope.",
    }


# ---------------------------------------------------------------------------
# SARIF export from imported findings
# ---------------------------------------------------------------------------

def findings_to_sarif(findings: list[dict], tool_name: str = "security-platform") -> dict[str, Any]:
    results = []
    for i, f in enumerate(findings):
        if "error" in f:
            continue
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(
            str(f.get("severity", "info")).lower(), "note"
        )
        msg = f.get("name") or f.get("summary") or f.get("template") or f.get("service") or "finding"
        loc = f.get("host") or f.get("url") or f.get("matched") or ""
        results.append({
            "ruleId": f.get("template") or f.get("source") or f"finding-{i}",
            "level": level,
            "message": {"text": str(msg)[:500]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(loc)[:300]}}}] if loc else [],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": VERSION, "informationUri": "https://localhost/lab-only"}},
            "results": results[:500],
        }],
    }


# ---------------------------------------------------------------------------
# Offline / local-first role routing (ethical analogue of multi-role systems)
# ---------------------------------------------------------------------------

def offline_role_matrix() -> dict[str, Any]:
    """Local specialist roles for authorized assessment — not malware generation."""
    return {
        "schema_version": VERSION,
        "mode": "offline-local-first",
        "roles": {
            "reasoner": {
                "purpose": "Maintain PTT, prioritize next authorized test, track blocked deps",
                "binds_to": "ReasoningModule",
            },
            "generator": {
                "purpose": "Expand tasks into registered-tool step templates",
                "binds_to": "GenerationModule",
            },
            "parser": {
                "purpose": "Normalize tool output into structured findings",
                "binds_to": "ParsingModule",
            },
            "reporter": {
                "purpose": "Coverage, SARIF, and operator-facing summaries",
                "binds_to": "findings_to_sarif",
            },
            "vision_evidence": {
                "purpose": "Record path/hash metadata for operator-supplied evidence images (no remote vision API required)",
                "binds_to": "evidence_image_register",
            },
        },
        "forbidden": [
            "malware_generation",
            "ransomware_generation",
            "phishing_content_generation",
            "deepfake_fraud",
            "unrestricted_payload_factory",
            "covert_c2",
        ],
        "note": "Inspired by public multi-role assistant patterns; original ethical implementation only.",
    }


def evidence_image_register(output: Path, image_paths: Iterable[str | Path]) -> dict[str, Any]:
    items = []
    for p in image_paths:
        path = Path(p)
        if not path.is_file():
            items.append({"path": str(p), "status": "missing"})
            continue
        data = path.read_bytes()[:1024 * 1024]
        items.append({
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(data if path.stat().st_size <= 1024 * 1024 else path.read_bytes()).hexdigest(),
            "status": "registered",
        })
    report = {"schema_version": VERSION, "images": items}
    _json_dump(Path(output) / "evidence" / "evidence-images-v510.json", report)
    return report


# ---------------------------------------------------------------------------
# Unified V5.1 control plane
# ---------------------------------------------------------------------------

class FusionEngineV51:
    def __init__(self, output: str | Path):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.cycle = AgentCycle(self.output)
        self.importer = FindingsImporter(self.output)
        self.ledger = ProcessLedger(self.output)

    def episode(self, target: str, objective: str = "authorized assessment",
                installed_tools: Iterable[str] = (), raw_output: str = "", tool: str = "") -> dict:
        return self.cycle.run_episode(target, objective, installed_tools, raw_output, tool)

    def import_findings(self, paths: Iterable[str | Path]) -> dict:
        return self.importer.run(paths)

    def port_pipeline(self, target: str, installed: Iterable[str] = ()) -> dict:
        plan = plan_two_phase_port_scan(target, installed)
        _json_dump(self.output / "evidence" / "port-pipeline-v510.json", plan)
        return plan

    def sarif_from_imports(self) -> dict:
        data = _safe_read_json(self.output / "evidence" / "imported-findings-v510.json") or {}
        sarif = findings_to_sarif(data.get("findings") or [])
        path = self.output / "reports" / "findings-v510.sarif.json"
        _json_dump(path, sarif)
        return {"path": str(path), "result_count": len((sarif.get("runs") or [{}])[0].get("results") or [])}

    def offline_roles(self) -> dict:
        roles = offline_role_matrix()
        _json_dump(self.output / "evidence" / "offline-roles-v510.json", roles)
        return roles

    def register_evidence_images(self, paths: Iterable[str | Path]) -> dict:
        return evidence_image_register(self.output, paths)

    def status(self) -> dict:
        return {
            "schema_version": VERSION,
            "ptt": self.cycle.tree.snapshot(),
            "process_runs": self.ledger.list_runs(20),
            "offline_roles": list(offline_role_matrix()["roles"].keys()),
            "governance": {
                "authorization_required": True,
                "scope_required": True,
                "no_arbitrary_shell": True,
                "no_malware_generation": True,
            },
        }
