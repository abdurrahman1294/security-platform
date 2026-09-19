#!/usr/bin/env python3
"""Controlled autonomous assessment loop.

Runs only policy-allowed tasks. R3+ requires approval tokens.
This is NOT an unrestricted exploit engine.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from modules.approval_queue import ApprovalQueue
from modules.autonomy_policy import AutonomyPolicy, Decision, RiskClass
from modules.task_prioritizer import prioritize, write_priority_queue
from modules.roe_policy_v18 import ROEPolicy


@dataclass
class LoopState:
    tasks_run: int = 0
    requests: int = 0
    hosts_seen: int = 0
    started_at: float = field(default_factory=time.time)
    log: list[dict[str, Any]] = field(default_factory=list)
    paused: bool = False

    def elapsed(self) -> float:
        return time.time() - self.started_at


# Safe built-in handlers (no external network by default in unit tests)
def _handle_local(action: str, target: str, outdir: Path) -> dict[str, Any]:
    evidence = outdir / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    if action in {"normalize_assets", "dedupe_evidence", "coverage_analysis", "draft_report", "prioritize_tasks", "load_state"}:
        note = evidence / f"auto-{action}.json"
        note.write_text(
            json.dumps({"action": action, "target": target, "status": "ok", "ts": time.time()}, indent=2),
            encoding="utf-8",
        )
        return {"status": "ok", "artifact": str(note)}
    if action == "preflight":
        return {"status": "ok", "detail": "preflight marker"}
    if action == "tool_inventory":
        return {"status": "ok", "detail": "inventory marker"}
    # Discovery-like actions are recorded as planned markers in dry-run/local mode
    marker = evidence / f"planned-{action}.json"
    marker.write_text(
        json.dumps({"action": action, "target": target, "status": "planned-or-delegated", "ts": time.time()}, indent=2),
        encoding="utf-8",
    )
    return {"status": "delegated", "artifact": str(marker)}


class AutonomousLoop:
    def __init__(
        self,
        outdir: str | Path,
        target: str,
        policy: AutonomyPolicy | None = None,
        *,
        authorized: bool = False,
        in_scope: bool = False,
        dry_run: bool = True,
        executor: Callable[[str, str, Path], dict[str, Any]] | None = None,
        scope_file: str | Path | None = None,
        roe: ROEPolicy | None = None,
    ):
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.target = target
        self.policy = policy or AutonomyPolicy(profile="assess")
        self.authorized = bool(authorized)
        self.in_scope = bool(in_scope)
        self.dry_run = bool(dry_run)
        self.scope_file = scope_file
        self.roe = roe or ROEPolicy()
        if executor is not None:
            self.executor = executor
        elif not self.dry_run:
            from modules.tool_executor import build_executor
            self.executor = build_executor(self.outdir, scope_file=scope_file)
        else:
            self.executor = _handle_local
        self.queue = ApprovalQueue(self.outdir / "evidence")
        self.state = LoopState()

    def pause(self) -> None:
        self.state.paused = True
        self.policy.kill_switch = True

    def resume(self) -> None:
        self.state.paused = False
        self.policy.kill_switch = False

    def _record(self, entry: dict[str, Any]) -> None:
        self.state.log.append(entry)
        log_path = self.outdir / "evidence" / "autonomous-loop.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def run_once(self, approval_tokens: dict[str, str] | None = None) -> dict[str, Any]:
        approval_tokens = approval_tokens or {}
        if self.state.paused or self.policy.kill_switch:
            return {"status": "paused_or_killed"}

        if self.policy.budgets.exhausted(
            self.state.tasks_run, self.state.elapsed(), self.state.requests, self.state.hosts_seen
        ):
            return {"status": "budget_exhausted"}

        write_priority_queue(self.outdir, self.target)
        tasks = prioritize(self.outdir, self.target)
        if not tasks:
            return {"status": "idle", "detail": "no tasks"}

        results = []
        for task in tasks:
            if self.policy.budgets.exhausted(
                self.state.tasks_run, self.state.elapsed(), self.state.requests, self.state.hosts_seen
            ):
                break

            # Approval tokens are request-bound. For compatibility, an action-keyed
            # token is also accepted, but it must still match a pending request.
            pending = self.queue.find_active(task.action, task.target)
            supplied = None
            if pending:
                supplied = approval_tokens.get(pending.request_id) or approval_tokens.get(task.action)
            if supplied and pending and self.queue.consume_token(pending.request_id, supplied, task.action, task.target):
                supplied = supplied
            else:
                supplied = None

            decision = self.policy.decide(
                task.action, authorized=self.authorized, in_scope=self.in_scope,
                approval_token=supplied,
                roe_permitted=self.roe.permits(task.action, target=task.target),
            )

            entry = {
                "ts": time.time(),
                "action": task.action,
                "target": task.target,
                "risk": task.risk,
                "score": task.score,
                "decision": decision.value,
            }

            if decision == Decision.DENY:
                entry["status"] = "denied"
                self._record(entry)
                results.append(entry)
                continue

            if decision == Decision.NEEDS_APPROVAL:
                req = self.queue.find_pending(task.action, task.target) or self.queue.submit(task.action, task.target, task.reason, risk=task.risk)
                entry["status"] = "queued_for_approval"
                entry["request_id"] = req.request_id
                self._record(entry)
                results.append(entry)
                continue

            # ALLOW_AUTO
            if self.dry_run:
                entry["status"] = "dry_run"
                self._record(entry)
                results.append(entry)
                self.state.tasks_run += 1
                continue

            try:
                out = self.executor(task.action, task.target, self.outdir)
                entry["result"] = out
                entry["status"] = "executed" if not isinstance(out, dict) or str(out.get("status", "")).lower() in {"ok", "completed", "executed", "delegated"} else "execution_failed"
                self.state.tasks_run += 1
                self.state.requests += 1
                self.state.hosts_seen = min(self.policy.budgets.max_hosts, self.state.hosts_seen + 1)
            except Exception as exc:  # noqa: BLE001 - loop must continue
                entry["status"] = "error"
                entry["error"] = str(exc)
            self._record(entry)
            results.append(entry)

        return {
            "status": "ok",
            "policy": self.policy.to_dict(),
            "results": results,
            "pending_approvals": self.queue.list_pending(),
            "tasks_run": self.state.tasks_run,
            "elapsed": self.state.elapsed(),
        }

    def run(self, cycles: int = 1, approval_tokens: dict[str, str] | None = None) -> dict[str, Any]:
        cycles = max(1, min(int(cycles), 20))
        cycle_out = []
        for i in range(cycles):
            out = self.run_once(approval_tokens=approval_tokens)
            cycle_out.append({"cycle": i + 1, **out})
            if out.get("status") in {"paused_or_killed", "budget_exhausted", "idle"}:
                break
        summary = {
            "target": self.target,
            "roe": self.roe.to_dict(),
            "authorized": self.authorized,
            "in_scope": self.in_scope,
            "dry_run": self.dry_run,
            "cycles": cycle_out,
            "tasks_run_total": self.state.tasks_run,
        }
        path = self.outdir / "evidence" / "autonomous-summary.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
