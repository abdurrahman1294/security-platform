"""V241 research-exhaustion planner.

Turns accumulated evidence into a bounded, resumable investigation queue.  It
never expands scope and never executes arbitrary commands.  The queue is a
coverage mechanism: keep investigating while new assets, endpoints, roles,
technologies, findings, or attack-path hypotheses appear; stop only when the
current evidence produces no new high-value work and the coverage review has
been emitted.
"""
from __future__ import annotations

from pathlib import Path
from .atomic_io import atomic_write_json, load_json

DOMAINS = (
    "recon", "web", "api", "identity", "authentication", "authorization",
    "session", "input", "client", "business_logic", "cloud", "infrastructure",
    "osint", "findings", "evidence", "manual_review",
)


def _count(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return 0


def build(root, target="", round_limit=8):
    root = Path(root)
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)

    assets = load_json(ev / "assets.json", {})
    findings = load_json(ev / "normalized-findings.json", {})
    web = load_json(ev / "web-surface-v45.json", {})
    api = load_json(ev / "api-surface-v58.json", {})
    plan = load_json(ev / "bug-bounty-plan-v239.json", {})
    osint = load_json(ev / "osint-correlation-v235.json", {})
    gaps = load_json(ev / "osint-gap-analysis-v236.json", {})

    counts = {
        "assets": _count(assets.get("assets", assets if isinstance(assets, list) else [])),
        "findings": _count(findings.get("findings", findings if isinstance(findings, list) else [])),
        "web_endpoints": _count(web.get("endpoints", web.get("routes", []))),
        "api_items": _count(api.get("endpoints", api.get("operations", []))),
        "bounty_tests": sum(len(x.get("tests", [])) for x in plan.get("plan", [])),
        "osint_entities": _count(osint.get("entities", [])),
    }

    queue = []
    if counts["assets"] == 0:
        queue.append(("recon", "asset discovery and scope-confirmed enumeration"))
    if counts["web_endpoints"] == 0:
        queue.append(("web", "discover and fingerprint web endpoints"))
    if counts["api_items"] == 0:
        queue.append(("api", "discover API schemas, operations and parameters"))
    for domain in ("identity", "authentication", "authorization", "session", "input", "client", "business_logic"):
        queue.append((domain, f"execute or manually validate {domain.replace('_', ' ')} coverage"))
    if counts["findings"]:
        queue.append(("findings", "deduplicate, correlate, validate and prioritize every material finding"))
    else:
        queue.append(("findings", "review scanner output and negative/empty-result evidence"))
    if gaps.get("dimensions"):
        missing = [x["dimension"] for x in gaps["dimensions"] if x.get("status") == "gap"]
        if missing:
            queue.append(("osint", "expand only the missing public-source dimensions: " + ", ".join(missing)))
    queue.extend([
        ("evidence", "verify provenance, timestamps, hashes, scope and reproducibility"),
        ("manual_review", "review creative/custom-logic hypotheses and residual blind spots"),
    ])

    # Deterministic de-duplication keeps resume/replay stable.
    seen = set()
    tasks = []
    for domain, action in queue:
        if domain not in DOMAINS or domain in seen:
            continue
        seen.add(domain)
        tasks.append({
            "task_id": f"V241-{len(tasks)+1:03d}",
            "domain": domain,
            "action": action,
            "priority": "critical" if domain in {"authorization", "authentication", "business_logic"} else "high",
            "status": "queued",
            "scope_change_allowed": False,
            "consequential_action": False,
        })

    data = {
        "schema_version": "241.0",
        "target": target,
        "round_limit": max(1, min(int(round_limit), 32)),
        "stop_condition": "No new high-value evidence or hypotheses plus explicit coverage review",
        "counts": counts,
        "tasks": tasks,
        "method": [
            "seed from evidence",
            "investigate new leads",
            "re-correlate after each completed task",
            "requeue only genuinely new high-value work",
            "perform coverage/blind-spot review",
            "require human confirmation for consequential findings and custom business logic",
        ],
        "safety": {
            "scope_expansion": False,
            "arbitrary_shell": False,
            "credential_theft": False,
            "persistence": False,
            "exfiltration": False,
            "automatic_submission": False,
            "human_review_required": True,
        },
    }
    atomic_write_json(ev / "research-exhaustion-v241.json", data)
    return data
