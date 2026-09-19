#!/usr/bin/env python3
"""High-risk action executor (control-plane + supervised stubs).

Even when the operator enables a high-risk action, this executor:
- re-checks token/ROE/kill switch
- writes a mandatory plan + audit record
- does NOT autonomously launch unrestricted exploit chains

For enabled actions it produces a supervised runbook and requires a second
per-run confirmation token consumption pattern via the controller.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from modules.high_risk_controls_v32 import HighRiskController


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def supervised_run(
    outdir: str | Path,
    action: str,
    *,
    token: str,
    target: str,
    controller: HighRiskController | None = None,
) -> dict[str, Any]:
    root = Path(outdir)
    ctl = controller or HighRiskController(root)
    ok, reason = ctl.is_allowed(action, token)
    if not ok:
        return {"status": "denied", "action": action, "reason": reason}

    # Consume enablement after one supervised planning run to force deliberate re-enable
    # for repeated high-risk activity (extreme care).
    plan_dir = root / "evidence" / "high-risk" / action
    plan_dir.mkdir(parents=True, exist_ok=True)

    plans = {
        "password_spray": f"""# Supervised Password Spray Plan
Target context: {target}
Status: ENABLED BY OPERATOR (single-use planning window)

Mandatory controls:
- Confirm lockout policy first
- Use very low rate
- Stop on lockout indicators
- Keep username list in-scope only
- Log every attempt ID

This platform will not auto-run mass spraying. Execute only with operator-chosen tooling under ROE.
""",
        "rce_chain": f"""# Supervised RCE Chain Plan
Target context: {target}

Mandatory controls:
- Minimum proof only
- No destructive payloads
- Capture evidence before/after
- Stop condition defined by operator
- No persistence unless separately enabled

This platform does not auto-chain arbitrary RCE. Operator performs/approves each hop.
""",
        "lateral_movement": f"""# Supervised Lateral Movement Plan
Target context: {target}

Mandatory controls:
- Explicit host allowlist
- Preferred use of valid authorized credentials
- Avoid noisy techniques unless ROE allows
- Document each hop

Not auto-executed as a blast-radius expander.
""",
        "persistence": f"""# Supervised Persistence Plan
Target context: {target}

WARNING: Persistence is high impact.
- Only if ROE explicitly requires it
- Prefer easily reversible methods
- Record cleanup steps before execution
- Disable this capability immediately after proof
""",
        "exfiltration_simulation": f"""# Supervised Exfiltration Simulation Plan
Target context: {target}

Controls:
- Use canary/sample data when possible
- Cap bytes transferred
- No bulk sensitive data movement
- Evidence of path only, unless ROE demands more
""",
    }

    content = plans.get(action, f"# Supervised plan for {action}\nTarget: {target}\n")
    plan_path = plan_dir / "PLAN.md"
    _write(plan_path, content)

    # single-use: disable after planning/supervised run marker
    ctl.disable_action(action)
    ctl._audit("supervised_run_completed_single_use", action=action, target=target)

    return {
        "status": "supervised_plan_created",
        "action": action,
        "target": target,
        "plan": str(plan_path),
        "note": (
            "High-risk action was operator-enabled and single-use consumed. "
            "Re-enable required before another high-risk run. "
            "No unrestricted autonomous execution performed."
        ),
    }
