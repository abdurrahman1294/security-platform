#!/usr/bin/env python3
"""Human-led Red Team Support Pack.

Assists authorized red team operations with structured playbooks, evidence
checklists, and command templates. Does NOT autonomously exploit, pivot,
persist, or exfiltrate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def generate_red_team_pack(outdir: str | Path, domain: str = "", dc_ip: str = "", target: str = "") -> dict:
    root = Path(outdir)
    root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    overview = f"""# Red Team Support Pack (Human-Led)
Generated: {ts}
Target: {target or '[TARGET]'}
Domain: {domain or '[DOMAIN]'}
DC/IP: {dc_ip or '[DC_IP]'}

## Purpose
Support authorized red team operations. This pack organizes work. It does not
replace operator judgment or automatically perform high-impact actions.

## Rules of engagement reminders
1. Stay inside written authorization and scope.
2. Prefer stealth and proportionality when required by ROE.
3. Record evidence IDs for every meaningful step.
4. High-impact actions require explicit operator decision.
5. No persistence/exfiltration unless explicitly authorized and necessary.

## Engagement phases
1. Objectives & success criteria
2. External surface mapping
3. Initial access hypotheses
4. Foothold validation (authorized)
5. Local situational awareness
6. Privilege hypotheses
7. Lateral movement hypotheses
8. Objective simulation / proof
9. Detection opportunities for blue team (if in scope)
10. Cleanup / reporting
"""

    external = f"""# External Attack Surface Playbook
Target: {target or '[TARGET]'}

## Goals
- Identify exposed services and identities
- Build credible initial-access hypotheses
- Collect evidence without unnecessary noise

## Suggested flow
1. Scope confirmation
2. Passive OSINT (public only)
3. In-scope active recon
4. Service prioritization
5. Candidate weaknesses
6. Human-approved validation only

## Evidence to capture
- Asset inventory
- Service/version notes
- Auth entry points
- Interesting error messages
- Priority matrix (impact vs effort)
"""

    ad = f"""# AD / Internal Support Playbook
Domain: {domain or '[DOMAIN]'}
DC: {dc_ip or '[DC_IP]'}

## Human-led sequence
1. Confirm positioning and authorization
2. Read-only enumeration (users/groups/policy/shares as allowed)
3. BloodHound/collection when authorized
4. Identify paths (Kerberoast, AS-REP, ACL, delegation)
5. Operator chooses least-abusive proof path under ROE
6. Document each hop with evidence

## Explicitly not automated here
- Password spraying at scale
- Uncontrolled lateral movement
- Persistence
- Domain-wide destructive actions

## Example read-oriented commands (authorized labs only)
```bash
nxc smb {dc_ip or '<DC_IP>'} -u '<USER>' -p '<PASS>' --users
nxc smb {dc_ip or '<DC_IP>'} -u '<USER>' -p '<PASS>' --groups
nxc smb {dc_ip or '<DC_IP>'} -u '<USER>' -p '<PASS>' --pass-pol
nxc smb {dc_ip or '<DC_IP>'} -u '<USER>' -p '<PASS>' --shares
```
"""

    objectives = """# Objective Simulation Checklist
- [ ] Initial access vector documented
- [ ] Privilege level confirmed
- [ ] Business objective mapped (data/path/impact)
- [ ] Minimal proof selected (avoid unnecessary harm)
- [ ] Detection notes captured (if purple-team/ROE requires)
- [ ] Cleanup actions listed
- [ ] Report evidence linked
"""

    report = """# Red Team Finding Template
**Title:**
**Phase:**
**Objective relevance:**
**Preconditions:**
**Steps (high level):**
**Evidence IDs:**
**Privileges obtained:**
**Business impact:**
**Detection opportunity:**
**Remediation:**
**Retest notes:**
"""

    files = {
        "REDTEAM-OVERVIEW.md": overview,
        "REDTEAM-EXTERNAL.md": external,
        "REDTEAM-AD-INTERNAL.md": ad,
        "REDTEAM-OBJECTIVES.md": objectives,
        "REDTEAM-FINDING-TEMPLATE.md": report,
    }
    written = []
    for name, content in files.items():
        path = root / name
        path.write_text(content, encoding="utf-8")
        written.append(str(path))

    return {
        "status": "ok",
        "mode": "human-led-support",
        "files": written,
        "disclaimer": "Support pack only. No autonomous exploitation.",
    }
