#!/usr/bin/env python3
"""
Advanced Active Directory Practice & Authorized Testing Module
--------------------------------------------------------------
Designed for legitimate lab practice and authorized engagements.
Provides structured methodology, commands, and attack path guidance.
"""

from pathlib import Path
from datetime import datetime

def generate_advanced_ad_guide(output_dir: str, domain: str = "", dc_ip: str = ""):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    content = f"""# Advanced Active Directory Methodology
Domain: {domain or '[TARGET_DOMAIN]'}
DC IP: {dc_ip or '[DC_IP]'}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

> Authorized lab/engagement use only.

## 1. Position and scope
- Confirm written authorization and exact AD assets in scope.
- Establish whether the test identity is anonymous, standard user, delegated admin, or privileged.
- Record domain, forest, DCs, trust boundaries, and assessment window.

## 2. Read-only enumeration
Use the framework V228 engine for bounded enumeration:
- SMB reachability
- Users
- Groups
- Password policy
- Shares

Do not place passwords in command lines or reports. V228 reads `NXC_USER`, `NXC_PASSWORD`, and optional `NXC_DOMAIN` from the environment and removes credential material from evidence.

## 3. High-value analyst review
- Privileged group membership and tiering
- Delegation configuration
- ACL relationships (GenericAll, WriteDACL, WriteOwner, ForceChangePassword, etc.)
- GPO permissions and scope
- AD CS certificate-template exposure
- Trust relationships
- Remote-management exposure

## 4. Attack-path reasoning
Model paths as hypotheses: `identity -> permission -> resource -> capability -> impact`.
Require independent evidence before declaring a path confirmed. Do not infer domain compromise from one scanner result.

## 5. Controlled validation
Only use the framework's registered, approval-gated proof adapters where a safe adapter exists. Credential theft, spraying, persistence, privilege changes, and lateral movement are outside the automated V228 boundary and require separate engagement procedures.

## 6. Reporting
For each confirmed issue capture: asset, principal, permission/configuration, evidence IDs, confidence, business impact, remediation, and retest state.
"""

    path = out / "AD-Advanced-Methodology.md"
    path.write_text(content, encoding="utf-8")
    print(f"[+] Advanced AD Methodology written → {path}")
    return str(path)
