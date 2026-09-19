#!/usr/bin/env python3
"""
Active Directory Safe Enumeration & Attack Path Guidance
Provides commands and checklists. Does NOT run aggressive attacks automatically.
"""

from pathlib import Path
from datetime import datetime

def generate_ad_enum_guide(output_dir: str, domain: str = ""):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    content = f"""# Active Directory Enumeration & Attack Path Guidance
Domain: {domain or 'Unknown'}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

> This is a guidance document. Run commands only when authorized and with care.

## 1. Initial Enumeration (from a domain-joined or positioned machine)

### Basic Domain Info
```bash
# Linux (with Impacket / ldapsearch / crackmapexec if available)
nxc smb <DC-IP> -u user -p password
nxc smb <DC-IP> --users
nxc smb <DC-IP> --groups
nxc smb <DC-IP> --pass-pol

# PowerView / Rubeus style (Windows)
Get-Domain
Get-DomainUser
Get-DomainComputer
Get-DomainGroupMember -Identity "Domain Admins"
```

### Useful BloodHound Collection (if allowed)
```bash
# SharpHound or AzureHound equivalent
# Only collect when explicitly authorized
```

## 2. Common Attack Paths to Look For

- [ ] Users with weak or reused passwords
- [ ] Kerberoastable service accounts (SPNs)
- [ ] AS-REP Roastable users (Do not require pre-auth)
- [ ] Unconstrained / Constrained Delegation issues
- [ ] Excessive privileges (users in privileged groups)
- [ ] ACL abuses (GenericAll, WriteDACL, ForceChangePassword, etc.)
- [ ] GPO abuse opportunities
- [ ] Domain trust relationships
- [ ] Print Spooler / other coercion vectors (if in scope)

## 3. Safe Credential Testing Guidance

- Prefer password spraying with very low rates and account lockout awareness
- Always coordinate with the client before any spraying
- Document lockout policy first

## 4. Privilege Escalation Paths (High Level)

1. Kerberoasting → crack service account hashes
2. AS-REP Roasting
3. Delegation abuse
4. ACL-based privilege escalation
5. GPO modification
6. Credential dumping from compromised hosts (when authorized)
7. Lateral movement via admin shares / WinRM / RDP / SMB

## 5. Recommended Tooling (for authorized use)

- BloodHound / SharpHound
- Impacket suite
- CrackMapExec / NetExec
- Rubeus
- Certipy (for AD CS attacks)
- ldapsearch / windapsearch

## 6. Reporting Requirements

For every AD finding clearly document:
- Initial access method
- Privileges obtained
- Attack path (step-by-step)
- Business impact
- Precise remediation steps

## Important Rules
- Never run destructive attacks (e.g. mass lockouts, ransomware-style actions)
- Prefer read-only enumeration first
- Get explicit approval for any privilege escalation or lateral movement
"""

    path = out / "active-directory-guidance.md"
    path.write_text(content, encoding="utf-8")
    print(f"[+] Active Directory guidance generated → {path}")
    return str(path)
