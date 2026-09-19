#!/usr/bin/env python3
"""Generate a read-only Active Directory operator runbook.

No credential-dumping, spraying, privilege-changing, or lateral-movement
commands are generated here. V228 can execute the bounded read-only subset.
"""
from pathlib import Path
from datetime import datetime

def generate_ad_commands(output_dir: str, domain: str, dc_ip: str, user: str = '<USER>', password: str = '<ENV:NXC_PASSWORD>'):
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True)
    content=f'''# AD Read-Only Operator Runbook\nDomain: {domain}\nDC IP: {dc_ip}\nGenerated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n> Authorized assessment only. Credentials belong in environment variables, never in this document.\n\n## Recommended automated path\nRun the framework's V228 AD assessment with explicit approval.\n\nEnvironment:\n- `NXC_USER={user}`\n- `NXC_PASSWORD=<set outside the document>`\n- Optional `NXC_DOMAIN={domain}`\n\nRead-only checks:\n- SMB baseline\n- Users\n- Groups\n- Password policy\n- Shares\n\n## Manual review\n- Domain/forest structure\n- Privileged groups and tiering\n- Delegation configuration\n- ACL relationships\n- GPO exposure\n- AD CS exposure\n- Trust relationships\n\n## Explicitly outside this module\n- Password spraying\n- Credential dumping\n- Kerberoasting/AS-REP roasting execution\n- Privilege changes\n- Lateral movement\n- Persistence\n\n## Evidence\nRecord command ID, timestamp, tool version, sanitized result hash, scope confirmation, and analyst conclusion.\n'''
    path=out/'AD-Command-Generator.md'; path.write_text(content,encoding='utf-8'); return str(path)
