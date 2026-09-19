#!/usr/bin/env python3
"""
Engagement Coverage Report
Shows what was automated vs what still requires manual work.
"""

from pathlib import Path
from datetime import datetime
import json

def generate_coverage_report(outdir: str, client: str, target: str):
    out = Path(outdir)
    report_file = out / "reports" / "engagement-coverage.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)

    # Check what artifacts exist
    has_recon = (out / "recon" / "live-hosts.txt").exists()
    has_ports = any((out / "ports").glob("nmap*")) or (out / "ports" / "naabu.txt").exists()
    has_web = (out / "web" / "urls.txt").exists()
    has_vulns = (out / "vulns" / "findings.txt").exists()
    has_auth = (out / "vulns" / "authenticated-findings.txt").exists()
    has_explanations = any((out / "evidence" / "vuln-explanations").glob("*.md")) if (out / "evidence" / "vuln-explanations").exists() else False
    has_session = (out / "evidence" / "session-auth-analysis.md").exists()
    has_business = any((out / "evidence").glob("business-logic-checklist*.md")) if (out / "evidence").exists() else False

    def status(flag):
        return "✅ Completed" if flag else "❌ Not run / Missing"

    content = f"""# Engagement Coverage Report
Client: {client}
Target: {target}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Automated Coverage

| Area                        | Status                  |
|----------------------------|-------------------------|
| Reconnaissance             | {status(has_recon)}     |
| Port & Service Scanning    | {status(has_ports)}     |
| Web Enumeration            | {status(has_web)}       |
| Unauthenticated Vuln Scan  | {status(has_vulns)}     |
| Authenticated Vuln Scan    | {status(has_auth)}      |
| Session / JWT Analysis     | {status(has_session)}   |
| Detailed Vuln Explanations | {status(has_explanations)} |
| Business Logic Checklist   | {status(has_business)}  |

## Still Requires Manual Work

These areas are difficult or unsafe to fully automate and should be performed manually:

- [ ] Business logic testing (use the generated checklist)
- [ ] IDOR / access control testing across users and roles
- [ ] Privilege escalation (after obtaining a foothold)
- [ ] Complex authentication flows (MFA, OAuth, SAML)
- [ ] Race conditions
- [ ] File upload abuse
- [ ] Server-side request forgery deep testing
- [ ] Chained exploitation
- [ ] Internal network pivoting (if in scope)
- [ ] Final validation of all automated findings

## Recommendation

Use the automated results as a strong foundation, then systematically complete the manual checklist items above before finalizing the client report.
"""

    report_file.write_text(content, encoding="utf-8")
    print(f"[+] Coverage report generated → {report_file}")
    return str(report_file)
