#!/usr/bin/env python3
"""
Smarter Reporting Module
- Prioritized findings
- Executive summary generation
"""

import json
from pathlib import Path
from datetime import datetime
from collections import Counter
from modules.findings_io import load_findings_file

def generate_executive_summary(outdir: str, client: str, target: str):
    out = Path(outdir)
    report_file = out / "reports" / "executive-summary.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)

    findings = load_findings_file(out / "vulns" / "findings.json")

    severity_count = Counter()
    high_value = []

    for f in findings:
        sev = f.get("info", {}).get("severity", "info").lower()
        severity_count[sev] += 1
        name = f.get("info", {}).get("name", "Unknown")
        host = f.get("host") or f.get("matched-at") or ""
        if sev in ("critical", "high"):
            high_value.append(f"- **{sev.upper()}**: {name} ({host})")

    content = f"""# Executive Summary
Client: {client}
Target: {target}
Date: {datetime.now().strftime("%Y-%m-%d")}

## Overview
This assessment identified **{len(findings)}** automated findings across the target environment.

## Severity Breakdown
- Critical: {severity_count.get('critical', 0)}
- High: {severity_count.get('high', 0)}
- Medium: {severity_count.get('medium', 0)}
- Low/Info: {severity_count.get('low', 0) + severity_count.get('info', 0)}

## Highest Priority Findings
"""
    if high_value:
        content += "\n".join(high_value[:10])
    else:
        content += "No critical or high findings detected by automated scanning.\n"

    content += """

## Recommendations
1. Address all Critical and High findings immediately.
2. Review medium findings within 30 days.
3. Perform manual business logic and access control testing.
4. Re-test after remediation.

## Next Steps
- Review the detailed technical report
- Validate findings manually
- Apply remediations
- Schedule retest if required
"""

    report_file.write_text(content, encoding="utf-8")
    print(f"[+] Executive summary generated → {report_file}")
    return str(report_file)


def prioritize_findings(outdir: str):
    """Create a prioritized list of findings."""
    out = Path(outdir)
    json_path = out / "vulns" / "findings.json"
    findings = load_findings_file(json_path)
    if not findings:
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x.get("info", {}).get("severity", "info").lower(), 5))

    prioritised_file = out / "reports" / "prioritized-findings.md"
    content = "# Prioritized Findings\n\n"
    for i, f in enumerate(findings, 1):
        sev = f.get("info", {}).get("severity", "info").upper()
        name = f.get("info", {}).get("name", "Unknown")
        host = f.get("host") or f.get("matched-at") or "N/A"
        content += f"{i}. **[{sev}]** {name}\n   - Host: {host}\n\n"

    prioritised_file.write_text(content, encoding="utf-8")
    print(f"[+] Prioritized findings → {prioritised_file}")
