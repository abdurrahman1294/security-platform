#!/usr/bin/env python3
"""Generate a clean HTML report from nuclei JSON findings."""

import json
import html as html_lib
import sys
from pathlib import Path
from datetime import datetime
from modules.findings_io import load_findings_file
from modules.security import redact_text
from modules.atomic_io import atomic_write_text

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Report - {client}</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 40px; background: #f7f9fc; color: #222; }}
h1, h2 {{ color: #1a73e8; }}
.summary {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
.finding {{ background: white; margin: 15px 0; padding: 15px 20px; border-left: 5px solid #ccc; border-radius: 4px; }}
.critical {{ border-left-color: #d93025; }}
.high {{ border-left-color: #f9ab00; }}
.medium {{ border-left-color: #fbbc04; }}
.low {{ border-left-color: #34a853; }}
.severity {{ font-weight: bold; text-transform: uppercase; }}
pre {{ background: #f1f3f4; padding: 12px; overflow-x: auto; border-radius: 4px; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
</style>
</head>
<body>
<h1>Vulnerability Assessment Report</h1>
<div class="summary">
<p><strong>Client:</strong> {client}<br>
<strong>Target:</strong> {target}<br>
<strong>Date:</strong> {date}<br>
<strong>Total Findings:</strong> {total}</p>
<table>
<tr><th>Severity</th><th>Count</th></tr>
<tr><td>Critical</td><td>{critical}</td></tr>
<tr><td>High</td><td>{high}</td></tr>
<tr><td>Medium</td><td>{medium}</td></tr>
<tr><td>Low</td><td>{low}</td></tr>
</table>
</div>

<h2>Findings</h2>
{findings_html}

<hr>
<p><em>Generated automatically. All findings should be manually validated.</em></p>
</body>
</html>
"""

def severity_class(sev):
    return sev.lower() if sev else "info"

def generate_html_report(json_file: str, client: str, target: str, output_file: str):
    path = Path(json_file)
    if not path.exists():
        print(f"[!] Findings file not found: {json_file}")
        return

    findings = load_findings_file(path)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings_html = ""

    for f in findings:
        sev = html_lib.escape(str(f.get("info", {}).get("severity", "info")).lower())
        counts[sev] = counts.get(sev, 0) + 1

        name = html_lib.escape(str(f.get("info", {}).get("name", "Unknown")))
        host = html_lib.escape(str(f.get("host") or f.get("matched-at") or "N/A"))
        matched = html_lib.escape(str(f.get("matched-at") or f.get("host") or ""))
        description = html_lib.escape(redact_text(str(f.get("info", {}).get("description", "")))[:400])

        findings_html += f"""
        <div class="finding {severity_class(sev)}">
            <p><span class="severity">[{sev}]</span> <strong>{name}</strong></p>
            <p><strong>Host:</strong> {host}</p>
            <p>{description}</p>
            <p><strong>Matched at:</strong> {matched}</p>
        </div>
        """

    rendered_html = HTML_TEMPLATE.format(
        client=html_lib.escape(str(client)),
        target=html_lib.escape(str(target)),
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=len(findings),
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        findings_html=findings_html or "<p>No findings.</p>"
    )

    atomic_write_text(output_file, rendered_html)
    print(f"[+] HTML report generated → {output_file}")
