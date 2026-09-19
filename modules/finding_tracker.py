#!/usr/bin/env python3
"""
Finding Status Tracker
Allows marking findings as Confirmed / False Positive / Accepted Risk.
"""

import json
from pathlib import Path
from datetime import datetime

VALID_STATUS = ["unreviewed", "candidate", "validating", "validated", "confirmed", "inconclusive", "blocked", "false-positive", "accepted-risk"]

def get_tracker_path(outdir: str) -> Path:
    path = Path(outdir) / "evidence" / "finding-status.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def load_tracker(outdir: str) -> dict:
    path = get_tracker_path(outdir)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}

def save_tracker(outdir: str, data: dict):
    path = get_tracker_path(outdir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def set_status(outdir: str, finding_id: str, status: str, note: str = ""):
    status = status.lower().strip()
    if status not in VALID_STATUS:
        print(f"[!] Invalid status. Use: {', '.join(VALID_STATUS)}")
        return

    data = load_tracker(outdir)
    data[finding_id] = {
        "status": status,
        "note": note,
        "updated": datetime.now().isoformat()
    }
    save_tracker(outdir, data)
    print(f"[+] {finding_id} marked as {status}")

def generate_status_report(outdir: str):
    data = load_tracker(outdir)
    report_path = Path(outdir) / "reports" / "finding-status-report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    content = "# Finding Status Report\n\n"
    if not data:
        content += "No findings have been reviewed yet.\n"
    else:
        for fid, info in data.items():
            content += f"- **{fid}**: `{info['status']}`"
            if info.get("note"):
                content += f" – {info['note']}"
            content += "\n"

    report_path.write_text(content, encoding="utf-8")
    print(f"[+] Status report → {report_path}")
    return str(report_path)
