#!/usr/bin/env python3
"""
Engagement Journal
Simple persistent notes for each engagement.
"""

from pathlib import Path
from datetime import datetime

def get_journal_path(outdir: str) -> Path:
    path = Path(outdir) / "evidence" / "engagement-journal.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def init_journal(outdir: str, client: str, target: str):
    path = get_journal_path(outdir)
    if not path.exists():
        content = f"""# Engagement Journal
Client: {client}
Target: {target}
Started: {datetime.now().strftime("%Y-%m-%d %H:%M")}

---

## Notes

"""
        path.write_text(content, encoding="utf-8")
        print(f"[+] Journal created → {path}")
    return str(path)

def add_note(outdir: str, note: str):
    path = get_journal_path(outdir)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n### {timestamp}\n{note}\n")
    print(f"[+] Note added to journal")
