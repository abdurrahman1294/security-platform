#!/usr/bin/env python3
"""
Basic Resume Support
Tracks which major phases have been completed for an engagement.
"""

import json
from pathlib import Path
from datetime import datetime

PHASES = [
    "recon",
    "ports",
    "web",
    "vuln_scan",
    "api",
    "server_enum",
    "authenticated",
    "exploit_review",
    "reporting"
]

def get_state_path(outdir: str) -> Path:
    path = Path(outdir) / "evidence" / "engagement-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def load_state(outdir: str) -> dict:
    path = get_state_path(outdir)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"completed": [], "last_updated": None}

def save_state(outdir: str, state: dict):
    state["last_updated"] = datetime.now().isoformat()
    path = get_state_path(outdir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def mark_complete(outdir: str, phase: str):
    state = load_state(outdir)
    if phase not in state["completed"]:
        state["completed"].append(phase)
        save_state(outdir, state)
        print(f"[+] Phase marked complete: {phase}")

def show_status(outdir: str):
    state = load_state(outdir)
    print("\n=== Engagement Resume Status ===")
    for phase in PHASES:
        status = "✓" if phase in state.get("completed", []) else " "
        print(f"[{status}] {phase}")
    if state.get("last_updated"):
        print(f"\nLast updated: {state['last_updated']}")
    print()
