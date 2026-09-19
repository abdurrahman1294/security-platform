#!/usr/bin/env python3
"""
Simple Engagement Credential Tracker
WARNING: Treat credentials.json as highly sensitive. Never commit it.
File is written with mode 600 (owner read/write only).
"""

import json
import os
from modules.atomic_io import atomic_write_json, load_json
from pathlib import Path
from datetime import datetime

def get_cred_path(outdir: str) -> Path:
    path = Path(outdir) / "evidence" / "credentials.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def load_creds(outdir: str) -> list:
    path = get_cred_path(outdir)
    data = load_json(path, [])
    return data if isinstance(data, list) else []

def save_creds(outdir: str, data: list):
    path = get_cred_path(outdir)
    atomic_write_json(path, data)
    # Harden permissions: owner read/write only
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def add_credential(outdir: str, system: str, username: str, secret: str, note: str = "", cred_type: str = "password"):
    data = load_creds(outdir)
    entry = {
        "system": system,
        "username": username,
        "secret": secret,
        "type": cred_type,
        "note": note,
        "added": datetime.now().isoformat()
    }
    data.append(entry)
    save_creds(outdir, data)
    print(f"[+] Credential added for {system} ({username})")

def list_credentials(outdir: str):
    data = load_creds(outdir)
    if not data:
        print("No credentials stored yet.")
        return
    print("\n=== Stored Credentials (Sensitive) ===")
    for i, c in enumerate(data, 1):
        print(f"{i}. [{c['type']}] {c['system']} | {c['username']} | [REDACTED] | {c.get('note','')}")
    print()
