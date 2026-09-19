#!/usr/bin/env python3
"""Evidence inventory and integrity metadata for authorized assessments.

This module indexes evidence; it never uploads, executes, or exposes secrets.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from .atomic_io import atomic_write_json, atomic_write_text

SENSITIVE_NAMES = {"credentials.json", "exploitation-log.txt"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".pfx", ".p12"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _kind(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".webp"}: return "screenshot"
    if ext in {".json", ".jsonl"}: return "structured-data"
    if ext in {".pcap", ".pcapng"}: return "network-capture"
    if ext in {".txt", ".log"}: return "text-log"
    if ext in {".md", ".html"}: return "report"
    if ext in {".pdf"}: return "document"
    if ext in {".csv", ".tsv"}: return "tabular-data"
    return "artifact"


def _is_sensitive(path: Path) -> bool:
    return path.name in SENSITIVE_NAMES or path.suffix.lower() in SENSITIVE_SUFFIXES


def build_evidence_index(outdir: Union[str, Path]) -> Path:
    root = Path(outdir)
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    index_path = ev / "evidence-index.json"
    md_path = ev / "evidence-index.md"

    entries = []
    skipped = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        # Never index the index's own output files. The previous version
        # of this check was `"evidence" not in p.parts and p.name ==
        # "evidence-index.json"` combined with `or` -- operator precedence
        # made the right-hand side almost always False (the index always
        # lives under an "evidence" dir), so it degraded to just
        # `not p.is_file()`. A separate explicit check below caught the
        # .json file but never the .md file, so evidence-index.md was
        # folded back into its own index and re-hashed on every run.
        if p in (index_path, md_path):
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        try:
            sha = _sha256(p)
            size = p.stat().st_size
        except OSError as exc:
            # A file that vanished, or that we don't have permission to
            # read, previously crashed the whole index build. Skip it and
            # say so in the output instead of losing the rest of the run.
            skipped.append({"path": rel, "reason": str(exc)})
            continue
        entries.append({
            "evidence_id": "E-" + hashlib.sha256(rel.encode()).hexdigest()[:10],
            "path": rel,
            "type": _kind(p),
            "size": size,
            "sha256": sha,
            "sensitive_filename": _is_sensitive(p),
        })

    payload = {
        "schema_version": "1.1",
        "generated": datetime.now(timezone.utc).isoformat(),
        "entry_count": len(entries),
        "skipped_unreadable": skipped,
        "entries": entries,
    }
    atomic_write_json(index_path, payload)

    lines = ["# Evidence Index", "", f"Generated: {payload['generated']}", ""]
    if skipped:
        lines.append(f"> {len(skipped)} file(s) could not be read and were skipped from this index.")
        lines.append("")
    lines += ["| Evidence | Type | Path | SHA-256 |", "|---|---|---|---|"]
    for e in entries:
        flag = " ⚠️" if e["sensitive_filename"] else ""
        lines.append(f"| `{e['evidence_id']}` | {e['type']} | `{e['path']}`{flag} | `{e['sha256'][:16]}…` |")
    atomic_write_text(md_path, "\n".join(lines) + "\n")
    return index_path
