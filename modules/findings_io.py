#!/usr/bin/env python3
"""
Shared, format-tolerant loader for scanner findings files.

nuclei can be told to write results as either a JSON array (-json-export /
-je) or JSONL (-jsonl / -j, one object per line). Several modules in this
project read a findings file assuming JSONL only -- that silently produces
zero findings against a real orchestrator run, since orchestrator.py's
vuln_scan phase uses -json-export (array format). Every module that reads
a findings/evidence file should go through this loader instead of rolling
its own line-by-line json.loads, so the format is only handled in one
place.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def load_findings_file(path: PathLike) -> List[Dict[str, Any]]:
    """Load a list of dict findings from `path`, tolerating either a JSON
    array or newline-delimited JSON objects. Never raises: a missing,
    empty, or unreadable file just yields an empty list -- callers should
    treat an empty list as 'nothing found here', not assume it means the
    file doesn't exist."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError as exc:
        logger.warning("findings_io: could not read %s: %s", p, exc)
        return []
    if not raw:
        return []

    if raw[0] in "[{":
        try:
            data: Any = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            if isinstance(data, dict):
                if "findings" in data and isinstance(data.get("findings"), list):
                    data = data["findings"]
                else:
                    data = [data]
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
            return []
        # Whole-file parse failed even though it starts with '[' or '{' --
        # most likely this is JSONL where the first line happens to start
        # with '{' (e.g. nuclei -jsonl). Fall through to line-by-line
        # parsing below instead of treating it as empty.

    items: List[Dict[str, Any]] = []
    skipped = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(obj, dict):
            items.append(obj)
        else:
            skipped += 1
    if skipped:
        logger.debug("findings_io: skipped %d unparseable/non-object line(s) in %s", skipped, p)
    return items


def load_findings_files(paths: List[PathLike]) -> List[Dict[str, Any]]:
    """Load and concatenate findings from several files, in order. A
    convenience wrapper for callers (report_pack, correlation_engine,
    finding_dedup, ...) that all read the same fixed set of findings
    paths -- keeps the per-file tolerant-loading logic in exactly one
    place rather than each caller writing its own loop."""
    out: List[Dict[str, Any]] = []
    for p in paths:
        out.extend(load_findings_file(p))
    return out
