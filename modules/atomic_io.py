#!/usr/bin/env python3
"""Shared atomic JSON/text write helper for evidence, state, and report files.

Several modules in this project write JSON state that a long-running
assessment depends on being intact (execution-state, tool-execution
ledgers, evidence indices). A plain `path.write_text(...)` call leaves a
truncated or invalid file behind if the process is interrupted mid-write
-- Ctrl+C, an OOM kill, a container eviction, a full disk -- which is
exactly the kind of event a long assessment run is likely to hit. This
writes to a temp file in the same directory and atomically renames it
into place (`os.replace`), so a reader never observes a partial write.

`load_json` is the read-side complement: on a parse failure it can
quarantine the corrupt file (rename it aside with a timestamp) instead
of silently discarding it, so state corruption is diagnosable rather
than just vanishing into a fresh empty state on the next run.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Union

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def atomic_write_text(path: PathLike, text: str, *, encoding: str = "utf-8") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_json(path: PathLike, data: Any, *, indent: int = 2) -> None:
    atomic_write_text(path, json.dumps(data, indent=indent, default=str))


def load_json(path: PathLike, default: Any, *, quarantine_on_error: bool = True) -> Any:
    """Read JSON from `path`, returning `default` if it's missing, unreadable,
    or not valid JSON. On a parse/read failure, the offending file is
    preserved as `<name>.corrupt-<unix ts>` next to itself (best-effort)
    rather than just being overwritten by the next write -- so a corrupted
    ledger or state file can be inspected instead of silently resetting."""
    path = Path(path)
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("atomic_io: %s is unreadable/corrupt (%s); quarantining and using default", path, exc)
        if quarantine_on_error:
            try:
                path.replace(path.with_name(f"{path.name}.corrupt-{time.time_ns()}"))
            except OSError:
                pass
        return default
