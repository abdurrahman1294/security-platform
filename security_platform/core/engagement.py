from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlparse

@dataclass(frozen=True)
class Engagement:
    client: str
    target: str
    output: Path
    scope_file: Path | None = None

    @property
    def evidence(self) -> Path:
        p = self.output / "evidence"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def target_host(self) -> str:
        """Return the hostname form used by network/recon tools."""
        raw = self.target.strip()
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            return parsed.hostname or raw
        return raw

    @property
    def reports(self) -> Path:
        p = self.output / "reports"
        p.mkdir(parents=True, exist_ok=True)
        return p

def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())[:80] or "engagement"
