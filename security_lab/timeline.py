"""Chronological event log (JSONL in the user data directory).

Events are scan findings, model predictions, case changes, and
remediation actions. Details are redacted at write time, so the log
never becomes a secret store.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scanner.findings import redact


class Timeline:
    def __init__(self, path: Path):
        self.path = Path(path)

    def append(self, event: str, detail: str = "", source: str = "") -> dict:
        entry = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event, "detail": redact(detail, 1000), "source": source,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def read_all(self, limit: int = 500) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        entries: list[dict] = []
        for line in lines[-limit:]:
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass
