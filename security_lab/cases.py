"""Case management: findings become trackable cases.

Statuses: New, Investigating, Accepted Risk, Resolved. Cases live in
``cases.json`` in the user data directory. Notes and exports never
contain passwords, tokens, or cookie values: finding evidence is
already redacted at creation, and case text is stored verbatim, so
analysts must not paste secrets into notes (the UI warns about this).
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUSES = ("New", "Investigating", "Accepted Risk", "Resolved")


@dataclass
class Case:
    id: int
    title: str
    severity: str
    url: str
    finding_name: str
    evidence: str
    status: str = "New"
    notes: list[dict[str, str]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"bad status: {self.status}")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.created_at = self.created_at or now
        self.updated_at = self.updated_at or now

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "url": self.url, "finding_name": self.finding_name,
            "evidence": self.evidence, "status": self.status,
            "notes": self.notes, "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        return cls(
            id=int(data["id"]), title=data["title"],
            severity=data["severity"], url=data["url"],
            finding_name=data["finding_name"], evidence=data["evidence"],
            status=data.get("status", "New"),
            notes=list(data.get("notes", [])),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


class CaseStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.cases: list[Case] = self._load()

    def _load(self) -> list[Case]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [Case.from_dict(row) for row in data]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([c.to_dict() for c in self.cases], indent=2),
            encoding="utf-8")

    def _next_id(self) -> int:
        return max([c.id for c in self.cases], default=0) + 1

    def create_from_finding(self, finding: Any) -> Case:
        case = Case(
            id=self._next_id(),
            title=f"{finding.name} ({finding.severity})",
            severity=finding.severity, url=finding.url,
            finding_name=finding.name, evidence=finding.evidence)
        self.cases.append(case)
        self._save()
        return case

    def create(self, title: str, severity: str, url: str,
               finding_name: str, evidence: str) -> Case:
        case = Case(id=self._next_id(), title=title, severity=severity,
                    url=url, finding_name=finding_name, evidence=evidence)
        self.cases.append(case)
        self._save()
        return case

    def get(self, case_id: int) -> Case | None:
        for case in self.cases:
            if case.id == case_id:
                return case
        return None

    def set_status(self, case_id: int, status: str) -> Case:
        if status not in STATUSES:
            raise ValueError(f"bad status: {status}")
        case = self.get(case_id)
        if case is None:
            raise KeyError(f"no such case: {case_id}")
        case.status = status
        case.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._save()
        return case

    def add_note(self, case_id: int, note: str, author: str = "analyst") -> Case:
        case = self.get(case_id)
        if case is None:
            raise KeyError(f"no such case: {case_id}")
        case.notes.append({
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "author": author, "text": note[:2000]})
        case.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._save()
        return case

    def summary_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in STATUSES}
        for case in self.cases:
            counts[case.status] += 1
        counts["total"] = len(self.cases)
        return counts

    def export_json(self, path: Path) -> Path:
        Path(path).write_text(
            json.dumps([c.to_dict() for c in self.cases], indent=2),
            encoding="utf-8")
        return Path(path)

    def export_csv(self, path: Path) -> Path:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["id", "title", "severity", "url", "finding",
                             "status", "created_at", "updated_at"])
            for c in self.cases:
                writer.writerow([c.id, c.title, c.severity, c.url,
                                 c.finding_name, c.status, c.created_at,
                                 c.updated_at])
        return Path(path)
