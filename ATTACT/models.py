"""ATTACT shared data models — findings and reports."""
from __future__ import annotations
import enum, time, uuid
from dataclasses import dataclass, field, asdict
from typing import Any

class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class Confidence(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"

class Status(str, enum.Enum):
    # How to read the finding:
    confirmed = "confirmed"          # observed, reproducible evidence
    potential = "potential"          # suspicious, needs manual verification
    not_found = "not_found"          # checked, no issue observed
    not_run = "not_run"              # skipped / unavailable / error

@dataclass
class Finding:
    check: str
    title: str
    status: str            # Status value
    severity: str          # Severity value
    confidence: str        # Confidence value
    summary: str
    evidence: str = ""
    remediation: str = ""
    request_count: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class Report:
    target: str
    timestamp: str
    checks: list[str]
    findings: list[Finding]
    request_count: int
    allowlist: list[str] = field(default_factory=list)
    tool: str = "ATTACT"
    version: str = "0.1.0"
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    elapsed_ms: int = 0
    # limitation notes rendered in CLI and persisted in JSON
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "version": self.version, "run_id": self.run_id,
            "target": self.target, "timestamp": self.timestamp,
            "checks": self.checks, "allowlist": self.allowlist,
            "request_count": self.request_count, "elapsed_ms": self.elapsed_ms,
            "limitations": self.limitations,
            "findings": [f.to_dict() for f in self.findings],
        }
