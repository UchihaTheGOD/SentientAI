"""Finding model + evidence redaction.

A finding's ``status`` describes the *observation*, not an exploit:
- ``verified``: the observation itself is confirmed (a header is absent,
  a path returns 200). It does NOT mean exploitation was confirmed.
- ``suspected``: an indicator is present but the vulnerability is not
  established (a reflected marker, an error string, a version banner).
- ``inconclusive``: the check could not run or its signal is ambiguous.

No finding ever claims a confirmed vulnerability from a missing header,
an error page, or a version string alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ("high", "medium", "low")
STATUSES = ("suspected", "verified", "inconclusive")

_SECRET_PATTERNS = [
    # Generic secret assignments (values replaced, keys kept for context).
    (re.compile(r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd"
                 r"|session[_-]?id|session)"
                 r"(\s*[:=]\s*)([\"']?)[^\s\"'&;]{4,}"),
     r"\1\2\3[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*)(Bearer\s+|Basic\s+)?\S+"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)(set-cookie:\s*[^=]+=\s*)[^;\s]+"),
     r"\1[REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9-]{16,}"), "[REDACTED]"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED KEY]"),
]

_SENSITIVE_PARAMS = {"password", "passwd", "pwd", "token", "secret",
                     "api_key", "apikey", "auth", "session", "cookie"}


def redact(text: str, limit: int = 2000) -> str:
    """Mask secret-looking material and cap length."""
    if not text:
        return ""
    out = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out[:limit]


def redact_url(url: str) -> str:
    """Strip userinfo and mask sensitive query values."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc += f":{parts.port}"
        query = urlencode([
            (k, "[REDACTED]" if k.lower() in _SENSITIVE_PARAMS else v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
        ])
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except ValueError:
        return "[unparseable URL]"


@dataclass
class Finding:
    name: str
    category: str
    severity: str
    confidence: str
    status: str
    explanation: str
    evidence: str
    url: str
    impact: str
    remediation: str
    reference: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.severity}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"bad confidence: {self.confidence}")
        if self.status not in STATUSES:
            raise ValueError(f"bad status: {self.status}")
        self.evidence = redact(self.evidence)
        self.url = redact_url(self.url)

    def to_dict(self) -> dict:
        return {
            "name": self.name, "category": self.category,
            "severity": self.severity, "confidence": self.confidence,
            "status": self.status, "explanation": self.explanation,
            "evidence": self.evidence, "url": self.url,
            "impact": self.impact, "remediation": self.remediation,
            "reference": self.reference,
        }


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    counts["total"] = len(findings)
    return counts
