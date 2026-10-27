"""Deterministic detection layer for CyberLLM analysis.

CyberLLM's product vision puts deterministic detection BEFORE LLM reasoning,
and pilot v8 has a demonstrated blind spot: it called an SSRF request to the
cloud metadata endpoint likely_benign with high confidence (frozen T1 item
22). These rules are narrow and evidence-based: every firing cites the exact
substring it matched. A rule never invents attribution or a technique ID.

- metadata_endpoint: fetch of a cloud metadata service (169.254.169.254,
  metadata.google.internal) as a URL target. High severity.
- private_fetch_target: loopback/private address as a fetch target. High.
- credential_file_probe: requests for .env, .git/config, credentials files. High.
- repeated_probe: >= 4 distinct sensitive paths in one submission. Medium.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata.google"}
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2",
                     "172.30.", "172.31.", "192.168.", "127.")
_CREDENTIAL_PATHS = ("/.env", "/.git/config", "/.aws/credentials", "/id_rsa",
                     "/wp-config.php", "/config.php", "/.htpasswd", "/.svn/entries")
_SUSPICIOUS_PATHS = ("/.env", "/.git/", "/wp-login.php", "/.aws/", "/admin",
                     "/phpmyadmin", "/.svn/", "/backup", "/config")


def _urls_in(text: str) -> list[str]:
    return [unquote(u).rstrip(".,);") for u in re.findall(r"https?://[^\s'\"<>]+", text)]


def _is_private_or_loopback(host: str) -> bool:
    host = host.lower().split(":")[0]
    return host in ("localhost",) or host.startswith(_PRIVATE_PREFIXES) or host == "0.0.0.0"


def screen(text: str) -> list[dict]:
    findings: list[dict] = []
    lowered = text.lower()
    for url in _urls_in(text):
        host = (urlparse(url).hostname or "").lower()
        if host in _METADATA_HOSTS:
            findings.append({
                "rule": "metadata_endpoint", "severity": "high", "evidence": url,
                "explanation": (
                    "Request targets a cloud instance-metadata service. "
                    "This is a server-side request forgery (SSRF) pattern: "
                    "metadata endpoints can disclose instance credentials. "
                    "Treat as a threat regardless of benign-looking context."
                ),
            })
        elif _is_private_or_loopback(host):
            findings.append({
                "rule": "private_fetch_target", "severity": "high", "evidence": url,
                "explanation": "Request asks the server to fetch a loopback or private network address, a standard SSRF indicator.",
            })
    for path in _CREDENTIAL_PATHS:
        if path in lowered:
            findings.append({
                "rule": "credential_file_probe", "severity": "high", "evidence": path,
                "explanation": "Request probes for a credential or configuration file.",
            })
    distinct = {p for p in _SUSPICIOUS_PATHS if p in lowered}
    if len(distinct) >= 4:
        findings.append({
            "rule": "repeated_probe", "severity": "medium",
            "evidence": ", ".join(sorted(distinct)),
            "explanation": "Multiple distinct sensitive paths probed in one submission, consistent with automated scanning.",
        })
    return findings


def suggested_classification(findings: list[dict]) -> str:
    if any(f["severity"] == "high" for f in findings):
        return "likely_threat"
    if findings:
        return "needs_review"
    return "likely_benign"
