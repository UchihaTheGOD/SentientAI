"""Deterministic attack-category rules (Stage 4).

Lightweight, explainable, independently testable patterns. A rule match
is an INDICATOR, never proof: confidence describes how distinctive the
pattern is, severity_hint is a triage hint, and outcome is always
"attempted_or_detected" from rules alone — a single suspicious string
never proves exploitation, success, or compromise.

MITRE discipline (hard guard in suggest_mitre()):
- Only TWO sources may propose a technique, and only after the local
  dataset validates the ID: (1) the auth-pattern classifier
  (guessing -> T1110.001, spraying -> T1110.003, stuffing -> T1110.004,
  brute force -> T1110), (2) web-shell evidence -> T1505.003.
- Everything else returns None ("Unknown / Not mapped"). In
  particular, SQLi / XSS / traversal NEVER auto-map to T1190, and
  T1190 requires evidence of exploitation of a public-facing
  application, which rules alone cannot establish.
- Passwords are never analyzed: the auth classifier accepts usernames
  plus OPTIONAL password hashes (never plaintext). Spraying vs
  stuffing is distinguished by hash reuse only when hashes are given;
  without them, multi-user low-attempt bursts are reported as
  spraying with low confidence and the ambiguity is stated.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Optional

from .mitre_attack import NOT_MAPPED

_MAX_EVIDENCE = 200


def _snippet(text: str, match: re.Match) -> str:
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)
    snip = text[start:end].replace("\n", " ").strip()
    return snip[:_MAX_EVIDENCE]


# (attack_type, category, severity_hint, confidence, [patterns])
# Patterns are matched case-insensitively against the raw text.
_RULES: list[tuple[str, str, str, str, list[str]]] = [
    ("sql_injection", "web_attack", "medium", "high", [
        r"union\s+(all\s+)?select\b", r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"'\s*or\s+'[^']+'\s*=\s*'[^']+'", r";\s*drop\s+table\b",
        r"sleep\s*\(\s*\d+\s*\)", r"benchmark\s*\(\s*\d+\s*,",
        r"'\s*--", r'"\s*--', r"/\*.*\*/\s*(union|select)",
    ]),
    ("cross_site_scripting", "web_attack", "medium", "high", [
        r"<\s*script\b", r"on\w+\s*=\s*['\"][^'\"]*(alert|document\.|eval\()",
        r"javascript\s*:", r"<\s*img\b[^>]*onerror", r"document\.cookie",
    ]),
    ("path_traversal", "web_attack", "medium", "high", [
        r"(\.\./|\.\.\\){2,}", r"%2e%2e(%2f|%5c)", r"\.\.;/",
        r"/etc/(passwd|shadow)\b",
    ]),
    ("local_file_inclusion", "web_attack", "medium", "medium", [
        r"php://filter", r"file://", r"(include|require)(_once)?\s*[=\(].*\.\./",
    ]),
    ("remote_file_inclusion", "web_attack", "medium", "medium", [
        r"(include|require|file|page|path)\s*=\s*https?://",
    ]),
    ("command_injection", "web_attack", "high", "high", [
        r"[;|&`$]\s*(id|whoami|uname|cat\s+/etc|nc\s|bash|sh)\b",
        r"\$\(\s*(id|whoami|uname|cat\s+/etc)", r"`\s*(id|whoami|uname)",
        r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", r"bash\s+-i\b", r"nc\s+-[el]",
    ]),
    ("server_side_request_forgery", "web_attack", "high", "high", [
        r"169\.254\.169\.254", r"metadata\.google\.internal",
        r"(url|uri|fetch|proxy|image|feed)\s*=\s*https?://(localhost|127\.0\.0\.1|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)",
    ]),
    ("server_side_template_injection", "web_attack", "medium", "high", [
        r"\{\{\s*7\s*\*\s*7\s*\}\}", r"\{\{.*?(config|self|__|class).*?\}\}",
        r"\$\{.*?(7\s*\*\s*7|__class__).*?\}",
    ]),
    ("xml_external_entity", "web_attack", "medium", "high", [
        r"<!ENTITY\b", r"<!DOCTYPE\b[^>]*\[", r"SYSTEM\s+['\"]file:",
    ]),
    ("insecure_deserialization", "web_attack", "high", "medium", [
        r"rO0AB", r"O:\d+:\s*\"", r"java\.io\.ObjectInputStream",
    ]),
    ("http_request_smuggling", "web_attack", "medium", "medium", [
        r"transfer-encoding\s*:\s*chunked.*content-length\s*:",
        r"content-length\s*:.*transfer-encoding\s*:\s*chunked",
    ]),
    ("auth_bypass", "auth_attack", "high", "medium", [
        r"'\s*or\s+'1'\s*=\s*'1", r"admin\s*['\"]\s*--", r"'\s*or\s+1\s*=\s*1\s*--",
    ]),
    ("file_upload_abuse", "web_attack", "high", "medium", [
        r"filename\s*=\s*\"[^\"]*\.(php\d?|jsp|asp|aspx|exe|sh|pl)\b",
        r"\.(php\d?|jsp|asp)\.(jpg|jpeg|png|gif)\b",
    ]),
    ("sensitive_file_probe", "web_attack", "low", "low", [
        r"/\.git/(HEAD|config)\b", r"/\.env\b", r"/\.svn/", r"/backup\.(zip|tar|sql)\b",
        r"/\.DS_Store\b", r"/config\.(php|bak|old|dist)\b",
    ]),
    ("security_misconfiguration", "web_attack", "low", "low", [
        r"/phpinfo", r"/actuator", r"/debug\b", r"/\.git/config",
    ]),
    ("directory_enumeration", "web_attack", "low", "low", [
        r"/wp-admin\b", r"/manager/html\b", r"/console\b",
    ]),
    ("suspicious_api_abuse", "web_attack", "low", "low", [
        r"[?&](api[_-]?key|access[_-]?token|secret)\s*=\s*[A-Za-z0-9\-_]{8,}",
        r"/api/(admin|internal)/",
    ]),
    ("web_shell_indicator", "malware_post_exploitation", "high", "high", [
        r"(c99|r57|wso|b374k)[\w.]*\.php", r"shell\.php\b",
        r"[?&](cmd|command|exec)\s*=\s*(id|whoami|uname|cat\s|ls\s)",
        r"eval\s*\(\s*base64_decode\s*\(",
    ]),
    ("suspicious_file_execution", "malware_post_exploitation", "high", "medium", [
        r"(/tmp|/dev/shm|/var/tmp)/[\w.\-]+\s+(;|&&|\|)",
        r"chmod\s+\+x\s+(/tmp|/dev/shm)",
    ]),
    ("persistence_indicator", "malware_post_exploitation", "high", "medium", [
        r"authorized_keys", r"/etc/cron", r"crontab\s", r"systemctl\s+enable",
        r"Run\\CurrentVersion\\Run", r"\.bashrc\b.*(curl|wget|nc|bash)",
    ]),
    ("privilege_escalation_indicator", "malware_post_exploitation", "high", "medium", [
        r"sudo\s+-l\b", r"pkexec\b", r"chmod\s+[ug]?\+s\b", r"/etc/shadow\b",
    ]),
    ("credential_access_indicator", "malware_post_exploitation", "high", "high", [
        r"mimikatz", r"sekurlsa", r"lsass", r"/etc/shadow\b", r"\.aws/credentials",
        r"\.ssh/id_rsa\b", r"ntds\.dit",
    ]),
    ("data_exfiltration_indicator", "malware_post_exploitation", "high", "medium", [
        r"(tar|zip)\s+.*(passwd|shadow|credentials|\.ssh)",
        r"curl\s+.*\s+(-d\s+@|--data-binary\s+@)\s*/(etc|home|root)",
    ]),
    ("remote_execution_indicator", "network_infrastructure", "high", "medium", [
        r"psexec", r"admin\$", r"wmic\s", r"Invoke-Expression", r"iex\s*\(",
    ]),
    ("scanning_tool_indicator", "network_infrastructure", "low", "low", [
        r"nmap", r"masscan", r"nikto", r"sqlmap", r"dirbuster", r"gobuster",
        r"nessus", r"nuclei",
    ]),
]

# Compiled once; also used by tests to assert no rule is vacuous.
COMPILED_RULES = [
    (attack_type, category, severity, confidence, [re.compile(p, re.IGNORECASE) for p in patterns])
    for attack_type, category, severity, confidence, patterns in _RULES
]

# SSRF via metadata hostname in structured metadata (not just raw text).
_METADATA_HOSTS = ("169.254.169.254", "metadata.google.internal")


def _is_private_host(host: str) -> bool:
    host = host.lower().strip()
    if host in ("localhost",) or host.startswith("127."):
        return True
    if host.startswith("10."):
        return True
    if host.startswith("192.168."):
        return True
    m = re.match(r"172\.(\d+)\.", host)
    if m and 16 <= int(m.group(1)) <= 31:
        return True
    return False


def analyze_text(text: str, metadata: Optional[dict] = None) -> list[dict]:
    """Deterministic findings for one log line / request / event text.

    metadata may carry endpoint, method, status, params: used only to
    (a) catch SSRF targets in structured fields and (b) label SQLi in
    credential fields as auth_bypass. Returns findings sorted by
    severity (high first), deduplicated by attack_type (strongest
    confidence wins). Empty input -> []."""
    if not text or not text.strip():
        return []
    metadata = metadata or {}
    findings: dict[str, dict] = {}

    def _add(attack_type, category, severity, confidence, evidence, subcategory=None):
        prev = findings.get(attack_type)
        rank = {"low": 0, "medium": 1, "high": 2}
        if prev is None or rank[confidence] > rank[prev["confidence"]]:
            findings[attack_type] = {
                "attack_category": category,
                "attack_type": attack_type,
                "attack_subtype": subcategory,
                "evidence": [evidence] if evidence else [],
                "confidence": confidence,
                "severity_hint": severity,
                "outcome": "attempted_or_detected",
                "mitre_suggestion": None,
            }
        elif evidence and evidence not in prev["evidence"]:
            prev["evidence"].append(evidence)

    for attack_type, category, severity, confidence, patterns in COMPILED_RULES:
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                subtype = None
                # SQLi-shaped input in a credential field is auth bypass.
                if attack_type == "sql_injection" and metadata.get("param") in (
                        "username", "password", "user", "login"):
                    subtype = "auth_bypass_via_injection"
                _add(attack_type, category, severity, confidence, _snippet(text, m), subtype)
                break

    # Structured SSRF: a URL-valued metadata field pointing at a
    # private/metadata host is stronger than a raw-text substring.
    for key in ("url", "target_url", "fetch_url", "redirect"):
        value = metadata.get(key)
        if isinstance(value, str):
            host = re.sub(r"^https?://", "", value).split("/")[0].split(":")[0]
            if host in _METADATA_HOSTS or _is_private_host(host):
                _add("server_side_request_forgery", "web_attack", "high", "high",
                     f"metadata field {key} targets private host {host}")
                break

    # DNS tunneling heuristic on a structured hostname: very long labels
    # in a high-entropy alphabet. Indicator only, low confidence.
    host = metadata.get("hostname") or metadata.get("host")
    if isinstance(host, str):
        labels = host.split(".")
        long_labels = [l for l in labels if len(l) > 40]
        if long_labels and re.fullmatch(r"[a-z2-7]+", long_labels[0]):
            _add("dns_tunneling_indicator", "network_infrastructure", "medium", "low",
                 f"overlong base32-like DNS label ({len(long_labels[0])} chars)")

    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings.values(), key=lambda f: order[f["severity_hint"]])


def classify_auth_attempts(attempts: list[dict], failure_threshold: int = 5) -> Optional[dict]:
    """Aggregate login attempts into one auth-attack classification.

    attempts: [{username, success: bool, password_hash?: str}].
    Password PLAINTEXT must never be passed here; password_hash is
    optional and only used to tell spraying (same hash, many users)
    from stuffing (distinct hashes, many users).
    Returns None when the volume does not meet the threshold, or a dict
    {attack_category, attack_type, confidence, evidence_summary,
    outcome, mitre_suggestion=None (filled by suggest_mitre)}."""
    failures = [a for a in attempts if not a.get("success")]
    if len(failures) < failure_threshold:
        return None
    users = Counter(a.get("username") for a in failures)
    distinct_users = len(users)
    max_per_user = max(users.values()) if users else 0
    hashes = [a.get("password_hash") for a in failures if a.get("password_hash")]
    distinct_hashes = len(set(hashes)) if hashes else 0

    if distinct_users == 1:
        if len(failures) >= 50:
            attack_type, confidence = "brute_force", "medium"
            summary = f"{len(failures)} failed logins for one account"
        else:
            attack_type, confidence = "password_guessing", "medium"
            summary = f"{len(failures)} failed logins for one account"
    elif hashes and distinct_hashes == 1 and distinct_users >= 5:
        attack_type, confidence = "password_spraying", "high"
        summary = (f"same password hash across {distinct_users} accounts, "
                   f"{len(failures)} failures")
    elif hashes and distinct_hashes >= 10 and distinct_users >= 10 and max_per_user <= 2:
        attack_type, confidence = "credential_stuffing", "medium"
        summary = (f"{distinct_hashes} distinct password hashes across "
                   f"{distinct_users} accounts, {len(failures)} failures")
    elif distinct_users >= 5 and max_per_user <= 3:
        attack_type, confidence = "password_spraying", "low"
        summary = (f"{len(failures)} failures spread across {distinct_users} "
                   f"accounts (≤3 each); without password hashes, spraying "
                   f"vs stuffing cannot be distinguished")
    else:
        attack_type, confidence = "repeated_auth_failure", "low"
        summary = f"{len(failures)} failures across {distinct_users} accounts"
    return {
        "attack_category": "auth_attack",
        "attack_type": attack_type,
        "attack_subtype": None,
        "evidence": [summary],
        "confidence": confidence,
        "severity_hint": "medium" if attack_type in ("password_guessing", "brute_force")
        else "high" if attack_type in ("password_spraying", "credential_stuffing") else "low",
        "outcome": "attempted_or_detected",
        "mitre_suggestion": None,
    }


def suggest_mitre(finding: dict, mitre=None) -> Optional[dict]:
    """The ONLY place a MITRE technique may be proposed from rules.

    Allowed: auth-pattern types -> T1110 family; web-shell evidence ->
    T1505.003. Everything else -> None. The ID must validate against
    the local dataset; on any failure (including a missing dataset)
    this returns None. The returned dict carries the validated name,
    tactic(s), rationale, and official reference — never an invented ID."""
    if mitre is None:
        try:
            from .mitre_attack import get_mitre
            mitre = get_mitre()
        except Exception:
            mitre = None
    if mitre is None:
        return None
    attack_type = finding.get("attack_type")
    candidates = {
        "password_guessing": ("T1110.001", "password-guessing pattern: repeated failures for one account"),
        "password_spraying": ("T1110.003", "password-spraying pattern: failures spread across many accounts"),
        "credential_stuffing": ("T1110.004", "credential-stuffing pattern: distinct credentials across many accounts"),
        "brute_force": ("T1110", "brute-force pattern: high-volume failures for one account"),
    }
    if attack_type in candidates:
        technique_id, rationale = candidates[attack_type]
    elif attack_type == "web_shell_indicator":
        technique_id = "T1505.003"
        rationale = "web-shell evidence observed (known webshell artifact or shell-execution parameter)"
    else:
        return None
    resolved = mitre.resolve(technique_id)
    if resolved is None:
        return None
    resolved["rationale"] = rationale
    resolved["evidence"] = list(finding.get("evidence", []))
    return resolved
