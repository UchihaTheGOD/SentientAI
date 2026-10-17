"""Security Test Lab — controlled, bounded HTTP + synthetic evidence tests."""
from __future__ import annotations
import json, re, time, uuid, urllib.parse, os, threading
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from app.models.security_lab import SecurityLabRun
_TEST_LOCK = threading.Lock()
_TEST_TYPES = {"xss","sqli","traversal","login_fail","port_scan","bruteforce","custom"}
def _allowlist() -> set[str]:
    raw = (os.getenv("SECURITY_LAB_ALLOWLIST") or "").strip()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}
def _local_origin() -> str:
    return (os.getenv("SECURITY_LAB_ORIGIN") or "http://127.0.0.1:8000").strip()
def validate_target_url(raw: str) -> tuple[str, str | None]:
    if not raw or not raw.strip():
        return "", "target required"
    raw = raw.strip()
    if len(raw) > 600:
        return "", "target too long"
    p = urllib.parse.urlparse(raw)
    if p.scheme not in ("http","https"):
        return "", "only http/https allowed"
    if p.username or p.password:
        return "", "credentials in URL not allowed"
    if not p.hostname:
        return "", "target has no host"
    host = p.hostname.lower()
    wl = _allowlist()
    origin_host = (urllib.parse.urlparse(_local_origin()).hostname or "").lower()
    allowed = {h for h in (wl | {origin_host, "127.0.0.1", "localhost", "::1", "testserver"}) if h}
    if host not in allowed and not host.startswith("127."):
        return "", f"target host '{host}' not allowed (use {_local_origin()} or SECURITY_LAB_ALLOWLIST)"
    path = p.path or "/"
    if len(path) > 500:
        return "", "path too long"
    query = p.query or ""
    if len(query) > 800:
        return "", "query too long"
    rebuilt = f"{p.scheme}://{p.netloc}{path}"
    if query:
        rebuilt += f"?{query}"
    return rebuilt, None
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
def _synthetic_evidence(test_type: str, custom: str | None = None) -> str:
    if test_type == "port_scan":
        return "[SYNTHETIC EVIDENCE port_scan] 2024-01-01 12:00:00 scan 10.0.0.5 ports 22,80,135,445,3389 SYN scan synthetic fixture"
    if test_type == "bruteforce":
        return "[SYNTHETIC EVIDENCE bruteforce] 2024-01-01 12:00:00-12:05:00 203.0.113.7 5 failed logins for admin 401 then success 200 synthetic fixture"
    return f"[SYNTHETIC] {custom or test_type}"[:1200]
def CANARYForType(t: str) -> str:
    if t == "xss": return "ATTACT-XSS-CANARY-9f3a1b<script>alert(1)</script>"
    if t == "sqli": return "'\" ATTACT"
    if t == "traversal": return "../../etc/passwd"
    return ""
lab_run_lock = _TEST_LOCK
