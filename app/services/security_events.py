"""Central security-event logging, redaction, IP helpers, and fingerprints."""
from __future__ import annotations
import hashlib, hmac, json, re, ipaddress, time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.models.attact_assessment import SecurityEvent
from app.services.audit import hash_ip

# Secrets redacted before any storage/display
_SECRET_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|csrf[_-]?token|authorization)\s*[:=]\s*\S+")
_REDACT = "[REDACTED]"
_MAX_EVIDENCE = 4000
_MAX_META = 8000


def redact(text: str | None) -> str | None:
    if not text:
        return text
    red = _SECRET_RE.sub(r"\1=" + _REDACT, text)
    # also redact raw cookie header snippets if any slipped in
    red = re.sub(r"Cookie:[^\n]*", "Cookie: " + _REDACT, red, flags=re.I)
    red = re.sub(r"access_token[^\s;]*", "access_token=" + _REDACT, red, flags=re.I)
    return red[:_MAX_EVIDENCE]


def trusted_client_ip(request) -> str | None:
    """Resolve client IP honoring X-Forwarded-For only from trusted proxy.

    - Without TRUSTED_PROXY env, never trusts XFF (safe default).
    - If request.client hosts is in trusted set, the first XFF entry is used.
    - Otherwise request.client.host.
    """
    direct = request.client.host if request.client else None
    fwd = request.headers.get("x-forwarded-for", "")
    if not fwd or not direct:
        return direct
    trusted = _trusted_proxies()
    if direct in trusted:
        # also support CIDR entries
        return fwd.split(",")[0].strip()
    # also check CIDR set membership for loopback/cidr trusted
    try:
        ip = ipaddress.ip_address(direct)
        for net in _trusted_cidrs():
            if ip in net:
                return fwd.split(",")[0].strip()
    except Exception:
        pass
    return direct


def _trusted_proxies() -> set[str]:
    raw = __import__("os").getenv("TRUSTED_PROXY_IPS", "").strip()
    return {h.strip() for h in raw.split(",") if h.strip()}


def _trusted_cidrs():
    raw = __import__("os").getenv("TRUSTED_PROXY_CIDRS", "").strip()
    nets = []
    for c in raw.split(","):
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            pass
    return nets


def session_digest(request) -> str | None:
    """Bound to access_token cookie via HMAC so rotation invalidates correlation.

    Returns hex digest[:16] or None.
    """
    token = request.cookies.get("access_token", "")
    if not token:
        return None
    try:
        return hmac.new(settings.SECRET_KEY.encode(), token.encode(), hashlib.sha256).hexdigest()[:16]
    except Exception:
        return None


def fingerprint(request) -> dict[str, str]:
    """Per-request fingerprint (hashed, not raw) for correlation."""
    ua = (request.headers.get("user-agent") or "")[:300]
    al = (request.headers.get("accept-language") or "")[:200]
    sch = (request.headers.get("sec-ch-ua") or "")[:300]
    raw = f"{ua}|{al}|{sch}"
    h = hashlib.sha256(f"{settings.SECRET_KEY}:{raw}".encode()).hexdigest()[:24]
    return {"ua_hash": h, "ua": ua[:120]}


def log_event(
    db: Session,
    *,
    event_type: str,
    category: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    source: str | None = None,
    request=None,
    ip_address: str | None = None,
    user_id: int | None = None,
    route: str | None = None,
    method: str | None = None,
    http_status: int | None = None,
    duration_ms: int | None = None,
    correlation_id: str | None = None,
    assessment_id: int | None = None,
    incident_id: int | None = None,
    evidence: str | None = None,
    meta: dict | None = None,
) -> SecurityEvent:
    ip = ip_address
    if ip is None and request is not None:
        try:
            ip = trusted_client_ip(request)
        except Exception:
            ip = None
    sd = None
    ua = None
    try:
        if request is not None:
            sd = session_digest(request)
            ua = (request.headers.get("user-agent") or "")[:300]
    except Exception:
        pass
    if user_id is None and request is not None:
        try:
            u = getattr(request.state, "user", None)
            if u:
                user_id = getattr(u, "id", None)
        except Exception:
            pass
    ev = SecurityEvent(
        event_type=event_type,
        category=category,
        severity=severity,
        confidence=confidence,
        source=source,
        ip_address=(ip or None),
        ip_hash=hash_ip(ip) if ip else None,
        user_id=user_id,
        session_digest=sd,
        user_agent=ua,
        route=(route or (request.url.path if request else None)),
        method=(method or (request.method if request else None)),
        http_status=http_status,
        duration_ms=duration_ms,
        correlation_id=correlation_id,
        assessment_id=assessment_id,
        incident_id=incident_id,
        evidence=redact(evidence) if evidence else None,
        meta_json=json.dumps(meta, ensure_ascii=False)[:_MAX_META] if meta else None,
    )
    try:
        db.add(ev)
        db.commit()
        db.refresh(ev)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return ev
