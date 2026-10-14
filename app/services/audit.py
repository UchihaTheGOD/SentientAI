"""Internal audit trail + aggregate metrics.

Privacy rules (enforced here, not left to callers):
  * only event types from AUDIT_EVENT_TYPES are accepted;
  * `detail` is truncated to a short string — never a request dump;
  * IP addresses are hashed with the app secret and truncated, so the trail
    supports "same client?" correlation without retaining an identifier;
  * nothing that looks like a credential is written. Callers pass labels, not
    form data.

Audit writes must never break the user's request, so every function swallows its
own errors after rolling back.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models.audit import AUDIT_EVENT_TYPES, AuditEvent, DailyMetric, SearchQueryStat

logger = logging.getLogger("sentientai.audit")

MAX_DETAIL = 300


def hash_ip(raw: str | None) -> str | None:
    """Salted, truncated hash. Not reversible to an address."""
    if not raw:
        return None
    digest = hashlib.sha256(f"{settings.SECRET_KEY}:{raw}".encode("utf-8")).hexdigest()
    return digest[:32]


def client_ip(request) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def record(
    db: Session,
    event_type: str,
    *,
    user=None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    detail: str | None = None,
    request=None,
) -> None:
    """Append one internal audit event. Never raises."""
    if event_type not in AUDIT_EVENT_TYPES:
        logger.warning("Refusing unknown audit event type: %s", event_type)
        return
    try:
        entry = AuditEvent(
            event_type=event_type,
            user_id=getattr(user, "id", None),
            actor_label=(getattr(user, "username", None) or None),
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=(detail or "")[:MAX_DETAIL] or None,
            ip_hash=hash_ip(client_ip(request)),
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to write audit event %s", event_type)


def bump_metric(db: Session, metric: str, amount: int = 1, day: str | None = None) -> None:
    """Increment an aggregate counter. No per-user data is stored."""
    key = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        row = (
            db.query(DailyMetric)
            .filter(DailyMetric.day == key, DailyMetric.metric == metric[:60])
            .first()
        )
        if row is None:
            row = DailyMetric(day=key, metric=metric[:60], value=0)
            db.add(row)
        row.value = (row.value or 0) + amount
        db.commit()
    except Exception:
        db.rollback()


def record_search(db: Session, term: str) -> None:
    """Count a search term. Aggregate only — never linked to the searcher."""
    cleaned = (term or "").strip().lower()[:120]
    if len(cleaned) < 2:
        return
    try:
        row = db.query(SearchQueryStat).filter(SearchQueryStat.term == cleaned).first()
        if row is None:
            row = SearchQueryStat(term=cleaned, count=0)
            db.add(row)
        row.count = (row.count or 0) + 1
        row.last_seen = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()


def recent(db: Session, limit: int = 100, event_type: str | None = None):
    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    return query.order_by(AuditEvent.created_at.desc()).limit(limit).all()
