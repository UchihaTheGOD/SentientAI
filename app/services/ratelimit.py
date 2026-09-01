"""In-process sliding-window rate limiting.

Deliberately simple: a dict of deques guarded by a lock. The application is a
single-process server backed by SQLite, so an external store (Redis) would add
infrastructure the project does not need (PHASE 36: "use the simplest
architecture compatible with the existing application").

Limits are intentionally generous — they stop scripted abuse, not real people.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

_LOCK = threading.Lock()
_HITS: dict[str, deque[float]] = defaultdict(deque)
_last_prune = 0.0
_PRUNE_INTERVAL = 300.0
_MAX_KEYS = 20_000


def _client_key(request: Request, bucket: str) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        request.client.host if request.client else "unknown"
    )
    # Include a short digest of the session cookie so several users behind one
    # NAT address are not throttled as a single client.
    token = request.cookies.get("access_token", "")
    session = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12] if token else "anon"
    return f"{bucket}:{ip}:{session}"


def _prune(now: float) -> None:
    global _last_prune
    if now - _last_prune < _PRUNE_INTERVAL and len(_HITS) < _MAX_KEYS:
        return
    _last_prune = now
    stale = [key for key, hits in _HITS.items() if not hits or now - hits[-1] > 3600]
    for key in stale:
        _HITS.pop(key, None)


def check(key: str, limit: int, window: float) -> float:
    """Record a hit. Returns 0.0 if allowed, else seconds until retry."""
    now = time.monotonic()
    with _LOCK:
        _prune(now)
        hits = _HITS[key]
        cutoff = now - window
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= limit:
            return max(1.0, window - (now - hits[0]))
        hits.append(now)
        return 0.0


def rate_limit(bucket: str, limit: int, window_seconds: float):
    """FastAPI dependency factory enforcing `limit` requests per window."""

    def dependency(request: Request) -> None:
        retry_after = check(_client_key(request, bucket), limit, window_seconds)
        if retry_after:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please slow down and try again shortly.",
                headers={"Retry-After": str(int(retry_after))},
            )

    return dependency


def reset() -> None:
    """Clear all counters (used by tests)."""
    with _LOCK:
        _HITS.clear()


# ---------------------------------------------------------------------------
# Shared limit definitions — one place to tune them.
# ---------------------------------------------------------------------------

limit_login = rate_limit("login", 12, 300)
limit_register = rate_limit("register", 6, 900)
limit_password = rate_limit("password", 6, 900)
limit_comment = rate_limit("comment", 20, 300)
limit_reaction = rate_limit("reaction", 80, 60)
limit_post_write = rate_limit("post_write", 15, 600)
limit_report = rate_limit("report", 10, 3600)
limit_search = rate_limit("search", 45, 60)
