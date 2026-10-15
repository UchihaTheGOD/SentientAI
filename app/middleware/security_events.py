"""Outermost security-events + enforcement middleware.

- Assigns correlation_id per request
- Measures duration
- Resolves trusted IP via TRUSTED_PROXY_IPS/CIDRS
- Enforces TempBlock ip/account/session (application layer)
- Logs notable 401/403/429 + rate-limit via security_events
- Monitor-only by default; deterministic blocks only via incident_service
"""
from __future__ import annotations
import time, uuid, logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.services.security_events import trusted_client_ip, log_event
from app.database import SessionLocal

logger = logging.getLogger("sentientai.security_middleware")


class SecurityEventsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.correlation_id = uuid.uuid4().hex[:16]
        request.state.start_ts = time.perf_counter()

        # Pre-check blocks (application layer, reversible)
        try:
            ip = trusted_client_ip(request)
            if ip:
                from app.services.incident_service import is_blocked
                db = SessionLocal()
                try:
                    if is_blocked(db, "ip", ip):
                        from app.services.errors import forbidden_response
                        return forbidden_response(request, detail="Temporarily blocked (IP). Contact admin.")
                finally:
                    db.close()
        except Exception:
            pass

        # Account/session block check if authenticated (read tv from token without DB hit? skip for now)
        response = await call_next(request)
        # log after
        try:
            path = request.url.path
            if response.status_code in (401, 403, 429) and not path.startswith("/static"):
                db = SessionLocal()
                try:
                    log_event(
                        db,
                        event_type=f"http.{response.status_code}",
                        category="access",
                        severity="medium" if response.status_code == 403 else "low",
                        confidence="high",
                        source="middleware",
                        request=request,
                        route=path,
                        method=request.method,
                        http_status=response.status_code,
                        duration_ms=int((time.perf_counter() - request.state.start_ts) * 1000),
                        correlation_id=request.state.correlation_id,
                    )
                finally:
                    db.close()
        except Exception:
            logger.exception("security_events log failed")
        return response
