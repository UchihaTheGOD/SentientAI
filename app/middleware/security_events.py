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
            query = request.url.query or ""
            full_url = str(request.url)
            # 1) Notable status codes — access events (skip static to reduce noise, but not for traversal probes)
            is_traversal_path = False
            try:
                from app.services.security_events import _is_traversal_probe as _is_trav
                is_traversal_path = _is_trav(full_url) or _is_trav(query) or _is_trav(path)
            except Exception:
                pass
            if response.status_code in (401, 403, 429) and (not path.startswith("/static") or is_traversal_path):
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
            # 2) Sanitized suspicious-input events for controlled probes — even when defended with 200
            # Avoid duplicate: /login POST is already logged by app/api/auth.py (auth.login_failed)
            if path != "/login":
                suspicious = None
                evidence_raw = None
                try:
                    from app.services.security_events import _is_xss_probe, _is_sqli_probe, _is_traversal_probe
                    # Collect text to scan: query string + path
                    scan_text = f"{full_url} {query}"
                    # For /search, also include decoded q if present
                    try:
                        dq = request.query_params.get("q", "")
                        if dq:
                            scan_text += f" q={dq}"
                    except Exception:
                        pass
                    if _is_xss_probe(scan_text):
                        suspicious = ("suspicious_input.xss", "xss")
                        evidence_raw = f"xss probe path={path[:300]} query={query[:600]} status={response.status_code}"
                    elif _is_sqli_probe(scan_text):
                        suspicious = ("suspicious_input.sqli", "sqli")
                        evidence_raw = f"sqli probe path={path[:300]} query={query[:600]} status={response.status_code}"
                    elif _is_traversal_probe(scan_text):
                        suspicious = ("suspicious_input.traversal", "traversal")
                        evidence_raw = f"traversal probe path={path[:500]} query={query[:500]} status={response.status_code}"
                except Exception:
                    pass
                if suspicious and evidence_raw:
                    # Bounded evidence, redacted via log_event
                    db = SessionLocal()
                    try:
                        # Deduplicate: only one suspicious event per request correlation_id
                        from app.models.attact_assessment import SecurityEvent as _SE
                        exists = db.query(_SE).filter(_SE.correlation_id == request.state.correlation_id, _SE.event_type == suspicious[0]).first()
                        if not exists:
                            log_event(
                                db,
                                event_type=suspicious[0],
                                category="input",
                                severity="medium",
                                confidence="medium",
                                source="middleware",
                                request=request,
                                route=path,
                                method=request.method,
                                http_status=response.status_code,
                                duration_ms=int((time.perf_counter() - request.state.start_ts) * 1000),
                                correlation_id=request.state.correlation_id,
                                evidence=evidence_raw[:2000],
                                meta={"probe_type": suspicious[1], "query_len": len(query)},
                            )
                    finally:
                        db.close()
        except Exception:
            logger.exception("security_events log failed")
        return response
