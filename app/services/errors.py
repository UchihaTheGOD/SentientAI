"""Centralised, user-safe error responses.

PHASE 39: users never see stack traces or internal detail. Server-side logs
keep the diagnostics; the browser gets a plain page. Nothing here echoes
exception text for 5xx.
"""
from __future__ import annotations

import logging

from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("sentientai.errors")

_JSON_PREFIXES = ("/api/",)


def wants_json(request: Request) -> bool:
    if request.url.path.startswith(_JSON_PREFIXES):
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def _render(request: Request, template: str, status_code: int, **extra) -> Response:
    from app.template_env import templates

    context = {"request": request, "current_user": None}
    context.update(extra)
    try:
        return templates.TemplateResponse(template, context, status_code=status_code)
    except Exception:  # pragma: no cover - template missing/broken
        logger.exception("Failed rendering error template %s", template)
        return HTMLResponse(
            "<h1>Something went wrong</h1><p>Please try again later.</p>",
            status_code=status_code,
        )


def not_found_response(request: Request) -> Response:
    if wants_json(request):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return _render(request, "404.html", 404)


def unauthorized_response(request: Request) -> Response:
    if wants_json(request):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    next_url = request.url.path
    if request.url.query:
        next_url = f"{next_url}?{request.url.query}"
    from urllib.parse import quote

    target = "/login"
    if request.method == "GET" and next_url and next_url != "/":
        target = f"/login?next={quote(next_url, safe='/?=&')}"
    return RedirectResponse(url=target, status_code=303)


def forbidden_response(request: Request, detail: str | None = None) -> Response:
    if wants_json(request):
        return JSONResponse({"detail": detail or "Forbidden"}, status_code=403)
    return _render(request, "403.html", 403, detail=detail)


def rate_limited_response(request: Request, retry_after: int = 60) -> Response:
    if wants_json(request):
        response: Response = JSONResponse(
            {"detail": "Too many requests. Please slow down."}, status_code=429
        )
    else:
        response = _render(request, "429.html", 429, retry_after=retry_after)
    response.headers["Retry-After"] = str(max(1, int(retry_after)))
    return response


def server_error_response(request: Request) -> Response:
    if wants_json(request):
        return JSONResponse({"detail": "Internal server error"}, status_code=500)
    return _render(request, "500.html", 500)


def csrf_failure_response(request: Request) -> Response:
    if wants_json(request):
        return JSONResponse({"detail": "Invalid or missing CSRF token"}, status_code=403)
    return _render(
        request,
        "403.html",
        403,
        detail="Your session expired or the form was stale. Please reload the page and try again.",
    )
