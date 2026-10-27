"""The 14 scanner check categories (detection only).

Every check receives the ScanContext and must use ``ctx.fetch`` /
``ctx.fetch_no_follow`` so the safety gates apply. No check sends
anything but GET, executes anything, or extracts data. Markers are
inert alphanumeric tokens; a reflection or an error string is a
*suspected* indicator, never a confirmed vulnerability.
"""

from __future__ import annotations

import re
import secrets
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

import requests

from .engine import ScanContext, ScanRefused
from .findings import Finding, redact

REF = "OWASP Web Security Testing Guide; see report limitations."


def _marker() -> str:
    return "C11M4RK" + secrets.token_hex(4)


def _base(ctx: ScanContext) -> str:
    return ctx.config.target


def _headers(ctx: ScanContext) -> dict:
    resp = ctx.base_response
    if resp is None:
        return {}
    return {k.lower(): v for k, v in resp.headers.items()}


def _mk(ctx: ScanContext, name: str, category: str, severity: str,
        confidence: str, status: str, explanation: str, evidence: str,
        url: str, impact: str, remediation: str,
        reference: str = REF) -> Finding:
    return Finding(name, category, severity, confidence, status,
                   explanation, redact(evidence, 800), url, impact,
                   remediation, reference)


# ---------------------------------------------------------------- 1. headers
def check_headers_tls(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    headers = _headers(ctx)
    url = _base(ctx)
    expected = {
        "content-security-policy": (
            "Content Security Policy header is absent",
            "Without a CSP, the browser has no allowlist for script, style, "
            "and frame sources, which makes injected content easier to run.",
            "Add a restrictive Content-Security-Policy (for example, "
            "default-src 'self') and test it before enforcing it."),
        "x-frame-options": (
            "Clickjacking protection header is absent",
            "Without X-Frame-Options or frame-ancestors, the page can be "
            "framed by another site (clickjacking).",
            "Set X-Frame-Options: DENY or SAMEORIGIN, or frame-ancestors "
            "in the CSP."),
        "x-content-type-options": (
            "MIME-sniffing protection header is absent",
            "Without nosniff, browsers may guess a content type and treat "
            "an uploaded file as executable content.",
            "Set X-Content-Type-Options: nosniff on all responses."),
        "referrer-policy": (
            "Referrer policy header is absent",
            "Without a referrer policy, full URLs (which can contain "
            "sensitive query data) may leak to third parties.",
            "Set Referrer-Policy: strict-origin-when-cross-origin or "
            "no-referrer."),
        "permissions-policy": (
            "Permissions policy header is absent",
            "Without a permissions policy, powerful browser features "
            "(camera, microphone, geolocation) stay available to the page "
            "and embedded content by default.",
            "Set a restrictive Permissions-Policy disabling features the "
            "site does not use."),
    }
    for header, (name, impact, fix) in expected.items():
        if header not in headers:
            out.append(_mk(ctx, name, "HTTP security headers", "Low",
                           "medium", "verified",
                           f"The response does not include {header}. This is "
                           "a hardening gap, not proof of exploitability.",
                           f"Response headers: {', '.join(sorted(headers)) or '(none)'}",
                           url, impact, fix))
    if urlparse(url).scheme == "https":
        if "strict-transport-security" not in headers:
            out.append(_mk(ctx, "HSTS header is absent",
                           "HTTP security headers", "Low", "medium", "verified",
                           "The HTTPS response does not include "
                           "Strict-Transport-Security, so a first visit over "
                           "plain HTTP is not automatically upgraded.",
                           "Response headers checked; HSTS absent.", url,
                           "Downgrade and sslstrip-style attacks stay possible "
                           "on first visits.",
                           "Set Strict-Transport-Security with a long "
                           "max-age and includeSubDomains once HTTPS is "
                           "stable."))
        tls = _tls_info(ctx)
        if tls.get("error"):
            out.append(_mk(ctx, "TLS details unavailable",
                           "HTTP security headers", "Informational", "low",
                           "inconclusive",
                           "The TLS handshake details could not be read; "
                           "this is not a vulnerability finding.",
                           tls["error"], url,
                           "TLS configuration could not be assessed.",
                           "Verify TLS configuration with a dedicated TLS "
                           "assessment tool."))
        else:
            if tls.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                out.append(_mk(ctx, f"Outdated TLS version: {tls['version']}",
                               "HTTP security headers", "Medium", "high",
                               "verified",
                               "The server negotiated an obsolete TLS "
                               "version with known weaknesses.",
                               f"Negotiated: {tls['version']}", url,
                               "Traffic may be decryptable by a network "
                               "attacker.",
                               "Disable TLS 1.0/1.1 and SSL; require TLS 1.2+.",
                               "OWASP Transport Layer Protection Cheat Sheet."))
            if tls.get("days_left") is not None and tls["days_left"] < 30:
                out.append(_mk(ctx, "TLS certificate expires soon",
                               "HTTP security headers", "Low", "high",
                               "verified",
                               "The certificate expires in under 30 days.",
                               f"Expires in {tls['days_left']} day(s).", url,
                               "An expired certificate breaks trust and "
                               "availability.",
                               "Renew the certificate and automate renewal."))
    return out


def _tls_info(ctx: ScanContext) -> dict:
    parsed = urlparse(_base(ctx))
    host = parsed.hostname or ""
    port = parsed.port or 443
    try:
        import socket as _socket

        conn = _socket.create_connection((host, port), timeout=ctx.config.timeout_seconds)
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=host) as sock:
            version = sock.version() or ""
            cert = sock.getpeercert() or {}
        days_left = None
        raw_after = cert.get("notAfter", "")
        if raw_after:
            from datetime import datetime, timezone

            try:
                exp = datetime.strptime(raw_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                days_left = None
        return {"version": version, "days_left": days_left}
    except Exception as exc:
        return {"error": f"TLS probe failed: {exc}"}


# ---------------------------------------------------------------- 2. cookies
def check_cookies(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    resp = ctx.base_response
    url = _base(ctx)
    if resp is None:
        return out
    set_cookies = []
    try:
        raw_headers = resp.raw.headers  # urllib3 header dict
        if hasattr(raw_headers, "getlist"):
            set_cookies = raw_headers.getlist("Set-Cookie")
        else:
            value = resp.headers.get("Set-Cookie", "")
            set_cookies = [value] if value else []
    except Exception:
        set_cookies = []
    is_https = urlparse(url).scheme == "https"
    for cookie in set_cookies:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=")[0] if parts else "cookie"
        flags = {p.lower() for p in parts[1:]}
        if is_https and "secure" not in flags:
            out.append(_mk(ctx, f"Cookie without Secure flag: {name}",
                           "Cookies and session security", "Medium", "medium",
                           "verified",
                           "A cookie set over HTTPS lacks the Secure flag, "
                           "so it could be sent over plain HTTP if the site "
                           "is ever visited that way.",
                           f"Cookie: {name} (value redacted)", url,
                           "Session cookies sent over HTTP can be stolen on "
                           "an untrusted network.",
                           "Set the Secure flag on all cookies served over "
                           "HTTPS."))
        if "httponly" not in flags:
            out.append(_mk(ctx, f"Cookie without HttpOnly flag: {name}",
                           "Cookies and session security", "Low", "medium",
                           "verified",
                           "The cookie lacks HttpOnly, so page JavaScript "
                           "can read it.",
                           f"Cookie: {name} (value redacted)", url,
                           "A cross-site scripting flaw could steal the "
                           "cookie value.",
                           "Set the HttpOnly flag on session cookies."))
        if not any(f.startswith("samesite") for f in flags):
            out.append(_mk(ctx, f"Cookie without SameSite attribute: {name}",
                           "Cookies and session security", "Low", "medium",
                           "verified",
                           "The cookie has no SameSite attribute, so it is "
                           "sent on cross-site requests by default.",
                           f"Cookie: {name} (value redacted)", url,
                           "Cross-site request forgery becomes easier.",
                           "Set SameSite=Lax (or Strict for sensitive "
                           "cookies)."))
    if not set_cookies:
        out.append(_mk(ctx, "No cookies observed on the target page",
                       "Cookies and session security", "Informational",
                       "low", "verified",
                       "The base page sets no cookies. Session-cookie checks "
                       "therefore do not apply to this page.",
                       "No Set-Cookie header on the base response.", url,
                       "No direct impact; session handling lives elsewhere.",
                       "No action for this page; check authenticated flows "
                       "separately."))
    return out


# ------------------------------------------------------- 3. info disclosure
def check_info_disclosure(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    headers = _headers(ctx)
    url = _base(ctx)
    for header in ("server", "x-powered-by", "x-aspnet-version", "via"):
        if header in headers:
            out.append(_mk(ctx, f"Technology disclosed in {header} header",
                           "Information disclosure", "Informational",
                           "high", "verified",
                           "The response advertises software and, possibly, "
                           "its version. This alone is not a vulnerability, "
                           "but it helps an attacker pick known issues.",
                           f"{header}: {headers[header]}", url,
                           "Faster targeting of known vulnerabilities.",
                           "Remove or genericise version banners; keep "
                           "components patched."))
    body = ctx.base_body or ""
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
                  body, re.I)
    if m:
        out.append(_mk(ctx, "Technology disclosed in generator meta tag",
                       "Information disclosure", "Informational", "high",
                       "verified",
                       "The page advertises its generator software.",
                       f"generator: {m.group(1)}", url,
                       "Faster targeting of known vulnerabilities.",
                       "Remove the generator tag or keep the component "
                       "patched."))
    # Error-page disclosure: one GET to a random path, error text only.
    probe = urljoin(url if url.endswith("/") else url + "/", "seclab-nonexistent-" + secrets.token_hex(4))
    try:
        resp, text = ctx.fetch_text(probe)
        if resp.status_code == 404:
            for sig, label in (
                    ("Traceback", "Python traceback"),
                    ("Stack trace", "stack trace"),
                    ("SQLSTATE", "database error"),
                    ("ORA-", "Oracle error code"),
                    ("Exception in thread", "Java stack trace")):
                if sig in text:
                    out.append(_mk(ctx, f"Error page discloses {label}",
                                   "Information disclosure", "Low", "medium",
                                   "suspected",
                                   "A 404 page contains error internals. "
                                   "This is a suspected disclosure; the "
                                   "error text itself was not stored.",
                                   f"Signature present on 404 page: {sig}",
                                   probe,
                                   "Error internals help an attacker map "
                                   "the stack.",
                                   "Serve generic error pages in production; "
                                   "log details server-side only."))
                    break
    except (ScanRefused, requests.RequestException):
        pass
    return out


# --------------------------------------------------------- 4. sensitive files
_PUBLIC_FILES = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
_SENSITIVE_FILES = ("/.env", "/.git/HEAD", "/.git/config", "/wp-config.php",
                    "/config.php", "/.svn/entries", "/.DS_Store",
                    "/backup.zip", "/.bak")


def _probe_path(ctx: ScanContext, path: str) -> tuple[str, int, int, str]:
    base = _base(ctx)
    parsed = urlparse(base)
    target = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    try:
        resp = ctx.fetch(target)
        ctype = resp.headers.get("Content-Type", "")
        length = len(resp.content or b"")
        return target, resp.status_code, length, ctype
    except ScanRefused as exc:
        raise
    except requests.RequestException as exc:
        return target, 0, 0, f"error: {exc}"


def check_sensitive_files(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    paths = list(_PUBLIC_FILES) + list(_SENSITIVE_FILES)
    results: dict[str, tuple[str, int, int, str]] = {}

    def probe(path: str) -> None:
        try:
            results[path] = _probe_path(ctx, path)
        except ScanRefused as exc:
            results[path] = (path, -1, 0, f"refused: {exc}")

    workers = max(1, min(ctx.config.max_workers, 4))
    if workers > 1 and len(paths) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(probe, paths))
    else:
        for path in paths:
            probe(path)
    for path in _PUBLIC_FILES:
        target, status, _length, _ctype = results.get(path, (path, 0, 0, ""))
        if status == 200:
            out.append(_mk(ctx, f"Public file present: {path}",
                           "Sensitive files", "Informational", "high",
                           "verified",
                           "This file is meant to be public; its presence "
                           "is noted, not treated as a vulnerability.",
                           f"{path} returned HTTP 200.", target,
                           "Review its contents for anything that should "
                           "not be public (for example, disallowed paths "
                           "that confirm sensitive areas).",
                           "Keep public files accurate; do not list "
                           "sensitive paths in robots.txt."))
    for path in _SENSITIVE_FILES:
        target, status, length, ctype = results.get(path, (path, 0, 0, ""))
        if status == 200:
            out.append(_mk(ctx, f"Sensitive file publicly accessible: {path}",
                           "Sensitive files", "High", "medium", "suspected",
                           "The path returned HTTP 200. The body was NOT "
                           "stored or inspected beyond its length, so this "
                           "is a suspected exposure, not a confirmed leak.",
                           f"{path} returned HTTP 200 ({length} bytes, "
                           f"{ctype or 'unknown type'}); body not stored.",
                           target,
                           "If the file holds credentials, config, or "
                           "repository data, it may be disclosed.",
                           "Block web access to this path, remove the file "
                           "from the web root, and rotate anything it may "
                           "have contained."))
    return out


# --------------------------------------------------------- 5. dir listing
def check_dir_listing(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    base = _base(ctx)
    parsed = urlparse(base)
    candidates = ["/uploads/", "/static/", "/files/", "/images/", "/assets/"]
    for cand in candidates:
        target = urlunsplit((parsed.scheme, parsed.netloc, cand, "", ""))
        try:
            resp, text = ctx.fetch_text(target)
        except (ScanRefused, requests.RequestException):
            continue
        if resp.status_code == 200 and re.search(
                r"Index of /|Directory Listing For|Parent Directory",
                text, re.I):
            out.append(_mk(ctx, f"Directory listing enabled: {cand}",
                           "Directory listing", "Medium", "high", "verified",
                           "The directory returns an auto-generated file "
                           "listing.",
                           f"Listing signature present at {cand}.", target,
                           "File names and structure are disclosed, which "
                           "aids further probing.",
                           "Disable directory indexes and serve only "
                           "intended files."))
    return out


# ------------------------------------------- 6/7/8. parameter probes (shared)
def _probe_params(ctx: ScanContext, value_fn) -> list[tuple[str, str, str]]:
    """GET the target with each query param replaced (max 3), plus one
    appended probe param. Returns (param, url, body)."""
    base = _base(ctx)
    parsed = urlparse(base)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    results: list[tuple[str, str, str]] = []
    probes: list[tuple[str, str]] = []
    for key, _val in params[:3]:
        new_q = urlencode([(k, value_fn(k) if k == key else v)
                           for k, v in params])
        probes.append((key, urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, new_q, ""))))
    if not params:
        probes.append(("seclab_probe", urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path,
             urlencode([("seclab_probe", value_fn("seclab_probe"))]), ""))))
    for key, url in probes:
        try:
            _resp, body = ctx.fetch_text(url)
            results.append((key, url, body))
        except (ScanRefused, requests.RequestException):
            continue
    return results


def check_reflected_input(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    marker = _marker()
    for key, url, body in _probe_params(ctx, lambda _k: marker):
        if marker in body:
            out.append(_mk(ctx, f"Reflected input in parameter: {key}",
                           "Input validation", "Low", "low", "suspected",
                           "An inert marker sent as a parameter value is "
                           "reflected in the response. Reflection alone "
                           "does not confirm cross-site scripting; it is "
                           "a prompt to review output encoding.",
                           f"Marker reflected for parameter '{key}'.",
                           url,
                           "If reflection is unescaped in an executable "
                           "context, stored or reflected XSS becomes "
                           "possible.",
                           "Encode output for its context and validate "
                           "input; retest with a proper XSS review."))
    return out


_SQL_ERROR_SIGS = ("SQL syntax", "mysql_fetch", "mysqli_", "ORA-",
                   "sqlite3.", "psycopg", "pg_query", "Warning: mysql",
                   "Unclosed quotation mark", "SQLSTATE")


def check_sqli(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    marker = _marker()
    for key, url, body in _probe_params(ctx, lambda _k: marker + "'"):
        for sig in _SQL_ERROR_SIGS:
            if sig in body:
                out.append(_mk(ctx, f"Database error message: parameter {key}",
                               "SQL injection indicators", "High", "medium",
                               "suspected",
                               "A non-destructive probe (a single quote "
                               "appended to an inert marker) produced a "
                               "database error string. No data was "
                               "extracted and injection is NOT confirmed; "
                               "the error text itself was not stored.",
                               f"Error signature present: {sig}", url,
                               "Error messages confirm a database-backed "
                               "parameter and may precede injection.",
                               "Use parameterised queries everywhere, "
                               "suppress database errors in responses, "
                               "and review this parameter."))
                break
    return out


def check_xss(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    marker = _marker()
    for key, url, body in _probe_params(ctx, lambda _k: marker):
        idx = body.find(marker)
        if idx < 0:
            continue
        window = body[max(0, idx - 200):idx]
        if "<script" in window.lower() and "</script>" not in window.lower():
            context, confidence = "inside a script block", "medium"
        elif re.search(r"on\w+\s*=\s*[\"']?$", window, re.I):
            context, confidence = "inside an event-handler attribute", "medium"
        else:
            context, confidence = "in general HTML content", "low"
        out.append(_mk(ctx, f"Reflected marker in executable-adjacent context: {key}",
                       "Cross-site scripting indicators", "Medium" if confidence == "medium" else "Low",
                       confidence, "suspected",
                       "An inert alphanumeric marker (never a script "
                       "payload) was reflected " + context + ". Nothing "
                       "was executed. This is a suspected indicator that "
                       "output encoding needs review, not a confirmed XSS.",
                       f"Marker reflected {context} for parameter '{key}'.",
                       url,
                       "Unescaped reflection in an executable context can "
                       "become reflected XSS.",
                       "Encode output for its context, apply a strict CSP, "
                       "and validate input."))
    return out


# ---------------------------------------------------------------- 9. SSRF
_URL_PARAMS = ("url", "redirect", "next", "return", "dest", "target",
               "file", "path", "uri", "image", "page", "continue")


def check_ssrf(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    parsed = urlparse(_base(ctx))
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key in params:
        if key.lower() not in _URL_PARAMS:
            continue
        out.append(_mk(ctx, f"URL-valued parameter present: {key}",
                       "SSRF indicators", "Low", "low", "suspected",
                       "A parameter accepts a URL-like value. Whether the "
                       "server fetches that URL was NOT tested: this tool "
                       "never asks a server to fetch an internal address, "
                       "so this is a suspected sink, not a confirmed SSRF.",
                       f"Parameter '{key}' present in the target URL.", _base(ctx),
                       "If the server fetches the supplied URL, internal "
                       "services and cloud metadata could be reached.",
                       "Allowlist fetch destinations, block private and "
                       "link-local ranges server-side, and do not pass "
                       "raw user URLs to fetchers."))
        # Open-redirect test: point the parameter at a neutral external
        # host and inspect the Location header only (never follow it).
        new_q = urlencode([(k, "https://example.com/" if k == key else v)
                           for k, v in params.items()])
        probe = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_q, ""))
        try:
            resp = ctx.fetch_no_follow(probe)
        except (ScanRefused, requests.RequestException):
            continue
        location = resp.headers.get("Location", "")
        if resp.is_redirect and "example.com" in location:
            out.append(_mk(ctx, f"Open redirect via parameter: {key}",
                           "SSRF indicators", "Medium", "high", "suspected",
                           "The server redirected to a neutral external "
                           "host supplied in the parameter. The redirect "
                           "was observed, not followed.",
                           f"Location: {location}", probe,
                           "Open redirects enable phishing and can mask "
                           "malicious destinations.",
                           "Allowlist redirect destinations or use "
                           "internal redirect identifiers."))
    return out


# ------------------------------------------------------------- 10. auth config
def check_auth_config(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    body = ctx.base_body or ""
    url = _base(ctx)
    is_https = urlparse(url).scheme == "https"
    has_login_form = bool(re.search(
        r'<input[^>]+type=["\']password["\']', body, re.I))
    if has_login_form and not is_https:
        out.append(_mk(ctx, "Login form served over plain HTTP",
                       "Authentication configuration", "High", "high",
                       "verified",
                       "The page contains a password field but is served "
                       "over HTTP. No login was attempted.",
                       "Password input present on an HTTP page.", url,
                       "Credentials would travel in cleartext.",
                       "Serve login pages and forms over HTTPS only."))
    parsed = urlparse(url)
    admin_url = urlunsplit((parsed.scheme, parsed.netloc, "/admin", "", ""))
    try:
        resp, text = ctx.fetch_text(admin_url)
        if resp.status_code == 200 and not re.search(
                r'<input[^>]+type=["\']password["\']', text, re.I):
            out.append(_mk(ctx, "Admin path reachable without a login form",
                           "Authentication configuration", "Medium", "low",
                           "suspected",
                           "/admin returned HTTP 200 without a password "
                           "field. This may be a public page or an "
                           "unprotected admin area; authorization was not "
                           "tested and no bypass was attempted.",
                           "/admin returned HTTP 200.", admin_url,
                           "An unprotected admin area could expose "
                           "privileged functions.",
                           "Verify /admin requires authentication and "
                           "authorization; return 403/redirect otherwise."))
    except (ScanRefused, requests.RequestException):
        pass
    return out


# --------------------------------------------------------------- 11. misconfig
def check_misconfig(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    headers = _headers(ctx)
    url = _base(ctx)
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        out.append(_mk(ctx, "Permissive CORS with credentials",
                       "Misconfigurations", "Medium", "high", "verified",
                       "The response allows any origin with credentials, "
                       "which lets other sites read authenticated "
                       "responses.",
                       "Access-Control-Allow-Origin: * with "
                       "Allow-Credentials: true.", url,
                       "Cross-origin theft of authenticated data.",
                       "Reflect only trusted origins and never combine "
                       "a wildcard origin with credentials."))
    elif acao == "*":
        out.append(_mk(ctx, "Wildcard CORS origin",
                       "Misconfigurations", "Low", "medium", "verified",
                       "The response allows any origin (without "
                       "credentials).",
                       "Access-Control-Allow-Origin: *.", url,
                       "Public data can be read cross-origin; combined "
                       "with other flaws this widens impact.",
                       "Restrict allowed origins to the ones the API "
                       "actually serves."))
    # TRACE method: a read-only echo check, never used to modify anything.
    try:
        resp = ctx.session.request(
            "TRACE", ctx.check_target(url),
            timeout=ctx.config.timeout_seconds, allow_redirects=False)
        if resp.status_code == 200:
            out.append(_mk(ctx, "HTTP TRACE method enabled",
                           "Misconfigurations", "Low", "medium", "verified",
                           "The server answers TRACE, which echoes request "
                           "data and can assist cross-site tracing.",
                           "TRACE returned HTTP 200.", url,
                           "Assists header/cookie theft in old browsers.",
                           "Disable TRACE (and TRACK) at the server."))
    except (ScanRefused, requests.RequestException):
        pass
    for path in ("/debug", "/console"):
        parsed = urlparse(url)
        target = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        try:
            resp, _text = ctx.fetch_text(target)
        except (ScanRefused, requests.RequestException):
            continue
        if resp.status_code == 200:
            out.append(_mk(ctx, f"Debug-style path reachable: {path}",
                           "Misconfigurations", "Medium", "low", "suspected",
                           f"{path} returned HTTP 200. It may be a harmless "
                           "page or an exposed debug interface; no "
                           "interaction beyond the GET was performed.",
                           f"{path} returned HTTP 200.", target,
                           "Debug interfaces can expose internals and "
                           "evaluation features.",
                           "Remove debug endpoints from production or "
                           "restrict them to administrators."))
    return out


# ------------------------------------------------------------ 12. API assess
def check_api_assessment(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    parsed = urlparse(_base(ctx))
    for path in ("/api", "/api/docs", "/openapi.json", "/swagger.json",
                 "/api/openapi.json"):
        target = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        try:
            resp, text = ctx.fetch_text(target)
        except (ScanRefused, requests.RequestException):
            continue
        if resp.status_code == 200 and ("openapi" in text.lower()
                                        or "swagger" in text.lower()):
            out.append(_mk(ctx, f"API documentation publicly accessible: {path}",
                           "API assessment", "Medium", "medium", "suspected",
                           "An API description document is reachable "
                           "without authentication. It maps the API "
                           "surface; whether endpoints enforce auth was "
                           "not tested beyond this GET.",
                           f"{path} returned HTTP 200 with an OpenAPI/Swagger document.",
                           target,
                           "Attackers gain a full API map for further "
                           "probing.",
                           "Restrict API docs to authenticated developers "
                           "or remove them from production."))
        elif resp.status_code in (401, 403):
            out.append(_mk(ctx, f"API path protected: {path}",
                           "API assessment", "Informational", "high",
                           "verified",
                           "The API path requires authentication.",
                           f"{path} returned HTTP {resp.status_code}.",
                           target,
                           "No direct impact observed.",
                           "No action; keep auth enforced on all API routes."))
    return out


# ------------------------------------------------------ 13. redirects/mixed
def check_redirects_mixed(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    url = _base(ctx)
    parsed = urlparse(url)
    if parsed.scheme == "http":
        https_url = urlunsplit(("https", parsed.netloc, parsed.path,
                                parsed.query, ""))
        try:
            resp = ctx.fetch_no_follow(url)
            location = resp.headers.get("Location", "")
            if not (resp.is_redirect and location.startswith("https://")):
                out.append(_mk(ctx, "No automatic upgrade from HTTP to HTTPS",
                               "Redirects and transport", "Medium", "medium",
                               "verified",
                               "The HTTP target does not redirect to HTTPS.",
                               f"GET {url} did not redirect to HTTPS.", url,
                               "Traffic and any credentials stay in "
                               "cleartext.",
                               "Redirect all HTTP traffic to HTTPS and "
                               "enable HSTS."))
        except (ScanRefused, requests.RequestException):
            pass
    if parsed.scheme == "https":
        http_refs = re.findall(r'https?://[^\s"\'<>]+', ctx.base_body or "")
        insecure = sorted({r for r in http_refs if r.startswith("http://")})
        if insecure:
            out.append(_mk(ctx, "Mixed content references on HTTPS page",
                           "Redirects and transport", "Low", "medium",
                           "verified",
                           "The HTTPS page references plain-HTTP resources, "
                           "which browsers may block or load insecurely.",
                           f"Insecure references: {', '.join(insecure[:5])}",
                           url,
                           "Mixed content weakens HTTPS guarantees and "
                           "can break page functionality.",
                           "Serve all subresources over HTTPS."))
    return out


# --------------------------------------------------------- 14. CVE signatures
_EOL_TOKENS = (
    ("Apache/2.2", "Apache 2.2 (end of life)"),
    ("Apache/2.0", "Apache 2.0 (end of life)"),
    ("Microsoft-IIS/7", "IIS 7 (end of life)"),
    ("Microsoft-IIS/8", "IIS 8 (end of life)"),
    ("nginx/1.0", "nginx 1.0 (very old)"),
    ("nginx/1.2", "nginx 1.2 (very old)"),
    ("PHP/5", "PHP 5 (end of life)"),
    ("OpenSSL/1.0.1", "OpenSSL 1.0.1 (Heartbleed-era)"),
)


def check_cve_signatures(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []
    headers = _headers(ctx)
    url = _base(ctx)
    banner = " ".join(headers.get(h, "") for h in ("server", "x-powered-by"))
    for token, label in _EOL_TOKENS:
        if token.lower() in banner.lower():
            out.append(_mk(ctx, f"Outdated component indicated: {label}",
                           "CVE exposure indicators", "Medium", "low",
                           "suspected",
                           "A response banner names an end-of-life "
                           "component. Banners can be spoofed or stale, "
                           "so this is a heuristic indicator only — "
                           "confirm the real version independently before "
                           "treating any CVE as applicable.",
                           f"Banner: {banner}", url,
                           "End-of-life components stop receiving "
                           "security fixes.",
                           "Upgrade the component and remove version "
                           "banners.",
                           "Vendor lifecycle documentation."))
    return out


ALL_CHECKS = [
    {"id": "headers_tls", "name": "HTTP security headers and TLS", "run": check_headers_tls},
    {"id": "cookies", "name": "Cookie and session flags", "run": check_cookies},
    {"id": "info_disclosure", "name": "Information disclosure", "run": check_info_disclosure},
    {"id": "sensitive_files", "name": "Sensitive files", "run": check_sensitive_files},
    {"id": "dir_listing", "name": "Directory listing", "run": check_dir_listing},
    {"id": "reflected_input", "name": "Reflected input", "run": check_reflected_input},
    {"id": "sqli", "name": "SQL injection indicators", "run": check_sqli},
    {"id": "xss", "name": "XSS indicators", "run": check_xss},
    {"id": "ssrf", "name": "SSRF indicators", "run": check_ssrf},
    {"id": "auth_config", "name": "Authentication configuration", "run": check_auth_config},
    {"id": "misconfig", "name": "Misconfigurations", "run": check_misconfig},
    {"id": "api_assessment", "name": "API assessment", "run": check_api_assessment},
    {"id": "redirects_mixed", "name": "Redirects and transport", "run": check_redirects_mixed},
    {"id": "cve_signatures", "name": "CVE exposure indicators", "run": check_cve_signatures},
]
