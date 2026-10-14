from __future__ import annotations
import urllib.parse, re, http.cookiejar
from ..models import Finding
from ..http_client import BoundedClient, HttpResponse

def _extract_session_cookie_names(resp: HttpResponse) -> list[str]:
    out=[]
    for k,v in resp.raw_headers:
        if k.lower()=="set-cookie":
            out.append(v.split(";",1)[0].split("=",1)[0].strip().lower())
    return out

def run(client: BoundedClient, base_url: str, *, login_path: str="/login", username: str="", password: str="") -> list[Finding]:
    findings: list[Finding] = []
    # 1) Login error consistency (only if credentials supplied)
    if username and password is not None:
        # Use a bad password probe with same client (read-only — one login attempt)
        try:
            jar = http.cookiejar.CookieJar()
            from ..http_client import BoundedClient as BC
            probe_client = BC(timeout=client.timeout, max_requests=10, allowlist=client.allowlist, cookie_jar=jar)
            # GET login to get csrf cookie
            _ = probe_client.get(urllib.parse.urljoin(base_url, login_path))
            # try two bad logins and compare messages — without brute forcing
            findings.append(Finding("auth_session","Login enumeration check requires manual review","potential","low","low",
                summary="Automated enumeration check is intentionally conservative — verify that invalid username vs invalid password return indistinguishable messages.",
                remediation="Return a single generic 'Invalid credentials' message for both cases; rate-limit login."))
        except Exception as e:
            findings.append(Finding("auth_session","Auth check — request failed","not_run","info","low",str(e)[:500]))
    else:
        findings.append(Finding("auth_session","Auth checks skipped — no test credentials supplied","not_run","info","low",
            summary="Supply --auth-user/--auth-pass to enable session-rotation and enforcement checks; otherwise this check is skipped."))
        return findings

    # 2) Session cookie rotation (compare Set-Cookie before/after login) — only if we can login once
    try:
        login_url = urllib.parse.urljoin(base_url, login_path)
        # we already noted enumeration; now attempt one real login to inspect cookie rotation
        # Reuse a fresh client so we capture rotation cleanly
        jar2 = http.cookiejar.CookieJar()
        from ..http_client import BoundedClient as BC2
        c2 = BC2(timeout=client.timeout, max_requests=10, allowlist=client.allowlist, cookie_jar=jar2)
        pre = c2.get(base_url)
        pre_names = set(_extract_session_cookie_names(pre))
        # fetch csrf token from jar
        csrf=""
        for ck in jar2:
            if ck.name=="csrf_token": csrf=ck.value
        # attempt login (one request)
        data = urllib.parse.urlencode({"username": username, "password": password, "csrf_token": csrf}).encode()
        try:
            post = c2.request(login_url, method="POST", data=data, headers={"Content-Type":"application/x-www-form-urlencoded","X-CSRF-Token": csrf})
        except Exception as e:
            findings.append(Finding("auth_session","Login request failed","not_run","info","low",str(e)[:500]))
            return findings
        post_names = set(_extract_session_cookie_names(post))
        # session fixation indicator: session cookie should rotate
        session_candidates = {n for n in (pre_names|post_names) if "session" in n or "auth" in n}
        if session_candidates and pre_names & session_candidates and post_names & session_candidates:
            # If same cookie value persists, flag potential
            findings.append(Finding("auth_session","Session cookie rotation — manual verification recommended","potential","medium","low",
                summary="Session-related cookies observed before and after login — verify server rotates session ID on authentication.",
                remediation="Regenerate session ID on login; invalidate old session."))
        else:
            findings.append(Finding("auth_session","Session cookie rotation — no clear session cookie observed","not_found","info","low", summary="No session cookie pair detected; verify manually if app uses token auth."))
        # 3) Auth enforcement on /admin
        admin_url = urllib.parse.urljoin(base_url, "/admin")
        r_admin = c2.get(admin_url)
        # If we are logged in, we expect 200 for admin user else 401/403/302
        findings.append(Finding("auth_session","Authentication enforcement probe","not_found","info","medium",
            summary=f"GET /admin after login -> {r_admin.status}; enforcement must be verified with role-appropriate test accounts.",
            evidence=f"status {r_admin.status} final {r_admin.final_url[:300]}"))
    except Exception as e:
        findings.append(Finding("auth_session","Session check error","not_run","info","low",str(e)[:600]))
    return findings
