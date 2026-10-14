"""ATTACT runner — orchestrates checks with scope, limits, and reporting."""
from __future__ import annotations
import datetime, time, http.cookiejar
from typing import Optional
from .scope import TargetConfig, validate_target, ScopeError
from .http_client import BoundedClient, StopRequested
from .models import Finding, Report

CHECKS = ["security_headers","cookie_security","xss","sqli","path_traversal","auth_session","access_control","csrf","input_validation","rate_limit","cors","info_disclosure"]

def run_assessment(*, target_url: str, allowlist: list[str]|None=None, confirm_authorized: bool=False,
                   checks: list[str]|None=None, timeout: float=6.0, max_requests: int=120,
                   auth_user: str="", auth_pass: str="",
                   access_user_a: str="", access_pass_a: str="", access_user_b: str="", access_pass_b: str="",
                   rate_limit_path: str="/login", rate_limit_count: int=6,
                   ) -> Report:
    t0=time.time()
    cfg=TargetConfig(target_url=target_url, allowlist=allowlist or [], confirm_authorized=confirm_authorized)
    try:
        parsed=validate_target(cfg)
    except ScopeError as e:
        raise
    active = [c for c in (checks or CHECKS) if c in CHECKS]
    if not active: raise ValueError(f"No valid checks selected. Available: {CHECKS}")
    wl=cfg.normalized_allowlist()
    jar=http.cookiejar.CookieJar()
    client=BoundedClient(timeout=timeout, max_requests=max_requests, allowlist=wl, cookie_jar=jar)
    findings: list[Finding]=[]
    base=parsed.geturl()
    limit_notes=[]
    def safe_run(name, fn, *a, **kw):
        before=client.request_count
        try: res=fn(client, base, *a, **kw)
        except StopRequested as e:
            limit_notes.append(str(e))
            return []
        except Exception as e:
            return [Finding(name, f"{name} — error","not_run","info","low", f"{e}"[:800])]
        after=client.request_count
        for f in res: f.request_count = after-before
        return res

    from .checks import security_headers, cookie_security, xss, sqli, path_traversal, auth_session, access_control, csrf, input_validation, rate_limit, cors, info_disclosure

    MAP={
        "security_headers": lambda: safe_run("security_headers", security_headers.run),
        "cookie_security": lambda: safe_run("cookie_security", cookie_security.run),
        "xss": lambda: safe_run("xss", xss.run),
        "sqli": lambda: safe_run("sqli", sqli.run),
        "path_traversal": lambda: safe_run("path_traversal", path_traversal.run),
        "auth_session": lambda: safe_run("auth_session", auth_session.run, username=auth_user, password=auth_pass),
        "access_control": lambda: safe_run("access_control", access_control.run, user_a=(access_user_a,access_pass_a), user_b=(access_user_b,access_pass_b)),
        "csrf": lambda: safe_run("csrf", csrf.run),
        "input_validation": lambda: safe_run("input_validation", input_validation.run),
        "rate_limit": lambda: safe_run("rate_limit", rate_limit.run, path=rate_limit_path, count=rate_limit_count),
        "cors": lambda: safe_run("cors", cors.run),
        "info_disclosure": lambda: safe_run("info_disclosure", info_disclosure.run),
    }
    for name in active:
        findings.extend(MAP[name]())
        if client.request_count >= max_requests:
            limit_notes.append(f"Request limit {max_requests} reached — remaining checks marked not_run")
            for rem in active[active.index(name)+1:]:
                findings.append(Finding(rem, f"{rem} — skipped (request limit)","not_run","info","low","Skipped due to request limit."))
            break

    elapsed=int((time.time()-t0)*1000)
    limitations=[
        "No single status/keyword is treated as proof of a vulnerability — 'potential' requires manual verification.",
        "Read-only, low-rate checks only — no brute force, DoS, or data extraction was attempted.",
        "Redirect scope revalidation and loopback default are enforced; allowlist any other host explicitly.",
    ]
    if limit_notes: limitations.extend(limit_notes)
    return Report(target=base, timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  checks=active, findings=findings, request_count=client.request_count,
                  allowlist=sorted(wl), elapsed_ms=elapsed, limitations=limitations)
