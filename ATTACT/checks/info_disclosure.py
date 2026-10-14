from __future__ import annotations
import re, urllib.parse
from ..models import Finding
from ..http_client import BoundedClient

TRACES = [r"Traceback", r"File \".*\.py\", line \d+", r"Exception", r"stack trace", r"at .*\(.*:\d+\)"]
SENSITIVE_HINTS = [r"SECRET_KEY", r"password", r"api[_-]?key", r"\.env", r"BEGIN .*PRIVATE KEY"]

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    findings=[]
    # trigger error page with a missing route
    miss = urllib.parse.urljoin(base_url, "/__attact_no_such_route_9f3a1b")
    try:
        r = client.get(miss)
        body = r.body
        has_trace = any(re.search(p, body, re.I) for p in TRACES)
        has_hint = any(re.search(p, body, re.I) for p in SENSITIVE_HINTS)
        if has_hint:
            findings.append(Finding("info_disclosure","Error response may expose sensitive string","potential","high","low",
                summary="Response body matched a sensitive-pattern hint — manual review required; never confirm from a single match.",
                evidence=body[:1200], remediation="Ensure 5xx pages use generic error templates (see app/services/errors.py) and never echo config."))
        elif has_trace:
            findings.append(Finding("info_disclosure","Verbose error / stack trace observed","potential","medium","medium",
                summary="Response contained a traceback-like pattern — verify error handlers suppress exception text.",
                evidence=body[:1200], remediation="Keep generic error pages; log tracebacks server-side only."))
        else:
            findings.append(Finding("info_disclosure","No verbose errors on missing route","not_found","info","medium", summary=f"404 body did not contain trace patterns (status {r.status})."))
    except Exception as e:
        findings.append(Finding("info_disclosure","Missing-route probe failed","not_run","info","low",str(e)[:500]))
    # Check accidental .env / config exposure (harmless GET, expect 404)
    for probe in ["/.env", "/config.py", "/.git/config", "/api/docs"]:
        u = urllib.parse.urljoin(base_url, probe)
        try:
            r2 = client.get(u)
            if r2.status==200 and probe in ["/.env","/.git/config"] and len(r2.body)>50:
                findings.append(Finding("info_disclosure", f"Sensitive path {probe} is exposed","confirmed","critical","high",
                    summary=f"GET {probe} returned 200 with content — sensitive file may be exposed.", evidence=r2.body[:800],
                    remediation="Serve only the intended static/public paths; deny dotfiles and source files at the web server."))
            elif r2.status==200 and probe=="/api/docs":
                findings.append(Finding("info_disclosure","API docs exposed","potential","low","high",
                    summary="OpenAPI docs at /api/docs are reachable — consider restricting in production.", evidence=f"status {r2.status}"))
        except Exception:
            pass
    return findings
