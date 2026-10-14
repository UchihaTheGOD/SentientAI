from __future__ import annotations
from ..models import Finding
from ..http_client import BoundedClient
from ..utils import parse_set_cookie_headers

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    try:
        r = client.get(base_url)
    except Exception as e:
        return [Finding("cookie_security","Cookie security — request failed","not_run","info","low",str(e)[:500])]
    cookies = parse_set_cookie_headers(r.raw_headers)
    if not cookies:
        return [Finding("cookie_security","No Set-Cookie observed","not_found","info","medium","No cookies set on GET / — check authenticated endpoints.", evidence=f"status {r.status}")]
    out=[]
    for c in cookies:
        issues=[]
        if not c["has_httponly"]: issues.append("missing HttpOnly")
        if not c["has_samesite"]: issues.append("missing SameSite")
        # Secure is expected on https; on http it would break, so only flag as potential
        from urllib.parse import urlparse
        is_https = urlparse(base_url).scheme=="https"
        if is_https and not c["has_secure"]: issues.append("missing Secure (https)")
        status = "potential" if issues else "not_found"
        sev = "medium" if "missing HttpOnly" in issues or "missing Secure" in issues else ("low" if issues else "info")
        out.append(Finding("cookie_security", f"Cookie '{c['name']}' flags", status, sev, "high",
                           summary="; ".join(issues) if issues else "Cookie has expected flags",
                           evidence=c["raw"][:800],
                           remediation="Set HttpOnly, Secure (on https), SameSite=Lax/Strict for session/auth cookies."))
    return out
