from __future__ import annotations
from ..models import Finding
from ..http_client import BoundedClient

EXPECTED = ["content-security-policy","strict-transport-security","x-content-type-options","referrer-policy","x-frame-options"]

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    try:
        r = client.get(base_url)
    except Exception as e:
        return [Finding("security_headers","Security headers — request failed","not_run","info","low",str(e)[:500], remediation="Ensure target is reachable.")]
    findings=[]
    low = r.headers
    for h in EXPECTED:
        present = h in low
        status = "not_found" if not present else "confirmed"
        sev = "medium" if h in ("content-security-policy","strict-transport-security") and not present else ("low" if not present else "info")
        conf = "high" if not present else "high"
        summary = f"Header '{h}' is {'missing' if not present else 'present'}"
        findings.append(Finding("security_headers", f"Header: {h}", status, sev, conf, summary,
                                evidence=f"Response headers: {', '.join(sorted(low.keys()))[:800]}" if not present else f"{h}: {low.get(h,'')[:500]}",
                                remediation=f"Add '{h}' header via SecurityHeadersMiddleware or web server config."))
    # HSTS only over https makes sense
    return findings
