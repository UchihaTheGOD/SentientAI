from __future__ import annotations
import re
from ..models import Finding
from ..http_client import BoundedClient

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    try:
        r = client.get(base_url)
    except Exception as e:
        return [Finding("csrf","CSRF check — GET failed","not_run","info","low",str(e)[:500])]
    has_token = "csrf" in r.body.lower()
    has_cookie = any(k.lower()=="set-cookie" and "csrf" in v.lower() for k,v in r.raw_headers)
    # Probe: POST without token should be rejected (no state change — we post to a non-existent endpoint)
    try:
        probe = client.request(base_url + "/api/sentinel/analyze", method="POST", data=b'{"log_text":"probe"}',
                               headers={"Content-Type":"application/json"}, follow_redirects=False)
        rejected = probe.status in (400,401,403,422)
    except Exception:
        rejected=None
    if has_token and has_cookie and rejected:
        return [Finding("csrf","CSRF protections appear present","not_found","info","medium",
            summary="CSRF token found in page/cookie and POST without token was rejected.",
            evidence=f"token_in_body={has_token} csrf_cookie={has_cookie} probe_rejected={rejected}")]
    if not has_token or not has_cookie:
        return [Finding("csrf","CSRF token/cookie not observed on GET / (needs manual verification)","potential","medium","low",
            summary="No CSRF token detected in landing page or Set-Cookie — verify forms include csrf_token and middleware is active.",
            evidence=f"has_token={has_token} has_cookie={has_cookie}",
            remediation="Use CSRFMiddleware with double-submit or synchronizer tokens on all state-changing endpoints.")]
    return [Finding("csrf","CSRF token present but rejection probe inconclusive","potential","low","low",
        summary="CSRF artefacts found but POST-without-token was not clearly rejected — verify manually.",
        evidence=f"probe status {probe.status if 'probe' in locals() else '?'}")]
