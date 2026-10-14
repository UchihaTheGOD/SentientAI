from __future__ import annotations
import time
from ..models import Finding
from ..http_client import BoundedClient

def run(client: BoundedClient, base_url: str, *, path: str="/login", count: int=6, delay_ms: int=200) -> list[Finding]:
    target = base_url.rstrip("/") + path
    statuses=[]
    for i in range(min(count, 10)):
        try:
            r = client.get(target)
            statuses.append(r.status)
            low={k.lower():v for k,v in r.raw_headers}
            # check rate-limit headers
            if any(k in low for k in ("x-ratelimit-limit","x-ratelimit-remaining","retry-after")):
                # handled below
                pass
        except Exception:
            statuses.append(-1)
        if delay_ms>0:
            time.sleep(delay_ms/1000)
        # respect global stop
        if i>=2 and statuses[-3:]==[429,429,429]:
            break
    got_429 = 429 in statuses
    has_headers = False
    # re-check last response headers
    try:
        r2 = client.get(target)
        has_headers = any(h.lower() in r2.headers for h in ["x-ratelimit-limit","retry-after"])
    except Exception:
        pass
    if got_429:
        return [Finding("rate_limit","Rate limiting appears enforced","not_found","info","medium",
            summary=f"Received 429 within {len(statuses)} probes — rate limiting is active.", evidence=f"statuses {statuses}")]
    if has_headers:
        return [Finding("rate_limit","Rate-limit headers present but 429 not triggered at low rate","not_found","info","medium",
            summary="Headers suggest rate limiting is configured; low-rate probe did not hit limit (expected).")]
    return [Finding("rate_limit","No rate limiting observed at low rate (needs manual verification)","potential","low","low",
        summary="Low-rate probe did not trigger 429 and no rate-limit headers seen — verify limits are configured for auth endpoints.",
        evidence=f"statuses {statuses}", remediation="Enable rate limiting on login/messaging endpoints (e.g. slowapi/ratelimit).")]
