from __future__ import annotations
import urllib.parse
from ..models import Finding
from ..http_client import BoundedClient

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    findings=[]
    # OPTIONS to see exposed methods
    try:
        r = client.request(base_url, method="OPTIONS")
        allow = r.headers.get("allow","") or r.headers.get("access-control-allow-methods","")
        if "TRACE" in allow.upper() or "CONNECT" in allow.upper():
            findings.append(Finding("input_http","Risky HTTP methods exposed","potential","medium","medium",
                summary=f"Allow header advertises {allow}", remediation="Disable TRACE/CONNECT; allow only GET/POST/PUT/DELETE as needed."))
        else:
            findings.append(Finding("input_http","Allowed methods", "not_found","info","medium", summary=f"OPTIONS Allow: {allow[:300] or '(none)'}"))
    except Exception as e:
        findings.append(Finding("input_http","OPTIONS probe failed","not_run","info","low",str(e)[:400]))
    # Malformed Content-Type / large-ish param (bounded)
    try:
        r2 = client.request(base_url, method="POST", data=b'not-json', headers={"Content-Type":"application/json"})
        # Expect 400/422 — not a finding itself
        findings.append(Finding("input_validation","Malformed JSON handling","not_found","info","medium",
            summary=f"POST malformed JSON -> {r2.status} (expected 400/422)", evidence=f"status {r2.status}"))
    except Exception as e:
        findings.append(Finding("input_validation","Malformed input probe failed","not_run","info","low",str(e)[:400]))
    # Overly long param (capped)
    long_val = "A"*2000
    try:
        u = base_url + ("&" if "?" in base_url else "?") + "q=" + urllib.parse.quote(long_val)
        r3 = client.get(u)
        if r3.status >=500:
            findings.append(Finding("input_validation","Long parameter caused 5xx (needs manual verification)","potential","low","low",
                summary="Long query value triggered server error — may indicate missing length validation.", evidence=f"status {r3.status}"))
        else:
            findings.append(Finding("input_validation","Long parameter handled without 5xx","not_found","info","medium", summary=f"status {r3.status}"))
    except Exception as e:
        findings.append(Finding("input_validation","Long param probe failed","not_run","info","low",str(e)[:400]))
    # rename check id for report grouping
    for f in findings:
        if f.check=="input_http": f.check="input_validation"
    return findings
