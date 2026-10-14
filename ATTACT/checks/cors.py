from __future__ import annotations
from ..models import Finding
from ..http_client import BoundedClient

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    origin = "https://evil.example"
    try:
        r = client.get(base_url, headers={"Origin": origin})
    except Exception as e:
        return [Finding("cors","CORS check failed","not_run","info","low",str(e)[:500])]
    acao = r.headers.get("access-control-allow-origin","")
    acac = r.headers.get("access-control-allow-credentials","")
    if acao=="*" and acac.lower()=="true":
        return [Finding("cors","CORS allows any origin with credentials","potential","high","high",
            summary="ACAO is '*' while Allow-Credentials is true — browsers will expose credentialed responses to any origin.",
            evidence=f"ACAO={acao} ACAC={acac}", remediation="Echo only allowlisted origins and never combine '*' with credentials.")]
    if acao==origin and acac.lower()=="true":
        return [Finding("cors","CORS reflects arbitrary origin with credentials","potential","high","high",
            summary="Server reflected the supplied Origin and allowed credentials — suggests wildcard reflection.",
            evidence=f"ACAO={acao} ACAC={acac}", remediation="Use an explicit allowlist for origins; do not reflect arbitrary Origin headers.")]
    if acao=="*":
        return [Finding("cors","CORS allows any origin (no credentials)","potential","low","medium",
            summary="ACAO is '*' without credentials — low risk but review if sensitive data is exposed.", evidence=f"ACAO={acao}")]
    if acao:
        return [Finding("cors","CORS policy present","not_found","info","medium", summary=f"ACAO={acao[:200]} ACAC={acac[:80]}")]
    return [Finding("cors","No CORS headers observed","not_found","info","medium", summary="No Access-Control-Allow-Origin header — default same-origin policy.")]
