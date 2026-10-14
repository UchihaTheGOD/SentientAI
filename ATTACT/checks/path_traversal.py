from __future__ import annotations
import urllib.parse
from ..models import Finding
from ..http_client import BoundedClient

CANARY = "ATTACT-TRAVERSAL-CANARY"

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    payloads = [
        "..%2F..%2F" + CANARY,
        "..%2F" * 3 + CANARY,
        "..%2F..%2Fetc%2Fpasswd-ATTACT",
    ]
    findings=[]
    for pay in payloads[:2]:
        for param in ["file","path","page"]:
            u = base_url + ("&" if "?" in base_url else "?") + f"{param}=" + pay
            try:
                r = client.get(u)
            except Exception as e:
                findings.append(Finding("path_traversal", f"Traversal probe {pay[:40]}", "not_run","info","low",str(e)[:500])); continue
            # Never attempt to read OS secrets; we only check whether the app *rejects* traversal
            # A 400/404 that does not echo filesystem content is the expected safe behavior.
            blocked = r.status in (400,403,404) and CANARY not in r.body and "root:" not in r.body
            reflected_unsafe = CANARY in r.body or "root:" in r.body.lower()
            if reflected_unsafe:
                findings.append(Finding("path_traversal","Traversal canary reflected (needs manual verification)","potential","high","low",
                    summary="Traversal payload appeared reflected; application may not be rejecting unsafe paths.",
                    evidence=f"param {param} payload {pay[:200]} -> {r.status} reflected={reflected_unsafe}",
                    remediation="Normalize and validate file paths; reject any containing '..' or absolute segments; use allowlists."))
            elif blocked:
                findings.append(Finding("path_traversal","Traversal payload appears rejected","not_found","info","medium", summary="Application returned 4xx and did not reflect traversal canary."))
            else:
                findings.append(Finding("path_traversal","No traversal reflection observed","not_found","info","medium", summary=f"Status {r.status} without canary reflection."))
            break  # one param per payload is enough
    return findings
