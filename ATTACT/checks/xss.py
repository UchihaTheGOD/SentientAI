from __future__ import annotations
import urllib.parse
from ..models import Finding
from ..http_client import BoundedClient

CANARY = "ATTACT-XSS-CANARY-9f3a1b"

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    # Test reflected param on root and /search if present — harmless canary, never executes
    candidates = [base_url]
    # add search endpoint if discoverable
    for suffix in ["/search?q=", "/?q=", "/?s="]:
        candidates.append(urllib.parse.urljoin(base_url, suffix + urllib.parse.quote(CANARY)))
    # also probe as query on base
    url = base_url + ("&" if "?" in base_url else "?") + "q=" + urllib.parse.quote(CANARY)
    urls = list(dict.fromkeys(candidates + [url]))[:4]
    # cap requests
    findings=[]
    for u in urls[:3]:
        try:
            r = client.get(u)
        except Exception as e:
            findings.append(Finding("xss", f"XSS probe {u[:80]}", "not_run","info","low", str(e)[:500])); continue
        reflected = CANARY in r.body
        encoded = "&lt;" in r.body or "&#" in r.body
        # Never label confirmed from a single reflection — needs encoding check + manual
        if reflected and not encoded and "text/html" in r.headers.get("content-type",""):
            findings.append(Finding("xss", "Reflected canary without encoding (needs manual verification)", "potential","medium","low",
                summary="Canary string reflected verbatim in HTML response — may indicate missing output encoding.",
                evidence=f"URL {u[:300]} reflected canary={reflected} encoded={encoded} ct={r.headers.get('content-type','')[:80]}",
                remediation="Ensure all reflected input is HTML-escaped (e.g. via sanitize.py/render_content) and enforce CSP."))
        elif reflected:
            findings.append(Finding("xss", "Canary reflected but appears encoded or non-HTML", "not_found","info","medium",
                summary="Canary reflected but HTML encoding detected or non-HTML content-type.", evidence=f"ct={r.headers.get('content-type','')[:80]}"))
        else:
            findings.append(Finding("xss", "No reflection observed", "not_found","info","high", summary="Canary not reflected in response."))
    return findings
