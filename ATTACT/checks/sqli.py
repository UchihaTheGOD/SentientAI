from __future__ import annotations
import urllib.parse, re
from ..models import Finding
from ..http_client import BoundedClient

# Safe non-destructive probe — single quote + harmless suffix that cannot dump data
PROBE = "'\" ATTACT"
SQL_ERROR_PATTERNS = [r"SQL", r"sqlite", r"syntax error", r"unterminated", r"psycopg", r"ORA-\d+", r"MySQL", r"MariaDB"]

def run(client: BoundedClient, base_url: str) -> list[Finding]:
    urls=[]
    for param in ["q","s","id","search"]:
        urls.append(base_url + ("&" if "?" in base_url else "?") + f"{param}=" + urllib.parse.quote(PROBE))
        urls.append(urllib.parse.urljoin(base_url, f"/search?{param}=" + urllib.parse.quote(PROBE)))
        if len(urls)>=3: break
    findings=[]
    for u in urls[:2]:
        try:
            base_r = client.get(base_url)
            probe_r = client.get(u)
        except Exception as e:
            findings.append(Finding("sqli","SQLi probe — request failed","not_run","info","low",str(e)[:500])); continue
        body = probe_r.body
        hit = any(re.search(p, body, re.I) for p in SQL_ERROR_PATTERNS)
        status_flip = probe_r.status >=500 and base_r.status <500
        if hit or status_flip:
            findings.append(Finding("sqli","Suspicious SQL-like error or 5xx on probe (needs manual verification)","potential","medium","low",
                summary="Probe caused an error pattern that could indicate unhandled input; manual review required.",
                evidence=f"probe {u[:300]} -> {probe_r.status} hit={hit} flip={status_flip} body_snippet={body[:600]}",
                remediation="Use parameterized queries / ORM; never interpolate input into SQL; add input validation."))
        else:
            findings.append(Finding("sqli","No SQL error indicators on safe probe","not_found","info","medium","Safe probe did not trigger SQL-like errors.", evidence=f"status {probe_r.status}"))
    return findings
