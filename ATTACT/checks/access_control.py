from __future__ import annotations
import urllib.parse, http.cookiejar
from ..models import Finding
from ..http_client import BoundedClient

def _login(client_kwargs: dict, base_url: str, username: str, password: str) -> tuple[BoundedClient, int]:
    jar=http.cookiejar.CookieJar()
    c=BoundedClient(cookie_jar=jar, **client_kwargs)
    # get csrf
    c.get(base_url)
    csrf=""
    for ck in jar:
        if ck.name=="csrf_token": csrf=ck.value
    login_url=urllib.parse.urljoin(base_url, "/login")
    data=urllib.parse.urlencode({"username":username,"password":password,"csrf_token": csrf}).encode()
    r=c.request(login_url, method="POST", data=data, headers={"Content-Type":"application/x-www-form-urlencoded","X-CSRF-Token": csrf})
    return c, r.status

def run(client: BoundedClient, base_url: str, *, user_a: tuple[str,str]=("",""), user_b: tuple[str,str]=("",""), resource_paths: list[str]|None=None) -> list[Finding]:
    if not user_a[0] or not user_b[0]:
        return [Finding("access_control","Access-control comparison skipped — two test accounts required","not_run","info","low",
            summary="Supply --access-user-a/--access-pass-a and --access-user-b/--access-pass-b (accounts with different roles) to run this check.")]
    resource_paths = resource_paths or ["/admin", "/admin/users", "/api/sentinel/incidents"]
    kwargs=dict(timeout=client.timeout, max_requests=30, allowlist=client.allowlist)
    try:
        ca, sa = _login(kwargs, base_url, user_a[0], user_a[1])
        cb, sb = _login(kwargs, base_url, user_b[0], user_b[1])
    except Exception as e:
        return [Finding("access_control","Access-control login failed","not_run","info","low",str(e)[:700])]
    findings=[]
    for path in resource_paths[:3]:
        url=urllib.parse.urljoin(base_url, path)
        try:
            ra=ca.get(url); rb=cb.get(url)
        except Exception as e:
            findings.append(Finding("access_control", f"IDOR check {path} — request failed","not_run","info","low",str(e)[:500])); continue
        # Compare: if both get 200 with same body length it suggests missing differentiation — but never flag confirmed
        if ra.status==200 and rb.status==200 and abs(len(ra.body)-len(rb.body))<50:
            findings.append(Finding("access_control", f"Resource {path} returned 200 for both accounts (needs manual verification)","potential","medium","low",
                summary="Both test accounts received similar 200 responses — verify authorization is enforced for role-specific resources.",
                evidence=f"a:{ra.status} b:{rb.status} len {len(ra.body)}/{len(rb.body)}", remediation="Enforce server-side authorization per resource/role; test with accounts of different privilege."))
        elif ra.status != rb.status:
            findings.append(Finding("access_control", f"Resource {path} differentiated by role","not_found","info","medium", summary=f"Accounts received different status ({ra.status} vs {rb.status}) — suggests access control is applied."))
        else:
            findings.append(Finding("access_control", f"Resource {path} — no cross-account issue observed","not_found","info","medium", summary=f"status a={ra.status} b={rb.status}"))
    return findings
