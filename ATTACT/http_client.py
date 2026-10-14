"""ATTACT HTTP client — stdlib only, bounded, scope-aware redirects."""
from __future__ import annotations
import http.cookiejar, urllib.request, urllib.parse, urllib.error, ssl, threading
from dataclasses import dataclass
from typing import Optional
from .scope import validate_redirect_url

class StopRequested(RuntimeError):
    pass

@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str,str]
    body: str
    raw_headers: list[tuple[str,str]]
    final_url: str

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None

class BoundedClient:
    def __init__(self, *, timeout=6.0, max_requests=120, max_redirects=3, user_agent="ATTACT/0.1 authorized-assessment", cookie_jar=None, allowlist=None):
        self.timeout=timeout; self.max_requests=max_requests; self.max_redirects=max_redirects
        self.user_agent=user_agent; self.cookie_jar=cookie_jar or http.cookiejar.CookieJar()
        self.allowlist=allowlist or set(); self._count=0; self._stop=threading.Event(); self._lock=threading.Lock()
    @property
    def request_count(self):
        with self._lock: return self._count
    def stop(self): self._stop.set()
    def _inc(self):
        with self._lock:
            if self._stop.is_set(): raise StopRequested("Assessment stopped")
            if self._count>=self.max_requests: raise StopRequested(f"Request limit {self.max_requests}")
            self._count+=1
    def _opener(self):
        ctx=ssl.create_default_context()
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPHandler(), urllib.request.HTTPCookieProcessor(self.cookie_jar), NoRedirect())
    def request(self, url, *, method="GET", headers=None, data=None, follow_redirects=True):
        self._inc()
        if self._stop.is_set(): raise StopRequested("Assessment stopped")
        opener=self._opener()
        hdrs={"User-Agent": self.user_agent, "Accept": "*/*"}
        if headers: hdrs.update(headers)
        cur_url, cur_method, cur_data, redirs = url, method, data, 0
        while True:
            req=urllib.request.Request(cur_url, data=cur_data, headers=hdrs, method=cur_method)
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    status=getattr(resp,"status", 200)
                    if hasattr(resp,"code"):
                        try: status=int(resp.code)
                        except: pass
                    raw=list(resp.headers.items()) if hasattr(resp.headers,"items") else []
                    low={k.lower():v for k,v in raw}
                    try: body=resp.read().decode("utf-8", errors="replace")
                    except: body=""
                    final=resp.geturl() if hasattr(resp,"geturl") else cur_url
                    loc=low.get("location")
                    if follow_redirects and status in (301,302,303,307,308) and loc and redirs < self.max_redirects:
                        nxt=urllib.parse.urljoin(cur_url, loc)
                        validate_redirect_url(nxt, self.allowlist)
                        redirs+=1; cur_url=nxt
                        if status in (301,302,303): cur_method="GET"; cur_data=None; hdrs.pop("Content-Type",None)
                        continue
                    return HttpResponse(url=url, status=status, headers=low, body=body, raw_headers=raw, final_url=final)
            except urllib.error.HTTPError as e:
                raw=list(e.headers.items()) if e.headers else []
                low={k.lower():v for k,v in raw}
                try: body=e.read().decode("utf-8", errors="replace")
                except: body=""
                code=e.code; loc=low.get("location","")
                if follow_redirects and code in (301,302,303,307,308) and loc and redirs < self.max_redirects:
                    nxt=urllib.parse.urljoin(cur_url, loc)
                    validate_redirect_url(nxt, self.allowlist)
                    redirs+=1; cur_url=nxt
                    if code in (301,302,303): cur_method="GET"; cur_data=None
                    continue
                return HttpResponse(url=url, status=code, headers=low, body=body, raw_headers=raw, final_url=cur_url)
            except urllib.error.URLError as e:
                raise RuntimeError(f"Request failed for {cur_url}: {getattr(e,'reason',e)}") from e
    def get(self, url, **kw): return self.request(url, method="GET", **kw)
    def post(self, url, *, data=None, headers=None, **kw): return self.request(url, method="POST", headers=headers, data=data, **kw)
