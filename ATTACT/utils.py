"""Utilities — header helpers, CSRF/cookie parsing, no secrets in output."""
from __future__ import annotations
import re, html, urllib.parse
from typing import Optional

def parse_set_cookie_headers(raw_headers: list[tuple[str,str]]) -> list[dict[str,str]]:
    out=[]
    for k,v in raw_headers:
        if k.lower()=="set-cookie":
            parts=[p.strip() for p in v.split(";")]
            name_val=parts[0] if parts else ""
            name,_sep,_val=name_val.partition("=")
            attrs={p.lower() for p in parts[1:]}
            # keep raw for display but keys lower for check
            out.append({"raw": v, "name": name, "attrs_lower": ";".join(attrs), "has_secure": "secure" in attrs,
                        "has_httponly": "httponly" in attrs, "has_samesite": "samesite" in attrs})
    return out

def extract_canary_reflection(body: str, canary: str) -> bool:
    return canary in body

def has_stack_trace(body: str) -> bool:
    patterns=[r"Traceback \(most recent", r"File \".*\.py\", line \d+", r"Exception", r"at .*\(.*:\d+\)"]
    return any(re.search(p, body) for p in patterns)

def origin_of(url: str) -> str:
    p=urllib.parse.urlparse(url)
    port = f":{p.port}" if p.port and p.port not in (80,443) else ""
    return f"{p.scheme}://{p.hostname}{port}"

def redact_secrets(text: str) -> str:
    # best-effort redaction before storing evidence
    text=re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
    return text[:4000]
