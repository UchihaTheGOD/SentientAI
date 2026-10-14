"""Scope and authorization controls — loopback by default, allowlist otherwise."""
from __future__ import annotations
import ipaddress, socket, urllib.parse
from dataclasses import dataclass, field

class ScopeError(ValueError):
    pass

@dataclass
class TargetConfig:
    target_url: str
    allowlist: list[str] = field(default_factory=list)
    confirm_authorized: bool = False
    def normalized_allowlist(self) -> set[str]:
        return {h.strip().lower() for h in self.allowlist if h.strip()}

def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False

def _resolve_ips(host: str) -> list[str]:
    host = host.strip().strip("[]")
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS failed for '{host}': {exc}") from exc
    ips: list[str] = []
    seen: set[str] = set()
    for _,_,_,_, sa in infos:
        ip = sa[0]
        if ip not in seen:
            seen.add(ip); ips.append(ip)
    return ips

def validate_url(url: str, allowlist: set[str]) -> urllib.parse.ParseResult:
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http","https"):
        raise ScopeError(f"Only http/https allowed (got '{p.scheme}')")
    if not p.hostname:
        raise ScopeError(f"URL has no host: {url!r}")
    if p.username or p.password:
        raise ScopeError("URLs with embedded credentials are not allowed")
    host = p.hostname
    ips = _resolve_ips(host)
    if not ips:
        raise ScopeError(f"Host '{host}' resolved to no addresses")
    hl = host.lower().strip()
    if hl in allowlist or hl.strip("[]") in allowlist:
        for ip in ips:
            if ipaddress.ip_address(ip).is_unspecified:
                raise ScopeError(f"Host '{host}' resolves to unspecified {ip} — rejected")
        return p
    for ip in ips:
        if ip.lower() in allowlist:
            return p
    non_loop = [ip for ip in ips if not _is_loopback(ip)]
    if non_loop:
        raise ScopeError(f"Host '{host}' -> {non_loop} not loopback. Add to --allowlist if authorized or use 127.0.0.1/localhost.")
    for ip in ips:
        if ipaddress.ip_address(ip).is_unspecified:
            raise ScopeError(f"Host '{host}' -> unspecified {ip} — rejected")
    return p

def validate_target(c: TargetConfig) -> urllib.parse.ParseResult:
    if not c.target_url or not c.target_url.strip():
        raise ScopeError("No --target supplied. Use --target http://127.0.0.1:8000")
    if not c.confirm_authorized:
        raise ScopeError("Add --confirm-authorized to confirm you have permission to test the target.")
    return validate_url(c.target_url, c.normalized_allowlist())

def validate_redirect_url(url: str, wl: set[str]) -> urllib.parse.ParseResult:
    try:
        return validate_url(url, wl)
    except ScopeError as e:
        raise ScopeError(f"Redirect blocked: {e}") from e
