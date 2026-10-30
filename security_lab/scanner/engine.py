"""Scanner engine: safety controls first, checks second.

Safety rules (all enforced here, so no check can bypass them):
- ``authorized`` must be True and the target host must be allowlisted.
- Every host is resolved and every resolved IP classified before any
  request; private/loopback (unless local-lab)/link-local/reserved/
  multicast/unspecified addresses are refused.
- Redirects are followed manually (max 5), each target re-validated
  and re-resolved; a redirect escaping the authorized host is refused.
- Only GET requests, with timeouts, a request cap, a min interval
  between requests, an overall deadline, and a stop event.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import requests

from .findings import SEVERITY_ORDER, Finding, redact, redact_url, summarize

USER_AGENT = "CyberLLMv1-Security-Lab/1.0 (authorized assessment; GET only)"

SCAN_LIMITATIONS = [
    "Detection only: findings are observations and suspected indicators, "
    "not confirmed exploitations. A missing header, an error string, or a "
    "version banner alone never confirms a vulnerability.",
    "Only GET requests were sent, plus one read-only TRACE echo probe "
    "(misconfigurations check). No login attempts, data extraction, "
    "brute force, denial-of-service, or destructive tests were performed.",
    "DNS was resolved once per host per scan and cached; a hostile DNS "
    "change between the check and the connect (rebinding) is not fully "
    "eliminated by this tool.",
    "The scanner connects directly (no proxy), so targets behind a proxy "
    "may behave differently than through a browser.",
]


class ScanRefused(RuntimeError):
    """Raised when a target or redirect fails a safety control."""


@dataclass
class ScanConfig:
    target: str
    allowlist: list[str] = field(default_factory=list)
    local_lab_enabled: bool = False
    authorized: bool = False
    categories: set[str] | None = None  # None = all categories
    rate_limit_seconds: float = 0.25
    timeout_seconds: float = 10.0
    max_requests: int = 200
    max_workers: int = 2
    deadline_seconds: float = 300.0


def _host_allowed(host: str, allowlist: list[str]) -> bool:
    host = host.lower()
    for entry in allowlist:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry.startswith("."):
            if host.endswith(entry) or host == entry[1:]:
                return True
        elif host == entry:
            return True
    return False


def _is_loopback_host(host: str) -> bool:
    if host in ("localhost", "ip6-localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return host.startswith("127.")


def classify_ips(ips: list[str]) -> tuple[bool, str]:
    """Return (allowed_for_general_use, reason). Loopback handled by caller."""
    problems = []
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            problems.append(f"unparseable address {raw}")
            continue
        if ip.is_loopback:
            problems.append(f"{raw} is loopback")
        elif ip.is_link_local:
            problems.append(f"{raw} is link-local (cloud metadata range)")
        elif ip.is_private:
            problems.append(f"{raw} is a private-network address")
        elif ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            problems.append(f"{raw} is reserved/multicast/unspecified")
    if problems:
        return False, "; ".join(problems)
    return True, ""


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    summary: dict[str, int]
    requests_made: int
    stopped: bool
    errors: list[str]
    timeline: list[dict[str, str]]
    limitations: list[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "requests_made": self.requests_made,
            "stopped": self.stopped,
            "errors": self.errors,
            "timeline": self.timeline,
            "limitations": self.limitations,
            "findings": [f.to_dict() for f in self.findings],
        }


class ScanContext:
    """Per-scan state handed to checks. All fetches go through here."""

    def __init__(self, config: ScanConfig,
                 progress: Callable[[int, int, str], None] | None = None):
        self.config = config
        self.progress = progress or (lambda *a: None)
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.stop_event = threading.Event()
        self.request_count = 0
        self._rate_lock = threading.Lock()
        self._count_lock = threading.Lock()
        self._next_allowed = 0.0
        self._deadline = time.time() + config.deadline_seconds
        self._resolved: dict[str, tuple[list[str], bool, str]] = {}
        self.timeline: list[dict[str, str]] = []
        self.errors: list[str] = []
        self.base_response: requests.Response | None = None
        self.base_body: str = ""

    def log(self, event: str, detail: str = "") -> None:
        self.timeline.append({
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event, "detail": redact(detail, 500),
        })

    def stop(self) -> None:
        self.stop_event.set()

    def _take_request_slot(self) -> None:
        """Atomically enforce the request cap (probe pools share fetch)."""
        with self._count_lock:
            if self.request_count >= self.config.max_requests:
                raise ScanRefused("scan request cap reached")
            self.request_count += 1

    def fetch_no_follow(self, url: str, timeout: float | None = None) -> requests.Response:
        """Single GET without redirect handling (for open-redirect probes).

        The request itself still passes the allowlist + DNS gates; only
        the Location header is inspected, never followed.
        """
        if self.stop_event.is_set():
            raise ScanRefused("scan stopped by user")
        if time.time() > self._deadline:
            raise ScanRefused("scan deadline reached")
        self._take_request_slot()
        url = self.check_target(url)
        with self._rate_lock:
            wait = self._next_allowed - time.time()
            if wait > 0:
                time.sleep(wait)
            self._next_allowed = time.time() + self.config.rate_limit_seconds
        return self.session.get(url, timeout=timeout or self.config.timeout_seconds,
                                allow_redirects=False)

    def request_raw(self, method: str, url: str,
                    timeout: float | None = None) -> requests.Response:
        """One non-GET probe through every safety gate.

        The scanner is GET-only except for the single documented
        read-only TRACE echo probe. That probe still passes the
        allowlist + DNS gates, the request cap, the deadline, the stop
        event, and the rate limiter, and redirects are never followed.
        Checks must use this (or fetch/fetch_no_follow), never the
        session directly, so no request can bypass the gates.
        """
        if self.stop_event.is_set():
            raise ScanRefused("scan stopped by user")
        if time.time() > self._deadline:
            raise ScanRefused("scan deadline reached")
        self._take_request_slot()
        url = self.check_target(url)
        with self._rate_lock:
            wait = self._next_allowed - time.time()
            if wait > 0:
                time.sleep(wait)
            self._next_allowed = time.time() + self.config.rate_limit_seconds
        return self.session.request(
            method, url, timeout=timeout or self.config.timeout_seconds,
            allow_redirects=False)

    # -- safety ---------------------------------------------------------
    def validate_url(self, url: str) -> str:
        """Validate a URL against scheme/allowlist rules. Returns normalized."""
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            raise ScanRefused(f"only http/https URLs are allowed: {parsed.scheme or '(none)'}")
        if parsed.username or parsed.password:
            raise ScanRefused("credentials in URLs are not allowed")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ScanRefused("URL has no host")
        if len(url) > 2000:
            raise ScanRefused("URL too long")
        if _host_allowed(host, self.config.allowlist):
            return urlunparse(parsed)
        if self.config.local_lab_enabled and _is_loopback_host(host):
            return urlunparse(parsed)
        raise ScanRefused(
            f"host '{host}' is not on the allowlist"
            + (" and local-lab mode is off" if not self.config.local_lab_enabled else ""))

    def resolve_host(self, host: str) -> tuple[list[str], bool, str]:
        """Resolve + classify a host (cached per scan)."""
        host = host.lower()
        if host in self._resolved:
            return self._resolved[host]
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            result: tuple[list[str], bool, str] = ([], False, f"DNS failed: {exc}")
            self._resolved[host] = result
            return result
        ips = sorted({info[4][0] for info in infos})
        if self.config.local_lab_enabled and all(
                _is_loopback_host(ip) or ip == host for ip in ips) \
                and _is_loopback_host(host):
            result = (ips, True, "")
        else:
            ok, reason = classify_ips(ips)
            result = (ips, ok, reason)
        self._resolved[host] = result
        return result

    def check_target(self, url: str) -> str:
        """Full safety gate for one URL: allowlist + DNS classification."""
        url = self.validate_url(url)
        host = urlparse(url).hostname or ""
        ips, ok, reason = self.resolve_host(host)
        if not ok:
            raise ScanRefused(
                f"target host '{host}' resolves to blocked address(es) "
                f"{', '.join(ips) or '(none)'}: {reason}")
        return url

    # -- fetching -------------------------------------------------------
    def fetch(self, url: str, timeout: float | None = None) -> requests.Response:
        """GET one URL through every safety control (redirects manual)."""
        if self.stop_event.is_set():
            raise ScanRefused("scan stopped by user")
        if time.time() > self._deadline:
            raise ScanRefused("scan deadline reached")
        self._take_request_slot()
        url = self.check_target(url)
        with self._rate_lock:
            wait = self._next_allowed - time.time()
            if wait > 0:
                time.sleep(wait)
            self._next_allowed = time.time() + self.config.rate_limit_seconds
        resp = self.session.get(url, timeout=timeout or self.config.timeout_seconds,
                                allow_redirects=False)
        # Manual redirect handling: each hop re-enters the safety gate.
        hops = 0
        while resp.is_redirect and hops < 5:
            location = resp.headers.get("Location", "")
            if not location:
                break
            from urllib.parse import urljoin

            nxt = urljoin(url, location)
            if self.stop_event.is_set():
                raise ScanRefused("scan stopped by user")
            nxt_host = (urlparse(nxt).hostname or "").lower()
            base_host = (urlparse(self.config.target).hostname or "").lower()
            if nxt_host != base_host:
                raise ScanRefused(
                    f"redirect escapes the authorized host ({base_host} -> "
                    f"{nxt_host}); refusing to follow")
            nxt = self.check_target(nxt)
            with self._rate_lock:
                wait = self._next_allowed - time.time()
                if wait > 0:
                    time.sleep(wait)
                self._next_allowed = time.time() + self.config.rate_limit_seconds
            self._take_request_slot()
            url = nxt
            resp = self.session.get(url, timeout=timeout or self.config.timeout_seconds,
                                    allow_redirects=False)
            hops += 1
        if resp.is_redirect:
            raise ScanRefused("too many redirects")
        return resp

    def fetch_text(self, url: str, limit: int = 512 * 1024) -> tuple[requests.Response, str]:
        resp = self.fetch(url)
        body = resp.text[:limit] if resp.text else ""
        return resp, body


class Scanner:
    def __init__(self, config: ScanConfig,
                 progress: Callable[[int, int, str], None] | None = None):
        if not config.authorized:
            raise ScanRefused(
                "scan requires explicit authorization confirmation")
        self.config = config
        self.ctx = ScanContext(config, progress=progress)

    def run(self) -> ScanResult:
        """Run the scan; the HTTP session is always closed afterwards.

        Every scan previously created a requests Session that was never
        closed, so pooled connections lingered after each run. Scanner
        instances are created fresh per run everywhere, so closing
        here cannot break a subsequent run.
        """
        try:
            return self._run_impl()
        finally:
            try:
                self.ctx.session.close()
            except Exception:
                pass

    def _run_impl(self) -> ScanResult:
        from .checks import ALL_CHECKS

        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        ctx = self.ctx
        findings: list[Finding] = []
        ctx.log("scan started", f"target={redact_url(self.config.target)}")
        try:
            target = ctx.check_target(self.config.target)
            resp, body = ctx.fetch_text(target)
            ctx.base_response = resp
            ctx.base_body = body
            ctx.log("fetched target", f"HTTP {resp.status_code}")
            checks = [c for c in ALL_CHECKS
                      if self.config.categories is None
                      or c["id"] in self.config.categories]
            for idx, check in enumerate(checks):
                if ctx.stop_event.is_set():
                    break
                ctx.progress(idx, len(checks), f"Running: {check['name']}")
                try:
                    found = check["run"](ctx)
                    findings.extend(found)
                    ctx.log("check completed",
                            f"{check['name']}: {len(found)} finding(s)")
                except ScanRefused as exc:
                    ctx.errors.append(f"{check['name']}: {exc}")
                    ctx.log("check refused", f"{check['name']}: {exc}")
                except requests.RequestException as exc:
                    ctx.errors.append(f"{check['name']}: network error: {exc}")
                    ctx.log("check network error", check["name"])
                except Exception as exc:  # a check must never kill a scan
                    ctx.errors.append(f"{check['name']}: internal error: {exc}")
                    ctx.log("check error", check["name"])
        except ScanRefused as exc:
            ctx.errors.append(str(exc))
            ctx.log("scan refused", str(exc))
        except requests.RequestException as exc:
            ctx.errors.append(f"network error: {exc}")
            ctx.log("scan network error", str(exc))
        finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        ctx.progress(len(ALL_CHECKS), len(ALL_CHECKS), "Done")
        if ctx.request_count >= self.config.max_requests:
            ctx.errors.append(
                "scan request cap reached; some checks may not have run")
        findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.name))
        ctx.log("scan finished",
                f"{len(findings)} finding(s), {ctx.request_count} request(s)")
        return ScanResult(
            target=self.config.target,
            started_at=started, finished_at=finished,
            findings=findings, summary=summarize(findings),
            requests_made=ctx.request_count,
            stopped=ctx.stop_event.is_set(),
            errors=ctx.errors, timeline=ctx.timeline,
            limitations=list(SCAN_LIMITATIONS),
        )
