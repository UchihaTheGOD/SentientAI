"""SSRF redirect-host equality, gated TRACE check, TLS socket cleanup."""

import ssl
from types import SimpleNamespace

from ..scanner.checks import _tls_info, check_misconfig, check_ssrf
from ..scanner.engine import ScanConfig, ScanRefused


def _ssrf_ctx(location):
    cfg = ScanConfig(target="http://127.0.0.1:9/page?next=x", authorized=True,
                     allowlist=["127.0.0.1"], local_lab_enabled=True)
    resp = SimpleNamespace(is_redirect=True, headers={"Location": location})
    return SimpleNamespace(config=cfg, fetch_no_follow=lambda url: resp)


def _names(findings):
    return [f.name for f in findings]


def test_ssrf_open_redirect_requires_exact_host():
    # example.com.evil.com contains "example.com" as a substring but
    # is a different host: it must NOT be reported as an open redirect.
    findings = check_ssrf(_ssrf_ctx("https://example.com.evil.com/"))
    assert not any("Open redirect" in n for n in _names(findings))
    assert any("URL-valued parameter" in n for n in _names(findings))


def test_ssrf_open_redirect_exact_host_is_reported():
    findings = check_ssrf(_ssrf_ctx("https://example.com/login"))
    assert any("Open redirect via parameter: next" in n for n in _names(findings))


def test_ssrf_relative_redirect_is_not_external():
    findings = check_ssrf(_ssrf_ctx("/login"))
    assert not any("Open redirect" in n for n in _names(findings))


def _misconfig_ctx(trace_status):
    cfg = ScanConfig(target="http://127.0.0.1:9/", authorized=True,
                     allowlist=["127.0.0.1"], local_lab_enabled=True)
    calls = []

    def request_raw(method, url, timeout=None):
        calls.append((method, url))
        return SimpleNamespace(status_code=trace_status, headers={})

    def fetch_text(url):
        raise ScanRefused("refused")

    return SimpleNamespace(config=cfg, base_body="", base_response=None,
                           request_raw=request_raw, fetch_text=fetch_text), calls


def test_trace_check_uses_gated_request_and_reports_200():
    ctx, calls = _misconfig_ctx(200)
    findings = check_misconfig(ctx)
    assert calls and calls[0][0] == "TRACE"
    assert any("HTTP TRACE method enabled" in n for n in _names(findings))


def test_trace_check_silent_when_not_enabled():
    ctx, calls = _misconfig_ctx(501)
    findings = check_misconfig(ctx)
    assert calls and calls[0][0] == "TRACE"
    assert not any("TRACE" in n for n in _names(findings))


def test_tls_info_closes_socket_on_handshake_failure(monkeypatch):
    closed = []

    class FakeConn:
        def close(self):
            closed.append(True)

    class FakeCtx:
        def wrap_socket(self, conn, server_hostname=None):
            raise ssl.SSLError("self-signed")

    monkeypatch.setattr("socket.create_connection",
                        lambda *args, **kwargs: FakeConn())
    monkeypatch.setattr("ssl.create_default_context", lambda: FakeCtx())
    ctx = SimpleNamespace(
        config=ScanConfig(target="https://127.0.0.1:443/", authorized=True,
                          allowlist=["127.0.0.1"]))
    result = _tls_info(ctx)
    assert "error" in result
    assert closed == [True]
