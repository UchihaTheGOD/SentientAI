"""Scanner safety contract: refusal paths, caps, stop, redirects."""

import pytest
import requests

from ..lab_server import start_lab_server, stop_lab_server
from ..scanner.engine import ScanConfig, ScanRefused, Scanner


def _cfg(**overrides):
    base = dict(target="http://127.0.0.1:1/", authorized=True,
                allowlist=["127.0.0.1"], local_lab_enabled=True,
                rate_limit_seconds=0.01, timeout_seconds=5)
    base.update(overrides)
    return ScanConfig(**base)


def test_unauthorized_scan_refused_before_any_request():
    with pytest.raises(ScanRefused):
        Scanner(_cfg(authorized=False))
    # The constructor itself refuses; no Scanner object escapes.
    with pytest.raises(ScanRefused):
        Scanner(ScanConfig(target="http://127.0.0.1:1/", authorized=False,
                           allowlist=["127.0.0.1"],
                           local_lab_enabled=True)).run()


def test_non_allowlisted_host_refused():
    result = Scanner(_cfg(target="http://example.com/",
                          allowlist=["other.example"])).run()
    assert result.requests_made == 0
    assert result.errors


def test_private_and_metadata_addresses_refused():
    for target in ("http://169.254.169.254/latest/meta-data/",
                   "http://10.0.0.5/admin", "http://192.168.1.1/",
                   "http://localhost:8000/"):
        result = Scanner(_cfg(target=target,
                              allowlist=["169.254.169.254", "10.0.0.5",
                                         "192.168.1.1", "localhost"],
                              local_lab_enabled=False)).run()
        assert result.requests_made == 0, target
        assert result.errors, target


def test_localhost_allowed_only_in_local_lab_mode():
    server, _thread, url = start_lab_server()
    try:
        result = Scanner(_cfg(target=url, local_lab_enabled=True)).run()
        assert result.requests_made > 0
        assert result.findings
    finally:
        stop_lab_server(server)


def test_request_cap_is_enforced_and_reported():
    server, _thread, url = start_lab_server()
    try:
        result = Scanner(_cfg(target=url, max_requests=2)).run()
        assert result.requests_made <= 2
        assert any("cap" in e for e in result.errors)
    finally:
        stop_lab_server(server)


def test_stop_before_start_is_honoured():
    server, _thread, url = start_lab_server()
    try:
        scanner = Scanner(_cfg(target=url))
        scanner.ctx.stop()
        result = scanner.run()
        assert result.stopped is True
    finally:
        stop_lab_server(server)


def test_credentials_in_url_refused():
    result = Scanner(_cfg(
        target="http://user:pass@127.0.0.1:9/")).run()
    assert result.requests_made == 0
    assert result.errors
