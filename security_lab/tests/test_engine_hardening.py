"""Gated raw requests: cap, stop, deadline, allowlist, TRACE probe."""

from types import SimpleNamespace

import pytest

from ..scanner.engine import ScanConfig, ScanContext, ScanRefused


class _Resp:
    def __init__(self, status=200):
        self.status_code = status
        self.headers = {}


class _Session:
    def __init__(self):
        self.calls = []

    def request(self, method, url, timeout=None, allow_redirects=False):
        self.calls.append((method, url))
        return _Resp(200)

    def get(self, url, timeout=None, allow_redirects=False):
        self.calls.append(("GET", url))
        return _Resp(200)


def _ctx(**overrides):
    cfg = dict(target="http://127.0.0.1:9/", authorized=True,
               allowlist=["127.0.0.1"], local_lab_enabled=True,
               rate_limit_seconds=0, timeout_seconds=5)
    cfg.update(overrides)
    ctx = ScanContext(ScanConfig(**cfg))
    ctx.session = _Session()
    return ctx


def test_request_raw_counts_toward_cap():
    ctx = _ctx(max_requests=1)
    ctx.request_raw("TRACE", "http://127.0.0.1:9/")
    assert ctx.request_count == 1
    assert len(ctx.session.calls) == 1
    with pytest.raises(ScanRefused, match="cap"):
        ctx.request_raw("TRACE", "http://127.0.0.1:9/")
    assert len(ctx.session.calls) == 1


def test_request_raw_refuses_when_stopped():
    ctx = _ctx()
    ctx.stop()
    with pytest.raises(ScanRefused, match="stopped"):
        ctx.request_raw("TRACE", "http://127.0.0.1:9/")
    assert ctx.session.calls == []


def test_request_raw_refuses_past_deadline():
    ctx = _ctx(deadline_seconds=-1)
    with pytest.raises(ScanRefused, match="deadline"):
        ctx.request_raw("TRACE", "http://127.0.0.1:9/")
    assert ctx.session.calls == []


def test_request_raw_refuses_non_allowlisted_host():
    ctx = _ctx(target="http://example.com/", allowlist=["other.example"])
    with pytest.raises(ScanRefused, match="allowlist"):
        ctx.request_raw("TRACE", "http://example.com/")
    assert ctx.session.calls == []


def test_request_raw_sends_the_given_method():
    ctx = _ctx()
    resp = ctx.request_raw("TRACE", "http://127.0.0.1:9/")
    assert resp.status_code == 200
    assert ctx.session.calls == [("TRACE", "http://127.0.0.1:9/")]
