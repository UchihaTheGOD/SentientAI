"""Rate-limit keys must not rotate on a spoofed X-Forwarded-For."""

from types import SimpleNamespace

import app.services.ratelimit as rl


def _req(host, xff=None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    return SimpleNamespace(headers=headers, cookies={},
                           client=SimpleNamespace(host=host))


def test_spoofed_xff_ignored_without_trusted_proxy(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
    key = rl._client_key(_req("1.2.3.4", "9.9.9.9"), "cyberllm_analyze")
    assert ":1.2.3.4:" in key
    assert "9.9.9.9" not in key


def test_trusted_proxy_may_use_xff(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "1.2.3.4")
    key = rl._client_key(_req("1.2.3.4", "9.9.9.9"), "cyberllm_analyze")
    assert ":9.9.9.9:" in key
