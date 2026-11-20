"""Tests for security_lab/tunnel.py (no network, no GUI).

Covers provider detection, command building, and the safety rules:
no stored tokens, only the manager's own process is stopped.
Starting a real tunnel needs a provider binary and is a manual check.
"""

from security_lab import tunnel as tun


def test_detect_providers_returns_all_four():
    statuses = tun.detect_providers()
    names = [s.name for s in statuses]
    assert names == ["cloudflared", "ngrok", "pinggy", "zrok"]
    for st in statuses:
        assert isinstance(st.installed, bool)


def test_build_cloudflared_temporary():
    cmd = tun.build_command("cloudflared", "temporary",
                            "http://127.0.0.1:8000")
    assert cmd == ["cloudflared", "tunnel", "--url", "http://127.0.0.1:8000"]


def test_build_cloudflared_persistent_needs_name():
    import pytest
    with pytest.raises(ValueError, match="tunnel name"):
        tun.build_command("cloudflared", "persistent",
                          "http://127.0.0.1:8000")


def test_build_cloudflared_persistent_with_name():
    cmd = tun.build_command("cloudflared", "persistent",
                            "http://127.0.0.1:8000", "my-tunnel")
    assert cmd == ["cloudflared", "tunnel", "run", "my-tunnel"]


def test_build_ngrok_temporary():
    cmd = tun.build_command("ngrok", "temporary", "http://127.0.0.1:8000")
    assert cmd == ["ngrok", "http", "8000"]


def test_build_pinggy_temporary_free_no_token():
    cmd = tun.build_command("pinggy", "temporary", "http://127.0.0.1:8000")
    assert cmd == ["ssh", "-p", "443", "-o", "StrictHostKeyChecking=no",
                   "-o", "ServerAliveInterval=30",
                   "-R0:localhost:8000", "free@a.pinggy.io"]


def test_build_pinggy_persistent_needs_token():
    import pytest
    with pytest.raises(ValueError, match="token"):
        tun.build_command("pinggy", "persistent", "http://127.0.0.1:8000")


def test_build_pinggy_persistent_with_token():
    cmd = tun.build_command("pinggy", "persistent", "http://127.0.0.1:8000",
                            token="tok123")
    assert cmd[-1] == "tok123@a.pinggy.io"
    assert cmd[0] == "ssh"


def test_build_zrok_temporary():
    cmd = tun.build_command("zrok", "temporary", "http://127.0.0.1:8000")
    assert cmd == ["zrok", "share", "public", "8000"]


def test_build_zrok_persistent_needs_share_token():
    import pytest
    with pytest.raises(ValueError, match="reserved share token"):
        tun.build_command("zrok", "persistent", "http://127.0.0.1:8000")


def test_build_zrok_persistent_with_share_token():
    cmd = tun.build_command("zrok", "persistent", "http://127.0.0.1:8000",
                            "abc123xyz")
    assert cmd == ["zrok", "share", "reserved", "abc123xyz"]


def test_build_unknown_provider_rejected():
    import pytest
    with pytest.raises(ValueError, match="unsupported"):
        tun.build_command("localtunnel", "temporary", "http://127.0.0.1:8000")


def test_no_token_in_default_commands():
    # The default (no-token) command for every provider carries no secret.
    # ("StrictHostKeyChecking" is an ssh option name, not a credential.)
    for provider in ("cloudflared", "ngrok", "pinggy", "zrok"):
        cmd = tun.build_command(provider, "temporary", "http://127.0.0.1:8000")
        joined = " ".join(cmd).lower()
        assert "token" not in joined
        assert "secret" not in joined
        assert "authtoken" not in joined
        assert "api_key" not in joined
        assert "api-key" not in joined


def test_start_tunnel_fails_clearly_when_binary_missing(monkeypatch):
    import pytest
    monkeypatch.setattr(tun.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not installed"):
        tun.start_tunnel("cloudflared", "temporary", "http://127.0.0.1:8000")


def test_url_patterns_match_provider_urls():
    cf = tun._URL_PATTERNS["cloudflared"]
    assert cf.search("https://abc-def.trycloudflare.com")
    ng = tun._URL_PATTERNS["ngrok"]
    assert ng.search("https://abc-def.ngrok-free.app")
    assert ng.search("https://abc-def.ngrok.io")
    pg = tun._URL_PATTERNS["pinggy"]
    assert pg.search("https://abc-def.a.pinggy.io")
    assert pg.search("Visit https://xyz123.a.pinggy.io for your site")
    zk = tun._URL_PATTERNS["zrok"]
    assert zk.search("https://abc-def.share.zrok.io")
    assert zk.search("https://abc123.zrok.io")
    assert not cf.search("https://example.com")
    assert not pg.search("https://abc-def.ngrok.io")
