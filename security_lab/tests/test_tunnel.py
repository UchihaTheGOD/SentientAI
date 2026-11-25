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


def test_save_ngrok_authtoken_calls_config_add_authtoken(monkeypatch):
    calls = []

    class _Res:
        returncode = 0
        stdout = ("Authtoken saved to configuration file: "
                  "C:\\Users\\x\\AppData\\Local\\ngrok\\ngrok.yml\n")
        stderr = ""

    monkeypatch.setattr(tun.shutil, "which", lambda name: "/usr/bin/ngrok")
    monkeypatch.setattr(
        tun.subprocess, "run",
        lambda *a, **k: calls.append(a[0]) or _Res())
    out = tun.save_ngrok_authtoken("tok123")
    assert calls == [["ngrok", "config", "add-authtoken", "tok123"]]
    assert "Authtoken saved" in out


def test_save_ngrok_authtoken_rejects_empty_token():
    import pytest
    with pytest.raises(ValueError, match="empty"):
        tun.save_ngrok_authtoken("   ")


def test_save_ngrok_authtoken_requires_ngrok(monkeypatch):
    import pytest
    monkeypatch.setattr(tun.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not installed"):
        tun.save_ngrok_authtoken("tok123")


def test_save_ngrok_authtoken_reports_failed_command(monkeypatch):
    import pytest

    class _Res:
        returncode = 1
        stdout = ""
        stderr = "ERROR: bad authtoken\n"

    monkeypatch.setattr(tun.shutil, "which", lambda name: "/usr/bin/ngrok")
    monkeypatch.setattr(tun.subprocess, "run", lambda *a, **k: _Res())
    with pytest.raises(RuntimeError, match="code 1"):
        tun.save_ngrok_authtoken("tok123")


def test_ngrok_command_carries_no_token_even_when_given():
    # The ngrok command must never carry a token: the token is saved to
    # ngrok's own config (save_ngrok_authtoken), never passed on the
    # command line. A token in the GUI field must not be silently
    # ignored — the GUI refuses to start until it is saved.
    cmd = tun.build_command("ngrok", "temporary", "http://127.0.0.1:8000",
                            token="secret123")
    assert cmd == ["ngrok", "http", "8000"]
    assert "secret123" not in " ".join(cmd)


class _FakeProc:
    """Pretends to be a provider that starts fine, then dies without
    printing a public URL (e.g. ngrok failing auth after the 1s
    fail-fast check). stdout stays open until the process 'exits',
    mirroring a real process whose pipe closes on exit."""

    def __init__(self, exit_after=1.15):
        import time
        self.pid = 17932
        self.returncode = None
        self._start = time.time()
        self._exit_after = exit_after
        self._stdout_iter = self._lines()

    def _lines(self):
        import time
        time.sleep(self._exit_after)
        yield "ERROR: authentication failed: authtoken not configured\n"

    @property
    def stdout(self):
        return self._stdout_iter

    def poll(self):
        import time
        if time.time() - self._start >= self._exit_after:
            self.returncode = 1
            return 1
        return None

    def terminate(self):
        self.returncode = -15

    def wait(self, timeout=None):
        return self.returncode


def test_start_tunnel_reports_exit_after_first_second(monkeypatch):
    # Regression test for the stuck "Waiting for the provider to report
    # its public URL…" label: ngrok died after the 1s fail-fast check
    # and nothing ever reported it. start_tunnel must now report the
    # exit code and last output lines via on_failure / failure_reason.
    import threading

    monkeypatch.setattr(tun.shutil, "which", lambda name: "/usr/bin/ngrok")
    monkeypatch.setattr(tun.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(exit_after=1.15))
    failed = []
    done = threading.Event()

    def on_failure(reason):
        failed.append(reason)
        done.set()

    # Returns (does not raise): the process was alive at the 1s check.
    tunnel = tun.start_tunnel("ngrok", "temporary", "http://127.0.0.1:8000",
                              on_failure=on_failure)
    assert done.wait(timeout=5), "on_failure was never called"
    assert failed and "code 1" in failed[0]
    assert "authentication failed" in failed[0]
    assert tunnel.failure_reason == failed[0]
    assert not tunnel.public_url
