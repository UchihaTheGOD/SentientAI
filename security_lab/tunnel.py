"""Tunnel Manager — expose the local SentientAI website publicly, safely.

Supports Cloudflare Tunnel (cloudflared), ngrok, Pinggy, and zrok.
This module has NO PySide6 dependency so it can be unit-tested
without a GUI.

Design rules (from the v2 task):
- Detect the provider binary; never assume it is installed. If one is
  not present, say so and point at the official download (never install
  from an unverified source, and never install silently).
  Pinggy needs no install: it uses the stock `ssh` client (Windows 10+,
  Linux, macOS all ship one).
- Never hardcode tokens or credentials, and never write one to disk.
  Authentication belongs to the provider's own flow:
  * cloudflared: `cloudflared tunnel login` (once, outside this app).
  * ngrok: `ngrok config add-authtoken <token>` (once). The app may run
    that command for the user on request (see save_ngrok_authtoken);
    it never stores the token itself — ngrok writes it to its own
    config file.
  * zrok: `zrok enable <account_token>` (once, outside this app).
  * Pinggy free tier: no token at all. Pinggy Pro: the token is passed
    as the SSH username (`<token>@a.pinggy.io`) for that tunnel process
    only — it is held in memory for the session, never saved, and the
    free tier works without it.
- A tunnel that dies after starting must be reported, not left looking
  alive: start_tunnel reports the provider's exit code and its last
  output lines (via on_failure / Tunnel.failure_reason) instead of
  waiting forever for a URL that will never arrive.
- Two modes:
  * "temporary" — a quick share (cloudflared `tunnel --url`, ngrok
    `http <port>`, Pinggy free `ssh ... free@a.pinggy.io`, zrok
    `share public <port>`). No account needed for cloudflared quick
    tunnels or Pinggy free; ngrok and zrok need their one-time setup.
  * "persistent" — a named/reserved tunnel the user configured with the
    provider (cloudflared `tunnel run <name>`, ngrok `--domain <name>`,
    Pinggy Pro token, zrok `share reserved <share_token>`).
- The manager only ever stops a tunnel process IT started (tracked by PID).
  It never kills unrelated processes.
- The public URL is parsed from the provider's own stdout. If the provider
  does not report a URL, the tunnel is reported as "running, URL unknown"
  — never a guessed URL.
- Before any tunnel starts, the caller must confirm the pre-exposure
  checklist (auth enabled, no default accounts, admin routes protected,
  debug off, no secrets in the repo). The GUI shows that warning; this
  module does not bypass it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

PROVIDERS = ("cloudflared", "ngrok", "pinggy", "zrok")

# The binary each provider needs on PATH. Pinggy uses the stock ssh client.
_PROVIDER_BINARY = {
    "cloudflared": "cloudflared",
    "ngrok": "ngrok",
    "pinggy": "ssh",
    "zrok": "zrok",
}

# Public URL patterns in provider stdout.
_URL_PATTERNS = {
    "cloudflared": re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com"),
    "ngrok": re.compile(r"https://[a-zA-Z0-9-]+\.ngrok(?:-free)?\.(?:app|io)"),
    "pinggy": re.compile(r"https://[a-zA-Z0-9-]+\.a\.pinggy\.io"),
    "zrok": re.compile(r"https://[a-zA-Z0-9-]+\.(?:share\.)?zrok\.io"),
}

OFFICIAL_DOWNLOADS = {
    "cloudflared": "https://developers.cloudflare.com/cloudflare-one/connections/connect/downloads/",
    "ngrok": "https://ngrok.com/download",
    "pinggy": "https://pinggy.io/ (no download — uses the stock ssh client)",
    "zrok": "https://docs.zrok.io/docs/getting-started/",
}

# One-line auth note shown in the GUI per provider.
PROVIDER_AUTH = {
    "cloudflared": "Quick tunnel: no account. Named tunnel: `cloudflared tunnel login` once.",
    "ngrok": "Needs authtoken once: `ngrok config add-authtoken <token>` (free account at ngrok.com).",
    "pinggy": "Free tier: no token, 60-min tunnels. Pro: paste your token (persistent URL, no time cap).",
    "zrok": "Needs account token once: `zrok enable <token>` (free account at zrok.io).",
}


@dataclass
class ProviderStatus:
    name: str
    installed: bool
    path: str = ""
    version: str = ""


def detect_providers() -> list[ProviderStatus]:
    """Return the install/version status of each supported provider.

    Pinggy is detected via the stock `ssh` client it uses.
    """
    out: list[ProviderStatus] = []
    for name in PROVIDERS:
        binary = _PROVIDER_BINARY[name]
        path = shutil.which(binary) or ""
        version = ""
        if path:
            try:
                res = subprocess.run(
                    [path, "--version"], capture_output=True, text=True,
                    timeout=10)
                version = (res.stdout or res.stderr or "").strip().splitlines()[0][:80]
            except Exception:
                version = ""
        out.append(ProviderStatus(name=name, installed=bool(path),
                                  path=path, version=version))
    return out


def save_ngrok_authtoken(token: str) -> str:
    """Save an ngrok authtoken using ngrok's own config command.

    Runs `ngrok config add-authtoken <token>` once. The app never stores
    the token itself — ngrok writes it to its own config file, exactly
    as if the user ran the command by hand. Raises RuntimeError if
    ngrok is not installed or the command fails, ValueError if the
    token is empty. Returns ngrok's output line (the config path it
    saved to), when ngrok prints one.
    """
    token = (token or "").strip()
    if not token:
        raise ValueError("authtoken is empty — paste your ngrok authtoken first.")
    if shutil.which("ngrok") is None:
        raise RuntimeError(
            "ngrok is not installed. Get it from the official "
            f"download: {OFFICIAL_DOWNLOADS.get('ngrok', '')}")
    res = subprocess.run(
        ["ngrok", "config", "add-authtoken", token],
        capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(
            f"ngrok config add-authtoken failed (code {res.returncode})"
            + (f": {detail[:200]}" if detail else "."))
    return (res.stdout or "").strip()


@dataclass
class Tunnel:
    provider: str
    mode: str  # "temporary" | "persistent"
    local_url: str
    public_url: str = ""
    pid: int | None = None
    started_at: float = 0.0
    # Set when the provider process exits without reporting a public URL
    # (e.g. ngrok failing auth): "exited (code N). Last output: ...".
    failure_reason: str = ""
    _proc: subprocess.Popen | None = field(default=None, repr=False)
    _reader: threading.Thread | None = field(default=None, repr=False)
    _stop_reader: threading.Event = field(
        default_factory=threading.Event, repr=False)

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self) -> None:
        """Stop ONLY the tunnel process this object started."""
        self._stop_reader.set()
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        self._proc = None


def build_command(provider: str, mode: str, local_url: str,
                  tunnel_name: str = "", token: str = "") -> list[str]:
    """Build the provider command.

    No credential is stored anywhere. `token` is only used for Pinggy Pro
    (passed as the SSH username for that one process, in memory only);
    every other provider authenticates through its own saved config.
    """
    if provider == "cloudflared":
        if mode == "persistent":
            if not tunnel_name:
                raise ValueError(
                    "persistent Cloudflare tunnel needs a tunnel name "
                    "(created with `cloudflared tunnel create <name>`)")
            return ["cloudflared", "tunnel", "run", tunnel_name]
        return ["cloudflared", "tunnel", "--url", local_url]
    if provider == "ngrok":
        # ngrok needs its authtoken configured by the user (ngrok config
        # add-authtoken) for both modes; this command carries no token.
        port = local_url.rsplit(":", 1)[-1]
        if mode == "persistent" and tunnel_name:
            return ["ngrok", "http", "--domain", tunnel_name, port]
        return ["ngrok", "http", port]
    if provider == "pinggy":
        # Pinggy is SSH: stock ssh client, no install. Free tier uses the
        # "free" user (no token, 60-minute tunnels, random subdomain).
        # Pro uses the user's token as the SSH username (persistent URL,
        # no time cap). The token is never written to disk by this module.
        port = local_url.rsplit(":", 1)[-1]
        if mode == "persistent":
            if not token:
                raise ValueError(
                    "Pinggy Pro (persistent) needs your Pinggy token "
                    "(free account at pinggy.io; paste it in the token "
                    "field). For no-token sharing use temporary mode.")
            user = f"{token}@a.pinggy.io"
        else:
            user = "free@a.pinggy.io"
        return ["ssh", "-p", "443", "-o", "StrictHostKeyChecking=no",
                "-o", "ServerAliveInterval=30",
                f"-R0:localhost:{port}", user]
    if provider == "zrok":
        # zrok needs its account token enabled once by the user
        # (`zrok enable <token>`); this command carries no token.
        port = local_url.rsplit(":", 1)[-1]
        if mode == "persistent":
            if not tunnel_name:
                raise ValueError(
                    "persistent zrok needs a reserved share token "
                    "(created with `zrok reserve public --backend-mode "
                    "proxy localhost:<port>`)")
            return ["zrok", "share", "reserved", tunnel_name]
        return ["zrok", "share", "public", port]
    raise ValueError(f"unsupported tunnel provider: {provider}")


def start_tunnel(provider: str, mode: str, local_url: str,
                 tunnel_name: str = "", token: str = "",
                 on_url: Optional[callable] = None,
                 on_failure: Optional[callable] = None) -> Tunnel:
    """Start a tunnel and return the Tunnel object. Raises on failure.

    on_url(public_url) is called (once) when the provider prints its URL.
    on_failure(reason) is called (once) if the provider process exits
    without ever reporting a URL — the reason carries its exit code and
    its last output lines, so a failed tunnel is reported instead of
    looking alive forever. The same reason is stored on
    Tunnel.failure_reason. Neither callback fires when the tunnel is
    stopped deliberately (Tunnel.stop sets the stop flag first).
    `token` is only used for Pinggy Pro and is never written to disk.
    """
    binary = _PROVIDER_BINARY.get(provider, provider)
    if shutil.which(binary) is None:
        if provider == "pinggy":
            raise RuntimeError(
                "Pinggy needs the stock ssh client, which was not found "
                "on PATH. It ships with Windows 10+, Linux and macOS.")
        raise RuntimeError(
            f"{provider} is not installed. Get it from the official "
            f"download: {OFFICIAL_DOWNLOADS.get(provider, '')}")
    cmd = build_command(provider, mode, local_url, tunnel_name, token)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    tunnel = Tunnel(provider=provider, mode=mode, local_url=local_url,
                    pid=proc.pid, started_at=time.time(), _proc=proc)
    pattern = _URL_PATTERNS.get(provider)
    last_lines: list[str] = []

    def _read() -> None:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if tunnel._stop_reader.is_set():
                    break
                last_lines.append(line.rstrip())
                del last_lines[:-10]
                if pattern and not tunnel.public_url:
                    m = pattern.search(line)
                    if m:
                        tunnel.public_url = m.group(0)
                        if on_url is not None:
                            on_url(tunnel.public_url)
        except Exception:
            pass
        # stdout closed: the provider process exited (or was stopped).
        # If it died on its own without a URL, report it — never leave
        # the caller waiting for a URL that will never arrive.
        if tunnel._stop_reader.is_set():
            return
        code = proc.poll()
        if code is not None and not tunnel.public_url:
            tail = " | ".join(last_lines[-3:]) if last_lines else "(no output)"
            reason = (f"{provider} exited (code {code}) before reporting "
                      f"a public URL. Last output: {tail}")
            tunnel.failure_reason = reason
            if on_failure is not None:
                try:
                    on_failure(reason)
                except Exception:
                    pass

    tunnel._reader = threading.Thread(target=_read, daemon=True)
    tunnel._reader.start()
    # Give the provider a moment to fail fast (bad binary, bad args).
    time.sleep(1.0)
    if proc.poll() is not None:
        raise RuntimeError(
            f"{provider} exited immediately (code {proc.returncode}). "
            "Check that it is configured (cloudflared: `cloudflared tunnel "
            "login`; ngrok: `ngrok config add-authtoken <token>`; zrok: "
            "`zrok enable <token>`; Pinggy: no setup for the free tier).")
    return tunnel
