"""Settings for CyberLLMv1 Security Lab.

Stored as JSON in a per-user data directory (``%APPDATA%\\CyberLLMv1
Security Lab`` on Windows, ``~/.local/share/cyberllm-security-lab``
elsewhere). The file holds paths and preferences only, plus one
local-only lab credential (see below). It never holds model weights,
API keys for third-party services, or the user's personal SentientAI
password.

Local lab credential: the GUI creates a dedicated SentientAI account
(``lab_username``) on the user's own machine so the desktop tool can
call the local backend without a browser. Its password is stored here
because the account is useless without it across launches. It is a
throwaway local credential, not the user's personal password; it is
never included in reports or exports, and deleting it (or the whole
settings file) forces the GUI to create a fresh lab account. Users who
prefer not to store it can leave ``lab_password`` empty and enter
their own SentientAI login each session instead (that login is kept
in memory only, never written to disk).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

APP_NAME = "CyberLLMv1 Security Lab"
APP_DIR_NAME = "CyberLLMv1 Security Lab"

EXPECTED_BASE_MODEL = "Qwen/Qwen3-1.7B"
EXPECTED_BASE_REVISION = "70d244cc86ccca08cf5af4e1e306ecf908b1ad5e"
EXPECTED_ADAPTER_SHA256 = (
    "d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1"
)

DEFAULT_API_BASE = "http://127.0.0.1:8000"


def user_data_dir() -> Path:
    """Per-user writable directory for settings, logs and reports."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_DIR_NAME
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "cyberllm-security-lab"
    return Path.home() / ".local" / "share" / "cyberllm-security-lab"


def settings_path(data_dir: Path | None = None) -> Path:
    return (data_dir or user_data_dir()) / "settings.json"


@dataclass
class Settings:
    # Backend location. Empty means "auto-detect from the app folder".
    project_root: str = ""
    backend_python: str = ""
    api_base: str = DEFAULT_API_BASE
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Model configuration. Empty means "use the backend's own defaults"
    # (project cyberLLMv1/ layout, manifest, or legacy fallback).
    model_root: str = ""
    base_dir: str = ""
    adapter_dir: str = ""
    base_model: str = EXPECTED_BASE_MODEL
    base_revision: str = EXPECTED_BASE_REVISION
    adapter_sha256: str = EXPECTED_ADAPTER_SHA256
    device: str = "auto"  # auto | cpu | cuda
    load_in_8bit: bool = False

    # Scanner safety defaults.
    allowlist: list[str] = field(default_factory=list)
    local_lab_enabled: bool = False
    rate_limit_seconds: float = 0.25
    request_timeout_seconds: float = 10.0
    max_requests_per_scan: int = 200
    max_workers: int = 2
    scan_deadline_seconds: float = 300.0

    # Local lab account for backend API access (see module docstring).
    lab_username: str = "seclab"
    lab_password: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        clean = {k: v for k, v in data.items() if k in known}
        obj = cls(**clean)
        # Coerce numeric fields that may arrive as strings from hand edits.
        try:
            obj.api_port = int(obj.api_port)
        except (TypeError, ValueError):
            obj.api_port = 8000
        try:
            obj.rate_limit_seconds = float(obj.rate_limit_seconds)
            obj.request_timeout_seconds = float(obj.request_timeout_seconds)
            obj.scan_deadline_seconds = float(obj.scan_deadline_seconds)
        except (TypeError, ValueError):
            pass
        try:
            obj.max_requests_per_scan = int(obj.max_requests_per_scan)
            obj.max_workers = int(obj.max_workers)
        except (TypeError, ValueError):
            pass
        if obj.device not in ("auto", "cpu", "cuda"):
            obj.device = "auto"
        return obj


def load_settings(data_dir: Path | None = None) -> Settings:
    path = settings_path(data_dir)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return Settings.from_dict(data)
    except (OSError, ValueError):
        pass
    return Settings()


def save_settings(settings: Settings, data_dir: Path | None = None) -> Path:
    data_dir = data_dir or user_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "settings.json"
    path.write_text(
        json.dumps(settings.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def ensure_data_dirs(data_dir: Path | None = None) -> dict[str, Path]:
    base = data_dir or user_data_dir()
    dirs = {
        "base": base,
        "logs": base / "logs",
        "reports": base / "reports",
        "history": base / "history",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs
