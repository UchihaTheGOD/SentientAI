"""Backend process management for CyberLLMv1 Security Lab.

The GUI manages the *existing* SentientAI backend: it launches
``app.main:app`` with uvicorn from the project root (never ``run.py``,
which enables reload mode) and talks to the existing readiness and
analysis API. No second model loader is built here; the loader inside
the backend remains the authority for model loading and adapter SHA
verification. The checks in this module are pre-flight UX: they tell
the user what is missing *before* a load is attempted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:  # pragma: no cover - requests is a hard requirement
    requests = None  # type: ignore

from .config import Settings, ensure_data_dirs


def find_project_root(settings: Settings) -> Path | None:
    """Locate the SentientAI project root (a dir with run.py + app/main.py)."""
    candidates: list[Path] = []
    if settings.project_root:
        candidates.append(Path(settings.project_root))
    # When frozen, the distribution folder holds the project next to the exe.
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent)
    candidates.append(Path(__file__).resolve().parent.parent)
    candidates.append(Path.cwd())
    for cand in candidates:
        try:
            if (cand / "run.py").is_file() and (cand / "app" / "main.py").is_file():
                return cand
        except OSError:
            continue
    return None


def find_backend_python(settings: Settings, project_root: Path) -> Path | None:
    """Pick the Python that runs the backend.

    Order: explicit setting, project venv, then (source runs only) the
    current interpreter. A frozen GUI exe is never used as the backend
    interpreter: it is not a Python environment.
    """
    if settings.backend_python:
        p = Path(settings.backend_python)
        if p.is_file():
            return p
    if os.name == "nt":
        venv_py = project_root / "venv" / "Scripts" / "python.exe"
    else:
        venv_py = project_root / "venv" / "bin" / "python"
    if venv_py.is_file():
        return venv_py
    if not getattr(sys, "frozen", False):
        return Path(sys.executable)
    return None


def build_backend_env(settings: Settings) -> dict[str, str]:
    """Environment for the backend subprocess.

    Only CyberLLM settings the user configured are injected; everything
    else (including SECRET_KEY, so existing website sessions survive)
    is left to the backend's own .env handling.
    """
    env = dict(os.environ)
    if settings.model_root:
        env["CYBERLLM_MODEL_ROOT"] = settings.model_root
    if settings.base_dir:
        env["CYBERLLM_BASE_DIR"] = settings.base_dir
    if settings.adapter_dir:
        env["CYBERLLM_ADAPTER_DIR"] = settings.adapter_dir
    env["CYBERLLM_BASE_MODEL"] = settings.base_model
    env["CYBERLLM_BASE_REVISION"] = settings.base_revision
    env["CYBERLLM_ADAPTER_SHA256"] = settings.adapter_sha256
    env["CYBERLLM_DEVICE"] = settings.device
    env["CYBERLLM_LOAD_IN_8BIT"] = "1" if settings.load_in_8bit else "0"
    return env


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class ArtifactCheck:
    missing: list[str] = field(default_factory=list)
    adapter_sha_status: str = "unchecked"  # match | mismatch | missing | unchecked
    adapter_sha_actual: str = ""
    base_dir: str = ""
    adapter_dir: str = ""

    @property
    def ok(self) -> bool:
        return not self.missing and self.adapter_sha_status in ("match", "unchecked")


def check_artifacts(settings: Settings, project_root: Path) -> ArtifactCheck:
    """Filesystem pre-flight check mirroring the loader's structure rules."""
    result = ArtifactCheck()
    # Resolve the same way the loader does: explicit dirs win, otherwise
    # the project cyberLLMv1/ layout, otherwise the legacy adapter dir.
    if settings.base_dir:
        base_dir = Path(settings.base_dir)
    elif settings.model_root:
        base_dir = Path(settings.model_root) / "base"
    else:
        base_dir = project_root / "cyberLLMv1" / "base"
    if settings.adapter_dir:
        adapter_dir = Path(settings.adapter_dir)
    elif settings.model_root:
        adapter_dir = Path(settings.model_root) / "adapter"
    else:
        adapter_dir = project_root / "cyberLLMv1" / "adapter"
        if not adapter_dir.is_dir():
            legacy = project_root / "local_models" / "cyberllm" / "v8"
            if legacy.is_dir():
                adapter_dir = legacy
    result.base_dir = str(base_dir)
    result.adapter_dir = str(adapter_dir)
    if not base_dir.is_dir():
        result.missing.append(f"base model directory missing: {base_dir}")
    else:
        if not (base_dir / "config.json").is_file():
            result.missing.append(f"base config.json missing: {base_dir}")
        weights = list(base_dir.glob("model*.safetensors")) or list(
            base_dir.glob("*.safetensors")
        )
        if not weights and not (base_dir / "pytorch_model.bin").is_file():
            result.missing.append(f"base model weights missing in: {base_dir}")
        if not (
            (base_dir / "tokenizer.json").is_file()
            or (base_dir / "tokenizer_config.json").is_file()
        ):
            result.missing.append(f"base tokenizer missing in: {base_dir}")
    if not adapter_dir.is_dir():
        result.missing.append(f"adapter directory missing: {adapter_dir}")
        result.adapter_sha_status = "missing"
    else:
        if not (adapter_dir / "adapter_config.json").is_file():
            result.missing.append(f"adapter_config.json missing: {adapter_dir}")
        weights_file = adapter_dir / "adapter_model.safetensors"
        if not weights_file.is_file():
            result.missing.append(f"adapter_model.safetensors missing: {adapter_dir}")
            result.adapter_sha_status = "missing"
        elif settings.adapter_sha256:
            try:
                actual = _sha256_file(weights_file)
                result.adapter_sha_actual = actual
                result.adapter_sha_status = (
                    "match"
                    if actual.lower() == settings.adapter_sha256.strip().lower()
                    else "mismatch"
                )
                if result.adapter_sha_status == "mismatch":
                    result.missing.append(
                        "adapter SHA-256 mismatch: refusing to treat this "
                        "adapter as pilot v8 (expected "
                        f"{settings.adapter_sha256[:12]}…, got {actual[:12]}…)"
                    )
            except OSError as exc:
                result.missing.append(f"could not hash adapter file: {exc}")
    return result


def gpu_info(backend_python: Path | None) -> dict[str, Any]:
    """Best-effort GPU report. Never raises; missing data is reported."""
    info: dict[str, Any] = {"available": False, "source": "none"}
    # nvidia-smi first: it works even when torch is absent.
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,memory.used",
             "--format=csv,noheader"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0 and out.stdout.strip():
            name, total, used = [p.strip() for p in out.stdout.strip().split(",")]
            info.update({
                "available": True, "source": "nvidia-smi", "name": name,
                "vram_total": total, "vram_used": used,
            })
            return info
    except (OSError, subprocess.SubprocessError):
        pass
    # Fall back to torch in the backend interpreter.
    if backend_python is not None:
        try:
            out = subprocess.run(
                [str(backend_python), "-c",
                 "import torch, json; print(json.dumps({"
                 "'cuda': torch.cuda.is_available(),"
                 "'name': torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,"
                 "'vram_total': torch.cuda.get_device_properties(0).total_memory if torch.cuda.is_available() else None}))"],
                capture_output=True, text=True, timeout=30,
            )
            if out.returncode == 0 and out.stdout.strip():
                data = json.loads(out.stdout.strip().splitlines()[-1])
                if data.get("cuda"):
                    info.update({
                        "available": True, "source": "torch",
                        "name": data["name"],
                        "vram_total": f"{data['vram_total'] / (1024 ** 2):.0f} MiB",
                        "vram_used": "unknown",
                    })
                else:
                    info.update({"available": False, "source": "torch",
                                 "detail": "torch reports no CUDA GPU"})
                return info
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    info["detail"] = "no nvidia-smi output and no torch CUDA report"
    return info


def system_stats() -> dict[str, Any]:
    """CPU/RAM snapshot; psutil is optional."""
    try:
        import psutil

        vm = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "ram_total_gb": round(vm.total / (1024 ** 3), 1),
            "ram_used_gb": round(vm.used / (1024 ** 3), 1),
            "ram_percent": vm.percent,
        }
    except ImportError:
        return {"detail": "psutil not installed; CPU/RAM unavailable"}


@dataclass
class BackendState:
    running: bool = False
    pid: int | None = None
    readiness: dict[str, Any] = field(default_factory=dict)
    last_error: str = ""


class BackendManager:
    """Owns the backend subprocess and its log output."""

    def __init__(self, settings: Settings, data_dir: Path | None = None):
        self.settings = settings
        self.dirs = ensure_data_dirs(data_dir)
        self.proc: subprocess.Popen | None = None
        self.started_by_gui = False
        self.log_lines: deque[str] = deque(maxlen=500)
        self._reader_thread: threading.Thread | None = None
        self._log_handle = None

    # -- lifecycle ------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        if self.proc is not None and self.proc.poll() is None:
            return True, f"backend already running (pid {self.proc.pid})"
        root = find_project_root(self.settings)
        if root is None:
            return False, (
                "SentientAI project root not found. Set it in Settings "
                "(the folder containing run.py and app/main.py)."
            )
        python = find_backend_python(self.settings, root)
        if python is None:
            return False, (
                "No backend Python found. Set it in Settings, or create "
                "the project venv (python -m venv venv, then install "
                "requirements.txt)."
            )
        log_path = self.dirs["logs"] / "backend.log"
        try:
            self._log_handle = open(log_path, "ab")
        except OSError as exc:
            return False, f"cannot open backend log file: {exc}"
        cmd = [
            str(python), "-m", "uvicorn", "app.main:app",
            "--host", self.settings.api_host,
            "--port", str(self.settings.api_port),
        ]
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=str(root), env=build_backend_env(self.settings),
                stdout=self._log_handle, stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            return False, f"failed to launch backend: {exc}"
        self._reader_thread = threading.Thread(
            target=self._tail_log, args=(log_path,), daemon=True)
        self._reader_thread.start()
        ok, msg = self.wait_ready(timeout=90)
        if not ok:
            return False, msg
        self.started_by_gui = True
        return True, f"backend running (pid {self.proc.pid})"

    def _tail_log(self, log_path: Path) -> None:
        try:
            with open(log_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                while self.proc is not None and self.proc.poll() is None:
                    line = fh.readline()
                    if line:
                        self.log_lines.append(
                            line.decode("utf-8", "replace").rstrip())
                    else:
                        time.sleep(0.2)
        except OSError:
            pass

    def stop(self) -> tuple[bool, str]:
        if self.proc is None or self.proc.poll() is not None:
            self.proc = None
            self.started_by_gui = False
            return True, "backend is not running"
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)
        except OSError as exc:
            return False, f"failed to stop backend: {exc}"
        finally:
            self.proc = None
            self.started_by_gui = False
            if self._log_handle is not None:
                try:
                    self._log_handle.close()
                except OSError:
                    pass
                self._log_handle = None
        return True, "backend stopped"

    def restart(self) -> tuple[bool, str]:
        ok, msg = self.stop()
        if not ok:
            return False, msg
        return self.start()

    # -- status ---------------------------------------------------------
    def wait_ready(self, timeout: float = 90) -> tuple[bool, str]:
        """Poll the unauthenticated readiness endpoint until it answers."""
        if requests is None:
            return False, "requests library is not installed"
        deadline = time.time() + timeout
        last_error = "no response"
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                return False, (
                    f"backend exited during startup (code {self.proc.returncode}); "
                    "see the log view for the traceback."
                )
            try:
                resp = requests.get(
                    f"{self.settings.api_base}/api/cyberllm/readiness",
                    timeout=3,
                )
                if resp.status_code == 200:
                    return True, "backend is responding"
                last_error = f"HTTP {resp.status_code}"
            except requests.RequestException as exc:
                last_error = str(exc)[:200]
            time.sleep(1.0)
        return False, f"backend did not answer readiness within {timeout}s: {last_error}"

    def readiness(self) -> dict[str, Any]:
        if requests is None:
            return {"error": "requests library is not installed"}
        try:
            resp = requests.get(
                f"{self.settings.api_base}/api/cyberllm/readiness", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    return data
            return {"error": f"readiness returned HTTP {resp.status_code}"}
        except requests.RequestException as exc:
            return {"error": str(exc)[:300]}
        except ValueError:
            return {"error": "readiness returned non-JSON output"}

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def state(self) -> BackendState:
        running = self.running
        return BackendState(
            running=running,
            pid=self.proc.pid if running else None,
            readiness=self.readiness() if running else {},
        )
