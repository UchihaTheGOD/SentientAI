from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("sentientai.cyberllm")

# PROJECT_ROOT, not the process working directory: app/services/*.py lives
# two levels below the project root, so this stays correct when the app is
# launched from another cwd, and when the whole project folder is moved.
# Every default CyberLLM path below is derived from this, never from a
# personal Windows directory.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BASE_DIR

# Portable default model root: <project>/cyberLLMv1/{base,adapter,manifest.json}
# Override it (documented, optional) with CYBERLLM_MODEL_ROOT. A relative
# override is resolved against PROJECT_ROOT, not against the caller's cwd.
DEFAULT_MODEL_ROOT = PROJECT_ROOT / "cyberLLMv1"
LEGACY_ADAPTER_DIR = PROJECT_ROOT / "local_models" / "cyberllm" / "v8"

BASE_MODEL_ID = os.getenv("CYBERLLM_BASE_MODEL", "Qwen/Qwen3-1.7B")
BASE_REVISION = os.getenv(
    "CYBERLLM_BASE_REVISION",
    "70d244cc86ccca08cf5af4e1e306ecf908b1ad5e",
)

BASE_DIR_ENV = os.getenv("CYBERLLM_BASE_DIR", "")

ADAPTER_DIR = Path(
    os.getenv(
        "CYBERLLM_ADAPTER_DIR",
        str(BASE_DIR / "local_models" / "cyberllm" / "v8"),
    )
)

ADAPTER_SHA256 = os.getenv(
    "CYBERLLM_ADAPTER_SHA256",
    "d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1",
)

DEVICE_ENV = os.getenv("CYBERLLM_DEVICE", "auto").strip().lower()
LOAD_IN_8BIT = os.getenv("CYBERLLM_LOAD_IN_8BIT", "0").strip() == "1"


def _resolve_against_root(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def _read_manifest(root: Path) -> dict[str, Any]:
    try:
        data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@dataclass
class CyberLLMPaths:
    """Resolved CyberLLM locations. Read fresh from the environment on
    every call so tests / a changed .env do not depend on import order.

    Precedence (highest first):
    1. CYBERLLM_BASE_DIR / CYBERLLM_ADAPTER_DIR (legacy, kept compatible)
    2. CYBERLLM_MODEL_ROOT / {base, adapter} (+ its manifest.json)
    3. <project>/cyberLLMv1 / {base, adapter} (+ its manifest.json)
    4. Legacy adapter only: <project>/local_models/cyberllm/v8, when the
       cyberLLMv1 adapter is absent. Base still falls back to the HF id.
    """

    root: Path
    base_dir: Path
    adapter_dir: Path
    base_model_id: str
    base_revision: str
    adapter_sha256: str
    source: str


def resolve_cyberllm_paths() -> CyberLLMPaths:
    root_env = os.getenv("CYBERLLM_MODEL_ROOT", "").strip()
    if root_env:
        root = _resolve_against_root(root_env)
        source = "env:CYBERLLM_MODEL_ROOT"
    else:
        root = DEFAULT_MODEL_ROOT
        source = "default:cyberLLMv1"
    manifest = _read_manifest(root)
    base_env = os.getenv("CYBERLLM_BASE_DIR", "").strip()
    adapter_env = os.getenv("CYBERLLM_ADAPTER_DIR", "").strip()
    if base_env:
        base_dir = _resolve_against_root(base_env)
    else:
        base_dir = root / "base"
    if adapter_env:
        adapter_dir = _resolve_against_root(adapter_env)
    elif (root / "adapter").is_dir():
        adapter_dir = root / "adapter"
    elif LEGACY_ADAPTER_DIR.is_dir():
        adapter_dir = LEGACY_ADAPTER_DIR
    else:
        adapter_dir = root / "adapter"
    return CyberLLMPaths(
        root=root,
        base_dir=base_dir,
        adapter_dir=adapter_dir,
        base_model_id=os.getenv("CYBERLLM_BASE_MODEL", "").strip()
        or str(manifest.get("base_model", "")).strip()
        or BASE_MODEL_ID,
        base_revision=os.getenv("CYBERLLM_BASE_REVISION", "").strip()
        or str(manifest.get("base_revision", "")).strip()
        or BASE_REVISION,
        adapter_sha256=os.getenv("CYBERLLM_ADAPTER_SHA256", "").strip()
        or str(manifest.get("adapter_sha256", "")).strip()
        or ADAPTER_SHA256,
        source=source,
    )


def validate_cyberllm_artifacts(paths: CyberLLMPaths) -> list[str]:
    """Return human-readable missing/incomplete items, or [] when usable.

    This checks structure only (files present, weights present); the SHA
    check in ensure_loaded() is the authority for adapter identity.
    """
    missing: list[str] = []
    if not paths.base_dir.is_dir():
        missing.append(f"base model directory missing: {paths.base_dir}")
    else:
        if not (paths.base_dir / "config.json").is_file():
            missing.append(f"base config.json missing: {paths.base_dir}")
        weights = list(paths.base_dir.glob("model*.safetensors")) or list(
            paths.base_dir.glob("*.safetensors")
        )
        if not weights and not (paths.base_dir / "pytorch_model.bin").is_file():
            missing.append(f"base model weights missing in: {paths.base_dir}")
        if not (
            (paths.base_dir / "tokenizer.json").is_file()
            or (paths.base_dir / "tokenizer_config.json").is_file()
        ):
            missing.append(f"base tokenizer missing in: {paths.base_dir}")
    if not paths.adapter_dir.is_dir():
        missing.append(f"adapter directory missing: {paths.adapter_dir}")
    else:
        if not (paths.adapter_dir / "adapter_config.json").is_file():
            missing.append(
                f"adapter_config.json missing: {paths.adapter_dir}"
            )
        if not (paths.adapter_dir / "adapter_model.safetensors").is_file():
            missing.append(
                f"adapter_model.safetensors missing: {paths.adapter_dir}"
            )
    return missing

try:
    import torch

    _TORCH_AVAILABLE = True
except ImportError:
    torch = None
    _TORCH_AVAILABLE = False


@dataclass
class CyberLLMStatus:
    ready: bool = False
    state: str = "not_loaded"
    reason: Optional[str] = None
    base_model: str = BASE_MODEL_ID
    model_root: str = str(DEFAULT_MODEL_ROOT)
    adapter_dir: str = str(ADAPTER_DIR)
    adapter_sha256: str = ADAPTER_SHA256
    device: str = "cpu"
    quantization: str = "none"
    load_ms: Optional[int] = None
    rss_mb: Optional[float] = None


_status = CyberLLMStatus(reason="not_initialized")
_bundle: dict[str, Any] = {}
_lock = threading.Lock()


def _get_rss_mb() -> Optional[float]:
    try:
        import psutil

        return round(
            psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024,
            1,
        )
    except Exception:
        return None


def _adapter_sha_ok(paths: Optional[CyberLLMPaths] = None) -> bool:
    """Verify the adapter file against the configured SHA-256 digest."""
    resolved = paths or resolve_cyberllm_paths()
    if not resolved.adapter_sha256:
        return True

    adapter_file = resolved.adapter_dir / "adapter_model.safetensors"

    if not adapter_file.is_file():
        return False

    digest = hashlib.sha256()

    with adapter_file.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1 << 20), b""):
            digest.update(chunk)

    return digest.hexdigest().lower() == resolved.adapter_sha256.strip().lower()


def get_status() -> CyberLLMStatus:
    # Report the resolved (project-local) paths even before any load, so
    # /api/cyberllm/readiness never shows a stale import-time legacy path
    # when cyberLLMv1/ is the actual default.
    try:
        paths = resolve_cyberllm_paths()
        _status.model_root = str(paths.root)
        _status.adapter_dir = str(paths.adapter_dir)
        _status.adapter_sha256 = paths.adapter_sha256
        if not _status.ready:
            _status.base_model = paths.base_model_id
    except Exception:
        pass
    _status.rss_mb = _get_rss_mb()
    return _status


def ensure_loaded() -> CyberLLMStatus:
    """Load the base model and LoRA adapter once.

    Loading failures are recorded in the status so the API can return
    an honest error instead of fabricating a model verdict.
    """
    global _bundle

    with _lock:
        if _status.ready:
            return _status

        started_at = time.perf_counter()

        # Reset status fields in case a previous load attempt failed.
        _status.state = "loading"
        _status.reason = None
        _status.load_ms = None
        _status.quantization = "none"

        try:
            paths = resolve_cyberllm_paths()
            _status.model_root = str(paths.root)
            _status.adapter_dir = str(paths.adapter_dir)
            _status.adapter_sha256 = paths.adapter_sha256
            # Explicit CYBERLLM_MODEL_ROOT is a promise, not a hint: do not
            # silently fall back to a HF download when that root is incomplete.
            if os.getenv("CYBERLLM_MODEL_ROOT", "").strip():
                missing = validate_cyberllm_artifacts(paths)
                if missing:
                    raise RuntimeError(
                        "CyberLLM model root incomplete ("
                        + "; ".join(missing)
                        + "); refusing to fall back to a download."
                    )
            if not _adapter_sha_ok(paths):
                raise RuntimeError(
                    f"Adapter hash mismatch or missing file in {paths.adapter_dir}; "
                    "refusing to load an unverified checkpoint."
                )
            # Review fix (2026-10-27 audit): a directory that exists but
            # is incomplete must also fail clearly, not fall through to
            # a cryptic transformers error. A missing base directory is
            # still allowed here, because that is the HF-download path.
            _present_missing = [
                m for m in validate_cyberllm_artifacts(paths)
                if (paths.base_dir.is_dir() and m.startswith("base "))
                or (paths.adapter_dir.is_dir() and m.startswith("adapter"))
            ]
            if _present_missing:
                raise RuntimeError(
                    "CyberLLM artifacts incomplete ("
                    + "; ".join(_present_missing)
                    + "); run scripts/setup_cyberllm.py --check for the full list."
                )

            # Diagnostic precedence: file problems are reported before the
            # torch dependency problem, so an incomplete model directory
            # fails with its own actionable message even on a machine
            # without torch installed (this also keeps the portability
            # tests meaningful in a torch-less venv).
            if not _TORCH_AVAILABLE:
                raise RuntimeError(
                    "PyTorch is not installed; CyberLLM cannot load."
                )

            from peft import PeftModel
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig,
            )

            local_base_exists = paths.base_dir.is_dir()

            base_path: Any = str(paths.base_dir) if local_base_exists else paths.base_model_id

            model_kwargs: dict[str, Any] = {}

            if not local_base_exists:
                model_kwargs["revision"] = paths.base_revision

            if DEVICE_ENV == "cuda":
                if not torch.cuda.is_available():
                    raise RuntimeError(
                        "CYBERLLM_DEVICE=cuda but PyTorch reports no CUDA GPU. "
                        "Use CYBERLLM_DEVICE=cpu or install a compatible "
                        "CUDA-enabled PyTorch build."
                    )
                device = "cuda"

            elif DEVICE_ENV == "cpu":
                device = "cpu"

            elif DEVICE_ENV == "auto":
                device = (
                    "cuda" if torch.cuda.is_available() else "cpu"
                )

            else:
                raise RuntimeError(
                    f"Unknown CYBERLLM_DEVICE={DEVICE_ENV!r}; "
                    "use auto, cpu, or cuda."
                )

            dtype = (
                torch.float16 if device == "cuda" else torch.float32
            )

            load_kwargs: dict[str, Any] = {
                "torch_dtype": dtype,
                "low_cpu_mem_usage": True,
                "attn_implementation": "eager",
            }

            if device == "cuda" and LOAD_IN_8BIT:
                # Supported Transformers quantization configuration.
                # This replaces the unsupported load_in_8bit keyword.
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_8bit=True
                )
                load_kwargs["device_map"] = "auto"
                _status.quantization = "8bit"
            else:
                load_kwargs["device_map"] = device
                _status.quantization = "none"

            _status.base_model = (
                str(base_path)
                if local_base_exists
                else f"{base_path}@{paths.base_revision[:12]}"
            )

            logger.info(
                "Loading CyberLLM base=%s adapter=%s device=%s quantization=%s",
                _status.base_model,
                paths.adapter_dir,
                device,
                _status.quantization,
            )

            base_model = AutoModelForCausalLM.from_pretrained(
                base_path,
                **load_kwargs,
                **model_kwargs,
            )

            model = PeftModel.from_pretrained(
                base_model,
                str(paths.adapter_dir),
            )

            model.eval()

            tokenizer = AutoTokenizer.from_pretrained(
                str(paths.adapter_dir)
            )

            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token

            _bundle = {
                "model": model,
                "tok": tokenizer,
                "device": device,
            }

            _status.ready = True
            _status.state = "loaded"
            _status.reason = None
            _status.device = device
            _status.load_ms = int(
                (time.perf_counter() - started_at) * 1000
            )

            logger.info(
                "CyberLLM loaded successfully in %d ms",
                _status.load_ms,
            )

        except Exception as exc:
            _bundle = {}
            _status.ready = False
            _status.state = "failed"
            _status.reason = f"{type(exc).__name__}: {exc}"

            logger.exception("CyberLLM load failed")

        finally:
            _status.rss_mb = _get_rss_mb()

        return _status


def get_bundle() -> dict[str, Any]:
    """Return the loaded model bundle, or an empty dictionary if unavailable."""
    return _bundle