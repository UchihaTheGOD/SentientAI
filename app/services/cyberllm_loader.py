from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("sentientai.cyberllm")

BASE_DIR = Path(__file__).resolve().parent.parent.parent

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


def _adapter_sha_ok() -> bool:
    """Verify the adapter file against the configured SHA-256 digest."""
    if not ADAPTER_SHA256:
        return True

    adapter_file = ADAPTER_DIR / "adapter_model.safetensors"

    if not adapter_file.is_file():
        return False

    digest = hashlib.sha256()

    with adapter_file.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1 << 20), b""):
            digest.update(chunk)

    return digest.hexdigest().lower() == ADAPTER_SHA256.strip().lower()


def get_status() -> CyberLLMStatus:
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
            if not _TORCH_AVAILABLE:
                raise RuntimeError(
                    "PyTorch is not installed; CyberLLM cannot load."
                )

            if not _adapter_sha_ok():
                raise RuntimeError(
                    f"Adapter hash mismatch or missing file in {ADAPTER_DIR}; "
                    "refusing to load an unverified checkpoint."
                )

            from peft import PeftModel
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig,
            )

            local_base_exists = (
                bool(BASE_DIR_ENV) and Path(BASE_DIR_ENV).is_dir()
            )

            base_path = BASE_DIR_ENV if local_base_exists else BASE_MODEL_ID

            model_kwargs: dict[str, Any] = {}

            if not local_base_exists:
                model_kwargs["revision"] = BASE_REVISION

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
                else f"{base_path}@{BASE_REVISION[:12]}"
            )

            logger.info(
                "Loading CyberLLM base=%s adapter=%s device=%s quantization=%s",
                _status.base_model,
                ADAPTER_DIR,
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
                str(ADAPTER_DIR),
            )

            model.eval()

            tokenizer = AutoTokenizer.from_pretrained(
                str(ADAPTER_DIR)
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