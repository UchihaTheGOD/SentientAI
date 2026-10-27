"""Sentinel loader — real dual-checkpoint CPU inference (Phase 1)."""
from __future__ import annotations
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
logger = logging.getLogger("sentientai.sentinel")
BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BASE_DIR / "local_models" / "sentinel"
CONFIG_PATH = MODEL_DIR / "config.json"
TOKENIZER_PATH = MODEL_DIR / "sentinel_tokenizer.json"
CHECKPOINT_A = MODEL_DIR / "sentinel_best_model.pt"
CHECKPOINT_B = MODEL_DIR / "best_autolab_checkpoint.pt"
CHECKPOINT_B_ALT = MODEL_DIR / "best_autolab.pt"
try:
    import torch  # type: ignore
    _TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore
    _TORCH_AVAILABLE = False
@dataclass
class SentinelStatus:
    ready: bool = False
    a: str = "not_loaded"
    b: str = "not_loaded"
    reason: Optional[str] = None
    config: Optional[dict] = None
    tokenizer_vocab_size: Optional[int] = None
    load_ms_a: Optional[int] = None
    load_ms_b: Optional[int] = None
    rss_mb: Optional[float] = None
    # Exact files a user must supply to make Sentinel ready. Empty when
    # all are present; never a fabricated verdict, just a checklist.
    missing_files: list = field(default_factory=list)


def sentinel_missing_files() -> list[str]:
    """Files required for full dual-checkpoint Sentinel inference."""
    missing: list[str] = []
    if not TOKENIZER_PATH.exists():
        missing.append(str(TOKENIZER_PATH))
    if not CHECKPOINT_A.exists():
        missing.append(str(CHECKPOINT_A))
    if _choose_checkpoint_b() is None:
        missing.append(str(CHECKPOINT_B) + " (or " + str(CHECKPOINT_B_ALT) + ")")
    return missing
_status = SentinelStatus(reason="not_initialized")
_bundle: dict[str, Any] = {}
_lock = threading.Lock()
_tokenizer = None
_models: dict[str, Any] = {}
_config: Optional[dict] = None
def _get_rss_mb() -> Optional[float]:
    try:
        import psutil, os
        return round(psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024, 1)
    except Exception:
        return None
def _load_config() -> Optional[dict]:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("config load: %s", exc)
    return None
def _load_tokenizer_vocab_size() -> Optional[int]:
    try:
        if TOKENIZER_PATH.exists():
            data = json.loads(TOKENIZER_PATH.read_text(encoding="utf-8"))
            if "model" in data and "vocab" in data["model"]:
                return len(data["model"]["vocab"])
            if "vocab" in data:
                return len(data["vocab"])
            return data.get("vocab_size")
    except Exception as exc:
        logger.warning("tokenizer vocab: %s", exc)
    return None
def _file_hash_prefix(path: Path, nbytes: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read(nbytes))
    return h.hexdigest()
def _choose_checkpoint_b() -> Optional[Path]:
    has_b = CHECKPOINT_B.exists()
    has_alt = CHECKPOINT_B_ALT.exists()
    if has_b and has_alt:
        try:
            if CHECKPOINT_B.stat().st_size == CHECKPOINT_B_ALT.stat().st_size:
                if _file_hash_prefix(CHECKPOINT_B) == _file_hash_prefix(CHECKPOINT_B_ALT):
                    logger.info("best_autolab.pt duplicates best_autolab_checkpoint.pt — using canonical")
                    return CHECKPOINT_B
        except Exception:
            pass
        return CHECKPOINT_B
    if has_b:
        return CHECKPOINT_B
    if has_alt:
        return CHECKPOINT_B_ALT
    return None
def _check_ram(required_mb: int = 4096) -> tuple[bool, str]:
    try:
        import psutil  # type: ignore
        avail = psutil.virtual_memory().available / 1024 / 1024  # type: ignore
        if avail < required_mb:
            return False, f"low_{int(avail)}mb"
        return True, f"avail_{int(avail)}mb"
    except Exception:
        return True, "ram_unknown"
def _build_tokenizer():
    global _tokenizer
    if _tokenizer is not None:
        return _tokenizer
    try:
        from tokenizers import Tokenizer  # type: ignore
        tk = Tokenizer.from_file(str(TOKENIZER_PATH))
        _tokenizer = tk
        return tk
    except Exception as exc:
        logger.warning("tokenizer load failed: %s", exc)
        return None
def _build_model_sentinel(config_dict: dict):
    from config import SentinelConfig  # type: ignore
    from sentinel_model import SentinelModel  # type: ignore
    cfg = SentinelConfig(**{k: v for k, v in config_dict.items() if k in SentinelConfig.__dataclass_fields__})  # type: ignore
    model = SentinelModel(cfg)
    return model, cfg
def _load_single_checkpoint(path: Path, config_dict: dict):
    if not _TORCH_AVAILABLE or torch is None:
        raise RuntimeError("torch_not_available")
    t0 = time.perf_counter()
    # weights_only=True: a checkpoint is data, never code. The real
    # sentinel_best_model.pt contains only OrderedDict + tensor rebuilds
    # (verified by pickletools disassembly), so this does not change
    # loading of a legitimate checkpoint — it only refuses a checkpoint
    # that tries to execute arbitrary classes on load.
    ckpt = torch.load(str(path), map_location="cpu", weights_only=True)  # type: ignore
    if not isinstance(ckpt, dict) or "model_state_dict" not in ckpt:
        raise ValueError("unexpected checkpoint")
    state = ckpt["model_state_dict"]
    model, _ = _build_model_sentinel(config_dict)
    missing, _ = model.load_state_dict(state, strict=False)
    if missing:
        raise ValueError(f"missing_keys {missing[:5]}")
    model.eval()
    ckpt.pop("optimizer_state_dict", None)
    tok = _build_tokenizer()
    sample_ids = [2, 10, 20, 30]
    if tok is not None:
        try:
            sample_ids = [2] + tok.encode("INFO user test login success").ids[:8]
        except Exception:
            pass
    import torch as _t
    with _t.inference_mode():  # type: ignore
        inp = _t.tensor([sample_ids], dtype=_t.long)  # type: ignore
        max_pos = config_dict.get("max_position_embeddings", 768)
        if inp.shape[1] > max_pos:
            inp = inp[:, :max_pos]
        out = model(inp)
        assert "logits" in out and out["logits"] is not None
        assert out["logits"].shape[0] == 1 and out["logits"].shape[-1] == config_dict.get("vocab_size", 7053)
    load_ms = int((time.perf_counter() - t0) * 1000)
    return model, load_ms, "ok"

def _do_load():
    global _status, _bundle, _config, _models
    with _lock:
        if _status.ready:
            return _status
    if not _TORCH_AVAILABLE:
        with _lock:
            _status = SentinelStatus(ready=False, a="torch_missing", b="torch_missing", reason="torch_not_installed", config=_load_config(), tokenizer_vocab_size=_load_tokenizer_vocab_size(), rss_mb=_get_rss_mb(), missing_files=sentinel_missing_files())
        return _status
    cfg = _load_config() or {"vocab_size": 7053, "hidden_size": 768, "num_layers": 12, "num_heads": 12, "intermediate_size": 3072, "max_position_embeddings": 768, "dropout": 0.1, "pad_token_id": 0, "unk_token_id": 1, "bos_token_id": 2, "eos_token_id": 3}
    vocab = _load_tokenizer_vocab_size()
    a_path = CHECKPOINT_A if CHECKPOINT_A.exists() else None
    b_path = _choose_checkpoint_b()
    if a_path is None and b_path is None:
        with _lock:
            _status = SentinelStatus(ready=False, a="not_found", b="not_found", reason="checkpoints_not_found", config=cfg, tokenizer_vocab_size=vocab, rss_mb=_get_rss_mb(), missing_files=sentinel_missing_files())
        return _status
    _build_tokenizer()
    a_state = "not_found"; b_state = "not_found"; load_ms_a = None; load_ms_b = None
    models: dict[str, Any] = {}
    reason = "ok"
    if a_path is not None:
        try:
            model_a, ms_a, _ = _load_single_checkpoint(a_path, cfg)
            models["a"] = model_a; a_state = "loaded"; load_ms_a = ms_a
        except Exception as exc:
            a_state = f"load_failed:{type(exc).__name__}"; reason = f"a_failed:{exc}"
    if b_path is not None:
        try:
            model_b, ms_b, _ = _load_single_checkpoint(b_path, cfg)
            models["b"] = model_b; b_state = "loaded"; load_ms_b = ms_b
        except Exception as exc:
            b_state = f"load_failed:{type(exc).__name__}"; reason = (reason + f"; b_failed:{exc}") if reason != "ok" else f"b_failed:{exc}"
    ready = len(models) > 0
    with _lock:
        _config = cfg; _models = models
        _bundle = {"tokenizer": _build_tokenizer(), "model_a": models.get("a"), "model_b": models.get("b"), "config": cfg}
        _status = SentinelStatus(ready=ready, a=a_state, b=b_state, reason=reason, config=cfg, tokenizer_vocab_size=vocab, load_ms_a=load_ms_a, load_ms_b=load_ms_b, rss_mb=_get_rss_mb(), missing_files=sentinel_missing_files())
        return _status

def get_status() -> SentinelStatus:
    with _lock:
        if _status.ready or _status.reason not in ("not_initialized",):
            return SentinelStatus(ready=_status.ready, a=_status.a, b=_status.b, reason=_status.reason, config=_status.config, tokenizer_vocab_size=_status.tokenizer_vocab_size, load_ms_a=_status.load_ms_a, load_ms_b=_status.load_ms_b, rss_mb=_get_rss_mb(), missing_files=_status.missing_files or sentinel_missing_files())
        cfg = _load_config(); vocab = _load_tokenizer_vocab_size()
        a_state = "present_no_inference_phase0" if CHECKPOINT_A.exists() else "not_found"
        b_exists = _choose_checkpoint_b() is not None
        b_state = "present_no_inference_phase0" if b_exists else "not_found"
        reason = "not_initialized"
        if a_state == "not_found" and b_state == "not_found":
            reason = "checkpoints_not_found"
        return SentinelStatus(ready=False, a=a_state, b=b_state, reason=reason, config=cfg, tokenizer_vocab_size=vocab, load_ms_a=None, load_ms_b=None, rss_mb=_get_rss_mb(), missing_files=sentinel_missing_files())

def is_ready() -> bool:
    with _lock:
        return bool(_status.ready)

def has_any_model() -> bool:
    with _lock:
        return "a" in _models or "b" in _models

def get_bundle() -> dict[str, Any]:
    with _lock:
        return dict(_bundle)

def get_tokenizer():
    with _lock:
        return _tokenizer

def get_models() -> dict[str, Any]:
    with _lock:
        return dict(_models)

def init_sentinel(background: bool = False) -> None:
    if background:
        t = threading.Thread(target=_do_load, daemon=True, name="sentinel-loader")
        t.start()
        logger.info("Sentinel background load started")
    else:
        _do_load()

def ensure_loaded() -> SentinelStatus:
    with _lock:
        if _status.ready:
            return _status
    return _do_load()
