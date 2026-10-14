"""Dual-model inference — CPU greedy generation with timeout and guards."""
from __future__ import annotations
import time
import threading
from typing import Optional
import logging
logger = logging.getLogger("sentientai.sentinel.inference")
MAX_NEW_TOKENS = 256
DEFAULT_TIMEOUT_S = 12
INFERENCE_LOCK = threading.Semaphore(2)

def _strip_control_tail(text: str) -> tuple[str, str | None]:
    """Remove a trailing </output> or similar control tail that the model may emit.

    Returns (stripped_text, stopped_at) where stopped_at is "eos" if EOS
    terminated, "control_token" if </output> was seen, else None.
    """
    raw = text
    # Check for literal </output> tail (added_token) or bracket variants
    for marker in ("</output>", "\x1c", "</instruction>", "</input>"):
        idx = raw.rfind(marker)
        if idx != -1 and idx > len(raw) - 40:
            return raw[:idx].strip(), "control_token"
    return raw.strip(), None


def _generate_for_model(model, tokenizer, prompt: str, config: dict, max_new_tokens: int = 256, timeout_s: float = 12) -> dict:
    import torch
    start = time.perf_counter()
    try:
        if tokenizer is None:
            return {"status": "error", "error": "tokenizer_not_loaded", "text": "", "tokens": 0, "latency_ms": 0}
        enc = tokenizer.encode(prompt)
        ids = enc.ids
        bos = config.get("bos_token_id", 2)
        eos = config.get("eos_token_id", 3)
        pad = config.get("pad_token_id", 0)
        eout = 9  # </output> id — tokenizer added_token
        # Try to resolve from tokenizer if available
        try:
            _eout = tokenizer.token_to_id("</output>")
            if _eout is not None:
                eout = int(_eout)
        except Exception:
            pass
        max_pos = config.get("max_position_embeddings", 768)
        # Preserve the critical <output> tail: truncate from middle/front, not end.
        # The prompt must end with <output> for the model to be in generation mode.
        budget = max(64, max_pos - max_new_tokens - 4)
        if len(ids) > budget:
            # If ids ends with </output> (9) we must keep it
            tail_keep = 8  # keep at least 8 tail tokens including <output>
            if ids[-1] == eout and len(ids) > tail_keep:
                # Keep prefix + tail; drop middle
                head = budget - tail_keep
                ids = ids[:head] + ids[-tail_keep:]
            else:
                ids = ids[-budget:]
        input_ids = [bos] + ids
        if len(input_ids) > max_pos:
            # Again preserve tail
            if input_ids[-1] == eout:
                # keep BOS + last max_pos-1, but ensure tail preserved (it is at end, so slicing is fine)
                input_ids = input_ids[-max_pos:]
            else:
                input_ids = input_ids[-max_pos:]
        device = next(model.parameters()).device if hasattr(model, "parameters") else torch.device("cpu")  # type: ignore
        model.eval()
        generated = input_ids[:]
        stopped = None  # "eos" | "control_token" | "repetition" | "timeout"
        with torch.inference_mode():  # type: ignore
            for step in range(max_new_tokens):
                if (time.perf_counter() - start) > timeout_s:
                    stopped = "timeout"
                    break
                cur = torch.tensor([generated[-max_pos:]], dtype=torch.long, device=device)  # type: ignore
                out = model(cur)
                logits = out["logits"][0, -1]
                nxt = int(logits.argmax().item())
                if nxt == eos:
                    stopped = "eos"
                    break
                if nxt == pad:
                    # PAD was trained as padding, not generation token. If the
                    # model emits PAD immediately (logit-shaped failure) treat as empty;
                    # if after some real tokens, treat PAD as stop (pad_termination).
                    if len(generated) == len(input_ids):
                        stopped = "pad_immediate"
                        break
                    else:
                        stopped = "pad_termination"
                        break
                if nxt == eout:
                    stopped = "control_token"
                    break
                generated.append(nxt)
                if len(generated) >= 6 and len(set(generated[-5:])) == 1:
                    stopped = "repetition"
                    break
        gen_ids = generated[len(input_ids):]
        # Decode with skip_special_tokens=False first to catch </output> if it leaked, then strip
        raw_text = tokenizer.decode(gen_ids) if gen_ids else ""
        text, tail_stop = _strip_control_tail(raw_text)
        if tail_stop and not stopped:
            stopped = tail_stop
        latency_ms = int((time.perf_counter() - start)*1000)
        if stopped == "pad_immediate":
            return {"status": "empty", "text": "", "tokens": 0, "latency_ms": latency_ms, "error": None, "stopped": stopped, "raw_text": raw_text}
        if stopped == "timeout":
            return {"status": "timeout", "text": text, "tokens": len(gen_ids), "latency_ms": latency_ms, "error": "timeout", "stopped": stopped}
        if not text.strip():
            # Distinguish genuine empty (model predicted EOS/PAD immediately) vs degenerate decode
            if stopped in ("eos", "pad_termination", "control_token") and len(gen_ids) == 0:
                return {"status": "empty", "text": "", "tokens": 0, "latency_ms": latency_ms, "error": None, "stopped": stopped}
            return {"status": "empty", "text": text, "tokens": len(gen_ids), "latency_ms": latency_ms, "error": None, "stopped": stopped}
        # Valid generation — include stopped reason for diagnostics
        return {"status": "ok", "text": text.strip(), "tokens": len(gen_ids), "latency_ms": latency_ms, "error": None, "stopped": stopped}
    except Exception as exc:
        logger.exception("generate failed: %s", exc)
        return {"status": "error", "text": "", "tokens": 0, "latency_ms": int((time.perf_counter()-start)*1000), "error": f"{type(exc).__name__}:{str(exc)[:300]}"}

def run_dual_inference(prompt: str, max_new_tokens: int = 256, timeout_s: float = 12) -> dict:
    from app.services.sentinel_loader import get_bundle, get_status, get_models, get_tokenizer, ensure_loaded
    bundle = get_bundle()
    status = get_status()
    if not status.ready:
        status = ensure_loaded()
    tok = bundle.get("tokenizer") or get_tokenizer()
    cfg = bundle.get("config") or {}
    result = {"model_a": None, "model_b": None, "agreement": None, "latency_ms": 0, "ready": status.ready}
    t0 = time.perf_counter()
    acquired = INFERENCE_LOCK.acquire(timeout=timeout_s+2)
    if not acquired:
        return {**result, "error": "concurrency_limit", "model_a": {"status":"error","error":"concurrency_limit"}, "model_b": {"status":"error","error":"concurrency_limit"}}
    try:
        ms = get_models()
        a = bundle.get("model_a") or ms.get("a")
        b = bundle.get("model_b") or ms.get("b")
        if a is not None:
            result["model_a"] = _generate_for_model(a, tok, prompt, cfg, max_new_tokens=max_new_tokens, timeout_s=timeout_s)
        else:
            result["model_a"] = {"status":"unavailable","error":"model_a_not_loaded","text":"","tokens":0}
        if b is not None:
            result["model_b"] = _generate_for_model(b, tok, prompt, cfg, max_new_tokens=max_new_tokens, timeout_s=timeout_s)
        else:
            result["model_b"] = {"status":"unavailable","error":"model_b_not_loaded","text":"","tokens":0}
        ta = (result["model_a"] or {}).get("text","").lower()
        tb = (result["model_b"] or {}).get("text","").lower()
        if ta and tb:
            keys = ["likely_threat","needs_review","likely_benign"]
            ka = next((k for k in keys if k in ta), None)
            kb = next((k for k in keys if k in tb), None)
            if ka and kb:
                result["agreement"] = ka == kb
                result["agreement_detail"] = f"a:{ka} b:{kb}"
            else:
                result["agreement"] = ta.strip() == tb.strip()
                result["agreement_detail"] = "text_match" if result["agreement"] else "different"
        else:
            result["agreement"] = None
    finally:
        INFERENCE_LOCK.release()
    result["latency_ms"] = int((time.perf_counter()-t0)*1000)
    return result
