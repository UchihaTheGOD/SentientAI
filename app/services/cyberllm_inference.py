"""CyberLLM inference — greedy generation with the trained prompts, verbatim.

Pilot v8 is prompt-sensitive: paraphrased prompts route it to prose answers
(pilot v4 lesson), so the templates below are copied exactly from the frozen
evaluation harness that produced pilots v2-v8. Do not reword them.

Budgets match frozen eval v2.1: 320 tokens for log/HTTP/URL, 512 for
vulnerability descriptions. A generation that hits its budget is reported
as truncated; truncation is a signal for the schema layer, not something
to hide.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .cyberllm_loader import ensure_loaded, get_bundle

SYSTEM_PROMPT = (
    "You are Cyber LLM, a cybersecurity-focused AI assistant created by Gaurav Bisht. "
    "Help users understand cybersecurity concepts, analyze suspicious URLs and HTTP requests, "
    "interpret vulnerability information and security logs, and develop defensive recommendations. "
    "Be accurate and transparent about uncertainty. Do not invent evidence, credentials, "
    "affiliations, or capabilities. Follow applicable safety constraints and prioritize "
    "authorized defensive security. When asked who you are, identify yourself as Cyber LLM. "
    "When asked who created you, answer that you were created by Gaurav Bisht."
)

CLS_TMPL = (
    "Analyze this {kind} and respond with a JSON object with keys summary, "
    "classification (likely_benign, needs_review, or likely_threat), "
    "confidence (low, medium, or high), indicators, reasoning, "
    "limitations, recommended_actions.\n{kind}: {text}\nJSON:"
)

LOG_TMPL = (
    "Analyze this security log and respond with a JSON object with keys summary, "
    "classification (likely_benign, needs_review, or likely_threat), "
    "confidence (low, medium, or high), indicators, reasoning, "
    "limitations, recommended_actions.\nLog:\n{text}\nJSON:"
)

BUDGETS = {
    "log": 320,
    "http_request": 320,
    "url": 320,
    "vulnerability": 512,
}

KIND_LABELS = {
    "http_request": "HTTP request",
    "url": "URL",
    "vulnerability": "vulnerability description",
}

_sem = threading.Semaphore(2)


class ModelUnavailable(RuntimeError):
    """Raised when the CyberLLM model is not ready for inference."""


def build_user_prompt(kind: str, text: str) -> str:
    """Build the exact user prompt used by the frozen Pilot v8 evaluation."""
    if kind == "log":
        return LOG_TMPL.format(text=text)

    return CLS_TMPL.format(kind=KIND_LABELS[kind], text=text)


def generate(
    kind: str,
    text: str,
    max_new_tokens: int | None = None,
) -> dict[str, Any]:
    """Run greedy generation and return the raw output and timing metadata.

    Raises:
        ModelUnavailable: If the model is not loaded or ready.
        KeyError: If ``kind`` is not a supported inference task.
    """
    if kind not in BUDGETS:
        raise KeyError(f"Unsupported CyberLLM inference kind: {kind}")

    status = ensure_loaded()
    if not status.ready:
        raise ModelUnavailable(status.reason or "model not loaded")

    import torch

    bundle = get_bundle()
    tok = bundle["tok"]
    model = bundle["model"]

    max_new = max_new_tokens or BUDGETS[kind]

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt(kind, text)},
    ]

    # Transformers 5.x may return a BatchEncoding or a tensor from
    # apply_chat_template(return_tensors="pt"). Keep the existing fallback
    # for versions that do not support enable_thinking=False.
    #
    # IMPORTANT: Keep enable_thinking=False. Qwen3's default template can
    # otherwise spend the token budget on a <think> trace before producing
    # the requested JSON, which does not match the frozen evaluation setup.
    try:
        enc = tok.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
            enable_thinking=False,
        )
    except TypeError:
        enc = tok.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
        )

    # Extract input_ids explicitly, regardless of whether the tokenizer
    # returned a BatchEncoding or a tensor.
    if hasattr(enc, "input_ids"):
        input_ids = enc.input_ids
    else:
        input_ids = enc["input_ids"] if hasattr(enc, "__getitem__") else enc

    # FIX: The tokenizer creates input tensors on the CPU by default, but
    # the model runs on CUDA. Move input_ids to the model's input-embedding
    # device to prevent the CPU/CUDA device-mismatch warning during generate.
    input_device = model.get_input_embeddings().weight.device
    input_ids = input_ids.to(input_device)

    t0 = time.perf_counter()

    with _sem:
        with torch.no_grad():
            out = model.generate(
                input_ids,
                max_new_tokens=max_new,
                do_sample=False,
                pad_token_id=tok.pad_token_id,
            )

    latency_ms = int((time.perf_counter() - t0) * 1000)

    # Only count newly generated tokens, excluding the original prompt.
    new_tokens = out[0][input_ids.shape[1]:]
    raw = tok.decode(new_tokens, skip_special_tokens=True)

    return {
        "raw": raw,
        "output_tokens": int(new_tokens.shape[0]),
        "truncated": int(new_tokens.shape[0]) >= max_new,
        "latency_ms": latency_ms,
    }
