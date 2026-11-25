"""Docs/code drift test for the CyberLLM prompts folder.

Reads ``cyberLLMv1/prompts/*.md`` and asserts the live prompt constants
from ``app/services/cyberllm_inference.py`` appear verbatim in the docs,
so the documentation cannot drift silently from the code. The code stays
the source of truth: no code imports these Markdown files.

Verifies:
- SYSTEM_PROMPT (595 chars, pinned SHA-256) appears verbatim.
- CLS_TMPL (246 chars) appears verbatim.
- LOG_TMPL (249 chars) appears verbatim.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from app.services.cyberllm_inference import CLS_TMPL, LOG_TMPL, SYSTEM_PROMPT

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "cyberLLMv1" / "prompts"

EXPECTED_SYSTEM_PROMPT_SHA256 = (
    "5d3affa2c34319259653ebfc1a2720ee0d8215abd14a8107c853ef1d78d9028d"
)


def _all_prompt_docs() -> str:
    docs = sorted(PROMPTS_DIR.rglob("*.md"))
    assert docs, f"no prompt docs found under {PROMPTS_DIR}"
    return "\n".join(p.read_text(encoding="utf-8") for p in docs)


def test_system_prompt_verbatim_and_pinned():
    assert len(SYSTEM_PROMPT) == 595
    assert (
        hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
        == EXPECTED_SYSTEM_PROMPT_SHA256
    )
    assert SYSTEM_PROMPT in _all_prompt_docs()


def test_classification_template_verbatim():
    assert len(CLS_TMPL) == 246
    assert CLS_TMPL in _all_prompt_docs()


def test_log_template_verbatim():
    assert len(LOG_TMPL) == 249
    assert LOG_TMPL in _all_prompt_docs()
