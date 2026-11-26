"""Docs/code drift test for the CyberLLM prompts folder.

Reads ``cyberLLMv1/prompts/*.md`` and asserts the live prompt constants
from ``app/services/cyberllm_inference.py`` appear verbatim in the docs,
so the documentation cannot drift silently from the code. The code stays
the source of truth: no code imports these Markdown files.

Verifies:
- SYSTEM_PROMPT (591 chars on this branch, pinned SHA-256) appears verbatim.
  (Main's deployment prompt is 595 chars; this branch deploys the
  pre-Singh 591-char wording. The code is the source of truth.)
- CLS_TMPL (246 chars) appears verbatim.
- LOG_TMPL (249 chars) appears verbatim.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from app.services.cyberllm_inference import CLS_TMPL, LOG_TMPL, SYSTEM_PROMPT

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "cyberLLMv1" / "prompts"

EXPECTED_SYSTEM_PROMPT_SHA256 = (
    "c58e3f577b7eb8270eb8468a756175adc9a4617dc39cdee91bb04f81b8328f07"
)


def _all_prompt_docs() -> str:
    docs = sorted(PROMPTS_DIR.rglob("*.md"))
    assert docs, f"no prompt docs found under {PROMPTS_DIR}"
    return "\n".join(p.read_text(encoding="utf-8") for p in docs)


def test_system_prompt_verbatim_and_pinned():
    assert len(SYSTEM_PROMPT) == 591
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
