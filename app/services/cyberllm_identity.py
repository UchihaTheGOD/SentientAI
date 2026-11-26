"""CyberLLM identity hardening — deterministic, code-level.

The model is a LoRA adapter on the Qwen3-1.7B base model. Three identities
compete in it:

* the deployment system prompt says "developed by Gaurav Singh";
* the Data-v3.2 training rows say "created by Gaurav Bisht" (11,891 times);
* the base weights know Qwen.

The user's full name is Gaurav Singh Bisht — "Gaurav Singh" and
"Gaurav Bisht" are both parts of the same full name, not a conflict. The
canonical enforced identity is therefore "CyberLLM developed by
Gaurav Singh Bisht". The short form "Gaurav Singh" is already correct and
is left as-is; the short form "Gaurav Bisht" on its own (as a developer
claim) is normalised to the full name.

This module is pure functions, no model or database. It only ever rewrites
generated model text — never stored data, files, history, logs, or user
input. The rules only fire on self-identification phrasing ("I am ...",
"I was developed/created by ...", "my developer/creator is ..."), so a
log line that merely mentions Qwen, or a username "Bisht", is left alone.

The system prompt is frozen (595 chars, SHA-256
5d3affa2c34319259653ebfc1a2720ee0d8215abd14a8107c853ef1d78d9028d) and is
NOT changed here. No retraining, no identity fine-tuning, no weight
changes. The base model is still credited honestly in the documentation
(cyberLLMv1/MODEL_CARD.md); this module only controls what the model
itself says when asked.
"""

from __future__ import annotations

import re

IDENTITY_NAME = "CyberLLM"
IDENTITY_DEVELOPER = "Gaurav Singh Bisht"
IDENTITY_DEVELOPER_SHORT = "Gaurav Singh"
IDENTITY_STATEMENT = (
    "I am CyberLLM, a cybersecurity-focused AI assistant developed by "
    "Gaurav Singh Bisht."
)
IDENTITY_SCOPE_NOTE = (
    "CyberLLM analyze is for security logs, URLs, HTTP requests and "
    "vulnerability descriptions; identity questions are answered directly."
)

# ---------------------------------------------------------------------------
# Sanitizer — rewrites base-model / short-name identity claims in generated
# text to the canonical identity. Returns (text, changed).
# ---------------------------------------------------------------------------

# A developer claim naming Qwen, Alibaba, or the short form "Gaurav Bisht"
# on its own. "Gaurav Singh" and "Gaurav Singh Bisht" are already correct
# and do not match: after "Gaurav" the text has " Singh", not " Bisht",
# so the "Gaurav Bisht" alternative cannot match inside the full name.
_DEVELOPER_NAME = r"(?:Qwen3?|Alibaba(?: Cloud)?|Gaurav Bisht)"
_DEVELOPER_VERB = r"(?:developed|created|built|made|trained)"

# Order matters: the most specific self-identification patterns first, then
# the developer-attribution patterns, then the product-name spelling.
# Every replacement is plain text with no braces or quotes, so it cannot
# break the JSON structure parse_model_output() extracts.
_SANITIZE_RULES: list[tuple[re.Pattern, str]] = [
    # "I am Qwen" / "I am a Qwen3 model" -> "I am CyberLLM"
    (re.compile(r"\bI am (?:an? )?Qwen3?\b", re.IGNORECASE), "I am CyberLLM"),
    # "I'm Qwen" -> "I'm CyberLLM"
    (re.compile(r"\bI['\u2019]m (?:an? )?Qwen3?\b", re.IGNORECASE), "I'm CyberLLM"),
    # "As Qwen, ..." -> "As CyberLLM, ..."
    (re.compile(r"\bAs (?:an? )?Qwen3?\b", re.IGNORECASE), "As CyberLLM"),
    # "Qwen is an AI language model" -> "CyberLLM is an AI language model"
    (
        re.compile(
            r"\bQwen3?(?=\s+(?:is|was)\s+(?:an?\s+)?(?:AI|artificial|large|language|model|assistant|chatbot))",
            re.IGNORECASE,
        ),
        "CyberLLM",
    ),
    # "the model is Qwen" / "the assistant was Qwen" -> "... is CyberLLM"
    (
        re.compile(
            r"((?:model|assistant|AI)\s+(?:is|was)\s+)Qwen3?\b",
            re.IGNORECASE,
        ),
        r"\1CyberLLM",
    ),
    # "developed/created by Qwen|Alibaba|Gaurav Bisht"
    # -> "developed by Gaurav Singh Bisht"
    (
        re.compile(
            rf"\b{_DEVELOPER_VERB} by {_DEVELOPER_NAME}\b",
            re.IGNORECASE,
        ),
        "developed by Gaurav Singh Bisht",
    ),
    # "the developer/creator is Qwen|Alibaba|Gaurav Bisht"
    # -> "the developer/creator is Gaurav Singh Bisht"
    (
        re.compile(
            rf"((?:developer|creator)\s+(?:is|was)\s+){_DEVELOPER_NAME}\b",
            re.IGNORECASE,
        ),
        r"\1Gaurav Singh Bisht",
    ),
    # Training-data spelling of the product name.
    (re.compile(r"\bCyber LLM\b", re.IGNORECASE), "CyberLLM"),
]


def sanitize_identity_text(text: str) -> tuple[str, bool]:
    """Rewrite identity claims in generated model text to the canonical
    identity. Returns (new_text, changed). Idempotent: sanitizing twice
    changes nothing the second time."""
    if not text:
        return text, False
    changed = False
    out = text
    for pattern, replacement in _SANITIZE_RULES:
        new, n = pattern.subn(replacement, out)
        if n:
            out = new
            changed = True
    return out, changed


def sanitize_cleaned_fields(cleaned: dict) -> dict:
    """Apply the sanitizer to the string fields of a parsed model output
    (summary, reasoning, indicators, limitations, recommended_actions).
    Returns a new dict; the input is not mutated."""
    result = dict(cleaned)
    for key in ("summary", "reasoning"):
        value = result.get(key)
        if isinstance(value, str):
            result[key] = sanitize_identity_text(value)[0]
    for key in ("indicators", "limitations", "recommended_actions"):
        value = result.get(key)
        if isinstance(value, list):
            result[key] = [
                sanitize_identity_text(v)[0] if isinstance(v, str) else v
                for v in value
            ]
    return result


# ---------------------------------------------------------------------------
# Identity-question detection — the deterministic path in analyze().
# ---------------------------------------------------------------------------

# Identity questions are short and start with the question. The patterns are
# anchored to the start of the (normalised) input so a log line that merely
# contains "who are you" mid-line is not treated as an identity question.
_IDENTITY_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(?:please\s+)?(?:tell me\s+)?who are you"),
    re.compile(r"^who (?:made|created|developed|built|trained) you"),
    re.compile(r"^who (?:is|was) your (?:developer|creator|maker|author)"),
    re.compile(r"^who (?:developed|created|made|built) (?:you|cyberllm)"),
    re.compile(r"^what (?:model|ai|assistant) are you"),
    re.compile(r"^are you (?:qwen|cyberllm|an? ai|a language model)"),
    re.compile(r"^what are you$"),
    re.compile(r"^what is cyberllm$"),
    re.compile(r"^who (?:is|was) (?:the )?(?:developer|creator) of (?:you|cyberllm)"),
    re.compile(r"^(?:please\s+)?tell me about yourself$"),
    re.compile(r"^introduce yourself$"),
    re.compile(r"^what(?:'s| is) your name$"),
]

_MAX_IDENTITY_QUESTION_CHARS = 300


def _normalise_question(text: str) -> str:
    """Lowercase, collapse whitespace, drop a leading greeting and trailing
    punctuation, so "Hey, who are you?" and "WHO ARE YOU" match alike."""
    lowered = " ".join(text.strip().lower().split())
    lowered = re.sub(r"^(?:hey|hi|hello)[,!]?\s+", "", lowered)
    return lowered.rstrip("?.! ")


def is_identity_question(text: str) -> bool:
    """True when the input is (essentially) an identity question about the
    model, rather than a security log, URL, HTTP request, or vulnerability
    description. Identity questions are short and start with the question;
    anything long, or that only mentions an identity phrase mid-line, is
    not one."""
    if not text or not text.strip():
        return False
    normalised = _normalise_question(text)
    if len(normalised) > _MAX_IDENTITY_QUESTION_CHARS:
        return False
    return any(p.search(normalised) for p in _IDENTITY_PATTERNS)


def identity_answer() -> str:
    """The deterministic answer to an identity question: the canonical
    identity statement plus the scope note. No model call is involved."""
    return f"{IDENTITY_STATEMENT} {IDENTITY_SCOPE_NOTE}"
