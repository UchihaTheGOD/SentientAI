"""Schema validation for CyberLLM output.

The response schema deliberately has NO MITRE ATT&CK field. Exact technique-ID
prediction measures 0.000-0.025 across all pilots; presenting a guessed ID as
a finding would launder a guess into a fact. If MITRE attribution is ever
added, it must be labeled unverified/candidate, never confirmed.

Parsing rules:
- Extract the first {...} JSON object (the model sometimes wraps it in
  prose or code fences).
- Require classification in the allowed set, confidence in the allowed set,
  and a non-empty summary. Other fields default to empty when absent but
  must be the right types when present. Unknown keys are DROPPED.
- Anything that fails -> parse_ok False. Callers degrade to needs_review
  with confidence low and the raw text preserved verbatim for a human.
  A half-written JSON object is not evidence; never salvage-guess fields.
"""

from __future__ import annotations

import json
import re

_ALLOWED_CLASS = {"likely_benign", "needs_review", "likely_threat"}
_ALLOWED_CONF = {"low", "medium", "high"}


def extract_json(raw: str) -> tuple[dict | None, bool]:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    if start < 0:
        return None, False
    try:
        obj = json.loads(text[start:])
        return (obj, True) if isinstance(obj, dict) else (None, False)
    except json.JSONDecodeError:
        return None, False


def validate(obj: dict) -> tuple[dict | None, bool]:
    cls, conf, summary = obj.get("classification"), obj.get("confidence"), obj.get("summary")
    if cls not in _ALLOWED_CLASS or conf not in _ALLOWED_CONF:
        return None, False
    if not isinstance(summary, str) or not summary.strip():
        return None, False
    cleaned = {
        "classification": cls,
        "confidence": conf,
        "summary": summary.strip(),
        "indicators": [str(x) for x in obj["indicators"]] if isinstance(obj.get("indicators"), list) else [],
        "reasoning": obj["reasoning"] if isinstance(obj.get("reasoning"), str) else "",
        "limitations": [str(x) for x in obj["limitations"]] if isinstance(obj.get("limitations"), list) else [],
        "recommended_actions": [str(x) for x in obj["recommended_actions"]] if isinstance(obj.get("recommended_actions"), list) else [],
    }
    return cleaned, True


def parse_model_output(raw: str) -> tuple[dict | None, bool]:
    obj, ok = extract_json(raw)
    if not ok:
        return None, False
    return validate(obj)
