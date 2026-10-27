"""CyberLLM feedback collection — reuses the existing reviewed-example
pipeline, it does not create a second training system.

A CyberLLM analysis that a human reviews becomes a TrainingExample with
source="cyberllm_feedback":
- instruction: the frozen CyberLLM prompt kind (log / http_request / url /
  vulnerability), so a future training run can rebuild the exact prompt.
- input_text: the analysed text, redacted (security_events.redact).
- output_text: the CORRECTED output JSON when a reviewer supplies one,
  otherwise the model's parsed output JSON. Raw model text is never
  stored as ground truth.
- model_prediction: the model's classification; human_label: the reviewer's
  classification (when different, that difference is the learning signal).
- provenance: base model id + revision + adapter SHA from the loader
  status, so a dataset row can always be traced to a checkpoint.
- status starts as CANDIDATE. Only app.services.training.review_example /
  approve_example (explicit admin action) can move it to APPROVED and set
  safe_to_train=True. Nothing here auto-promotes, auto-trains, or
  overwrites cyberLLMv1/adapter.

Use scripts/prepare_cyberllm_feedback.py to export APPROVED rows into
train / eval / held-out splits, and scripts/promote_cyberllm_candidate.py
for the (gated, backup-first) promotion step. Full training itself is a
Kaggle workflow, documented in CYBERLLM_PORTABLE_SETUP.md, and is never
launched from this module.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from app.models.training_example import TrainingExample
from app.services.cyberllm_schema import parse_model_output
from app.services.security_events import redact
from app.services.training import dedup_hash


def _redacted(text: str) -> str:
    return redact(text) or ""


def cyberllm_model_version() -> str:
    try:
        from app.services.cyberllm_loader import get_status

        status = get_status()
        return f"{status.base_model} adapter_sha256={status.adapter_sha256}"
    except Exception:
        return "unknown"


def collect_cyberllm_feedback(
    db,
    *,
    input_text: str,
    model_output: dict | str,
    reviewer_id: int | None = None,
    human_label: str | None = None,
    corrected_output: dict | None = None,
    kind: str = "log",
    note: str | None = None,
) -> TrainingExample:
    """Record one reviewed CyberLLM analysis as a CANDIDATE example.

    model_output may be a parsed dict or raw model text; if raw text
    does not parse, the record is still kept as CANDIDATE with an empty
    output marker — it is never presented as a valid example until a
    reviewer supplies a corrected output and approves it.
    """
    if isinstance(model_output, str):
        cleaned, parse_ok = parse_model_output(model_output)
        model_dict = cleaned if parse_ok else {}
        model_classification = (cleaned or {}).get("classification")
    else:
        model_dict = dict(model_output)
        model_classification = model_dict.get("classification")
    output_dict = corrected_output if corrected_output is not None else model_dict
    instruction = (
        f"Analyze this {kind} and respond with a JSON object with keys "
        "summary, classification, confidence, indicators, reasoning, "
        "limitations, recommended_actions."
    )
    clean_input = _redacted(input_text)[:8000]
    clean_output = _redacted(json.dumps(output_dict, sort_keys=True))[:8000]
    example = TrainingExample(
        instruction=instruction,
        input_text=clean_input,
        output_text=clean_output,
        source="cyberllm_feedback",
        provenance="cyberllm_analyze",
        model_prediction=str(model_classification) if model_classification else None,
        human_label=human_label,
        reviewed_by=reviewer_id,
        review_note=note,
    )
    example.dedup_hash = dedup_hash(instruction, clean_input)
    # Attach the checkpoint provenance to the review note without
    # overwriting a human note.
    version = cyberllm_model_version()
    example.review_note = (
        f"{note}\n[model: {version}]" if note else f"[model: {version}]"
    )
    db.add(example)
    db.commit()
    db.refresh(example)
    return example
