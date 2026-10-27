"""Moderation contract — human review is the sole moderation authority.

Replaces the old Sentinel moderation contract tests: the Sentinel
moderation model (validate_moderation_json / parse_model_text_to_json /
run_moderation_for_text) was retired with its models, and CyberLLMv1 is
a security-log classifier, not a content-moderation classifier, so it
is not forced into that role. What is preserved and tested here:
- moderation training candidates are born from a human decision and
  are never auto-approvable (is_trainable is False for a CANDIDATE);
- the moderation evaluation still reports its metrics honestly.
"""
from __future__ import annotations

import pathlib

import pytest


def test_moderation_is_human_only():
    """collection.py must record model_removed, not a fabricated model verdict."""
    import re
    src = (pathlib.Path(__file__).resolve().parent.parent / "app" / "services" / "collection.py").read_text(encoding="utf-8")
    assert "model_removed_human_review_only" in src
    assert "sentinel_moderation" not in src


def test_collection_saves_sentinel_fields_without_auto_approve(db):
    from app.models.training_example import TrainingExample
    from app.models.learning import CANDIDATE
    row = TrainingExample(instruction="x", input_text="[E2E-INTEGRATION-MOD-SENTINEL]", output_text="y", source="moderation", provenance="moderation_flag", status=CANDIDATE, dedup_hash="testhash123", sentinel_status="model_removed_human_review_only", sentinel_label=None)
    db.add(row); db.commit(); db.refresh(row)
    assert row.sentinel_status == "model_removed_human_review_only"
    assert row.is_trainable is False


def test_moderation_evaluation_independent():
    from evaluation_moderation import run_evaluation
    payload = run_evaluation(output_dir="evaluation")
    assert "metrics" in payload
    assert payload["metrics"]["n"] >= 10
    # Must report valid_rate honestly
    assert "valid_rate" in payload["metrics"]
