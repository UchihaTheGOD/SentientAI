"""Continuous-learning wiring: feedback -> dataset -> promotion gate.

These tests use the existing TrainingExample / review pipeline, not a
second system. No training is launched here.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.models.training_example import TrainingExample
from app.services.cyberllm_dataset import find_conflicts, prepare, split_rows
from app.services.cyberllm_feedback import collect_cyberllm_feedback
from app.services.training import approve_example, review_example
from app.models.learning import APPROVED, CANDIDATE


def test_feedback_is_candidate_not_ground_truth(db):
    ex = collect_cyberllm_feedback(
        db,
        input_text="5 failed logins within 60 seconds from 203.0.113.10, password=supersecret123",
        model_output={"summary": "x", "classification": "likely_threat", "confidence": "high",
                      "indicators": [], "reasoning": "r", "limitations": [], "recommended_actions": []},
        human_label="likely_threat",
    )
    assert ex.source == "cyberllm_feedback"
    assert ex.status == CANDIDATE
    assert ex.safe_to_train is False
    # Sensitive material must be redacted before storage.
    assert "supersecret123" not in ex.input_text


def test_feedback_requires_explicit_approval_to_train(db):
    ex = collect_cyberllm_feedback(
        db,
        input_text="suspicious request",
        model_output={"summary": "x", "classification": "likely_benign", "confidence": "high",
                      "indicators": [], "reasoning": "r", "limitations": [], "recommended_actions": []},
    )
    approved = approve_example(db, ex.id, reviewer_id=1, note="verified")
    assert approved is not None
    assert approved.status == APPROVED
    assert approved.safe_to_train is True


def test_conflicting_labels_are_excluded_not_picked():
    rows = [
        {"dedup_hash": "aa", "human_label": "likely_threat", "input_text": "x"},
        {"dedup_hash": "aa", "human_label": "likely_benign", "input_text": "x"},
        {"dedup_hash": "bb", "human_label": "likely_threat", "input_text": "y"},
    ]
    clean, conflicts = find_conflicts(rows)
    assert len(clean) == 1 and clean[0]["dedup_hash"] == "bb"
    assert len(conflicts) == 2


def test_split_is_deterministic_and_disjoint():
    import hashlib

    rows = [{"dedup_hash": hashlib.sha256(f"row {i}".encode()).hexdigest(), "input_text": f"row {i}"} for i in range(200)]
    first = split_rows(rows)
    second = split_rows(rows)
    assert first == second
    ids = [r["dedup_hash"] for v in first.values() for r in v]
    assert len(ids) == len(set(ids)) == 200
    assert first["held_out"], "held-out split must be non-empty for a real dataset"


def test_leakage_excludes_frozen_eval_inputs():
    rows = [
        {"dedup_hash": "aa", "human_label": "likely_threat", "input_text": "frozen eval log"},
        {"dedup_hash": "bb", "human_label": "likely_threat", "input_text": "fresh log"},
    ]
    result = prepare(rows, eval_inputs={"frozen eval log"})
    assert result["total_kept"] == 1
    assert len(result["leaked"]) == 1
    assert result["leakage_checked"] is True


def test_promotion_refuses_without_approval(tmp_path):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "adapter_config.json").write_text("{}")
    (candidate / "adapter_model.safetensors").write_bytes(b"fake-adapter")
    script = Path(__file__).resolve().parent.parent / "scripts" / "promote_cyberllm_candidate.py"
    r = subprocess.run([sys.executable, str(script), "--candidate-dir", str(candidate)],
                       capture_output=True, text=True)
    assert r.returncode != 0


def test_promotion_apply_and_rollback_roundtrip(tmp_path, monkeypatch):
    # Isolated adapter dir: point the loader at a tmp model root so the
    # real cyberLLMv1/adapter is never touched by this test.
    root = tmp_path / "model"
    adapter = root / "adapter"
    adapter.mkdir(parents=True)
    (adapter / "adapter_config.json").write_text("{}")
    (adapter / "adapter_model.safetensors").write_bytes(b"old-adapter")
    monkeypatch.setenv("CYBERLLM_MODEL_ROOT", str(root))
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "adapter_config.json").write_text("{}")
    (candidate / "adapter_model.safetensors").write_bytes(b"new-adapter")
    approval = tmp_path / "approval.json"
    eval_report = tmp_path / "eval.json"
    eval_report.write_text("{}")
    approval.write_text(json.dumps({"decision": "approved", "approver": "admin", "evaluation_report": str(eval_report)}))
    backup = tmp_path / "backup"
    script = Path(__file__).resolve().parent.parent / "scripts" / "promote_cyberllm_candidate.py"
    r = subprocess.run([sys.executable, str(script), "--candidate-dir", str(candidate),
                        "--approval", str(approval), "--apply",
                        "--backup-dir", str(backup), "--confirm", "I APPROVE"],
                       capture_output=True, text=True, env={"CYBERLLM_MODEL_ROOT": str(root), "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"new-adapter"
    r2 = subprocess.run([sys.executable, str(script), "--rollback", "--backup-dir", str(backup)],
                        capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"old-adapter"
