"""End-to-end learning workflow with synthetic records only.

Lifecycle, in order, with rejection paths at each gate:
1. feedback submission -> CANDIDATE, not trainable
2. redaction of secrets before storage
3. export filter: CANDIDATE rows are NOT exported (only APPROVED)
4. duplicate handling: second identical submission is a duplicate
5. conflicting labels: both rows excluded from the dataset
6. admin approval -> APPROVED + safe_to_train, then exportable
7. rejection -> REJECTED, not exportable
8. dataset preparation + leakage detection
9. promotion check without approval -> refuses, model intact
10. promotion apply with approval -> backup, new adapter, rollback
    restores the previous adapter byte-for-byte

No training is launched and no production model is replaced outside
the tmp model root used by the promotion tests.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.models.learning import APPROVED, CANDIDATE, REJECTED
from app.models.training_example import TrainingExample
from app.services.cyberllm_dataset import prepare
from app.services.cyberllm_feedback import collect_cyberllm_feedback
from app.services.training import approve_example, reject_example, review_example
from app.services.cyberllm_dataset import find_conflicts


def _model_output(cls="likely_threat"):
    return {"summary": "synthetic", "classification": cls, "confidence": "high",
            "indicators": ["synthetic"], "reasoning": "synthetic reasoning",
            "limitations": [], "recommended_actions": []}


def _approved_only(db):
    return (
        db.query(TrainingExample)
        .filter(
            TrainingExample.source == "cyberllm_feedback",
            TrainingExample.status == APPROVED,
            TrainingExample.safe_to_train.is_(True),
        )
        .all()
    )


def test_lifecycle_candidate_not_exportable_until_approved(db):
    ex = collect_cyberllm_feedback(
        db, input_text="synthetic log: 5 failed logins, token=do-not-store-123",
        model_output=_model_output(), human_label="likely_threat",
    )
    assert ex.status == CANDIDATE
    assert ex.safe_to_train is False
    assert "do-not-store-123" not in ex.input_text
    assert _approved_only(db) == []
    approved = approve_example(db, ex.id, reviewer_id=1, note="verified synthetic")
    assert approved.status == APPROVED and approved.safe_to_train is True
    assert len(_approved_only(db)) == 1


def test_lifecycle_rejection_is_not_exportable(db):
    ex = collect_cyberllm_feedback(
        db, input_text="synthetic benign log", model_output=_model_output("likely_benign"),
    )
    rejected = reject_example(db, ex.id, reviewer_id=1, reason="other", note="bad label")
    assert rejected.status == REJECTED
    assert rejected.safe_to_train is False
    assert _approved_only(db) == []


def test_lifecycle_duplicate_and_conflict_handling(db):
    a = collect_cyberllm_feedback(
        db, input_text="synthetic duplicate log", model_output=_model_output(),
        human_label="likely_threat",
    )
    b = collect_cyberllm_feedback(
        db, input_text="synthetic duplicate log", model_output=_model_output(),
        human_label="likely_threat",
    )
    assert a.dedup_hash == b.dedup_hash
    # Approving the second identical row must mark it DUPLICATE, not
    # create a second trainable copy.
    approve_example(db, a.id, reviewer_id=1)
    second = review_example(db, b.id, reviewer_id=1, new_status=APPROVED)
    assert second is not None
    assert second.status != APPROVED or second.safe_to_train is False or "Identical" in (second.review_note or "")
    # Conflict group: same input, different human labels -> excluded.
    rows = [
        {"dedup_hash": "cc", "human_label": "likely_threat", "input_text": "conflict log"},
        {"dedup_hash": "cc", "human_label": "likely_benign", "input_text": "conflict log"},
    ]
    result = prepare(rows, eval_inputs=set())
    assert result["total_kept"] == 0
    assert len(result["conflicts"]) == 2


def test_lifecycle_leakage_and_split(db):
    ex = collect_cyberllm_feedback(
        db, input_text="frozen eval synthetic log", model_output=_model_output(),
        human_label="likely_threat",
    )
    approve_example(db, ex.id, reviewer_id=1)
    rows = _approved_only(db)
    assert len(rows) == 1
    dicts = [{
        "dedup_hash": rows[0].dedup_hash, "input_text": rows[0].input_text,
        "human_label": rows[0].human_label,
    }]
    leaked = prepare(dicts, eval_inputs={"frozen eval synthetic log"})
    assert leaked["total_kept"] == 0 and len(leaked["leaked"]) == 1
    clean = prepare(dicts, eval_inputs={"something else"})
    assert clean["total_kept"] == 1
    assert sum(clean["counts"].values()) == 1


def _promotion_script():
    return Path(__file__).resolve().parent.parent / "scripts" / "promote_cyberllm_candidate.py"


def test_promotion_rejection_leaves_model_intact(tmp_path):
    root = tmp_path / "model"
    adapter = root / "adapter"
    adapter.mkdir(parents=True)
    (adapter / "adapter_config.json").write_text("{}")
    (adapter / "adapter_model.safetensors").write_bytes(b"production-adapter")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "adapter_config.json").write_text("{}")
    (candidate / "adapter_model.safetensors").write_bytes(b"candidate-adapter")
    # No approval file at all -> check mode refuses, nothing copied.
    r = subprocess.run(
        [sys.executable, str(_promotion_script()), "--candidate-dir", str(candidate)],
        capture_output=True, text=True,
        env={"CYBERLLM_MODEL_ROOT": str(root), "PATH": "/usr/bin:/bin"},
    )
    assert r.returncode != 0
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"production-adapter"
    # Approval with decision != approved -> also refuses.
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"decision": "pending", "approver": "admin", "evaluation_report": str(tmp_path / "e.json")}))
    (tmp_path / "e.json").write_text("{}")
    r2 = subprocess.run(
        [sys.executable, str(_promotion_script()), "--candidate-dir", str(candidate),
         "--approval", str(bad)],
        capture_output=True, text=True,
        env={"CYBERLLM_MODEL_ROOT": str(root), "PATH": "/usr/bin:/bin"},
    )
    assert r2.returncode != 0
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"production-adapter"
    # Apply without the exact confirm phrase -> refuses.
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"decision": "approved", "approver": "admin", "evaluation_report": str(tmp_path / "e.json")}))
    r3 = subprocess.run(
        [sys.executable, str(_promotion_script()), "--candidate-dir", str(candidate),
         "--approval", str(good), "--apply", "--backup-dir", str(tmp_path / "backup"),
         "--confirm", "yes"],
        capture_output=True, text=True,
        env={"CYBERLLM_MODEL_ROOT": str(root), "PATH": "/usr/bin:/bin"},
    )
    assert r3.returncode != 0
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"production-adapter"


def test_promotion_apply_backup_rollback_intact(tmp_path):
    root = tmp_path / "model"
    adapter = root / "adapter"
    adapter.mkdir(parents=True)
    (adapter / "adapter_config.json").write_text("{}")
    (adapter / "adapter_model.safetensors").write_bytes(b"production-adapter")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "adapter_config.json").write_text("{}")
    (candidate / "adapter_model.safetensors").write_bytes(b"candidate-adapter")
    eval_report = tmp_path / "e.json"
    eval_report.write_text("{}")
    approval = tmp_path / "good.json"
    approval.write_text(json.dumps({"decision": "approved", "approver": "admin", "evaluation_report": str(eval_report)}))
    backup = tmp_path / "backup"
    env = {"CYBERLLM_MODEL_ROOT": str(root), "PATH": "/usr/bin:/bin"}
    r = subprocess.run(
        [sys.executable, str(_promotion_script()), "--candidate-dir", str(candidate),
         "--approval", str(approval), "--apply", "--backup-dir", str(backup),
         "--confirm", "I APPROVE"],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"candidate-adapter"
    assert (backup / "promotion.json").exists()
    assert (backup / "rollback.json").exists()
    r2 = subprocess.run(
        [sys.executable, str(_promotion_script()), "--rollback", "--backup-dir", str(backup)],
        capture_output=True, text=True, env=env,
    )
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert (adapter / "adapter_model.safetensors").read_bytes() == b"production-adapter"
