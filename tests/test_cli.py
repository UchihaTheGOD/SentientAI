"""The maintenance CLI (`python -m app.cli`).

These are thin wrappers over the training service, so the tests check the two
things the wrappers add: that the numbers/exports match the service, and that
`score-backfill` only ever fills a *band* — it never invents a score and never
makes a row trainable.
"""
from __future__ import annotations

import pytest

from app import cli
from app.models.learning import APPROVED, CANDIDATE, SPLIT_EVAL, SPLIT_TRAIN
from app.models.training_example import TrainingExample
from app.services import training as training_service

INSTRUCTION = "Explain the attack in this observation and how to defend against it."


def _candidate(db, **overrides) -> TrainingExample:
    fields = {
        "instruction": INSTRUCTION,
        "input_text": "A request parameter contained ' OR 1=1 -- against a login form.",
        "output_text": "Boolean-based SQL injection. Use parameterised queries.",
        "attack_type": "sql_injection",
        "severity": "high",
        "source": "sentientai_lab",
        "approved": False,
        "status": CANDIDATE,
        "safe_to_train": False,
        "provenance": "lab_submission",
    }
    fields.update(overrides)
    fields.setdefault(
        "dedup_hash",
        training_service.dedup_hash(fields["instruction"], fields["input_text"]),
    )
    row = TrainingExample(**fields)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ---------------------------------------------------------------------------
# status + export mirror the service
# ---------------------------------------------------------------------------

def test_training_status_reports_the_pipeline_counts(db, admin):
    train_row = _candidate(db, split=SPLIT_TRAIN)
    eval_row = _candidate(db, split=SPLIT_EVAL, input_text="A held-out observation.")
    _candidate(db, input_text="A third, left pending.")
    training_service.approve_example(db, train_row.id, admin.id)
    training_service.approve_example(db, eval_row.id, admin.id)

    summary = cli.training_status(db)
    assert summary["train_ready"] == 1
    assert summary["eval_ready"] == 1
    assert summary["status_counts"][APPROVED] == 2
    assert summary["status_counts"][CANDIDATE] == 1


def test_export_training_emits_only_the_approved_train_split(db, admin):
    approved = _candidate(db, split=SPLIT_TRAIN)
    _candidate(db, input_text="An unreviewed candidate.")  # stays pending
    training_service.approve_example(db, approved.id, admin.id)

    lines = cli.export_training(db).splitlines()
    assert len(lines) == 1


def test_export_eval_emits_the_eval_split(db, admin):
    eval_row = _candidate(db, split=SPLIT_EVAL)
    training_service.approve_example(db, eval_row.id, admin.id)
    assert len(cli.export_eval(db).splitlines()) == 1


# ---------------------------------------------------------------------------
# score-backfill fills a band, nothing more
# ---------------------------------------------------------------------------

def test_backfill_dry_run_changes_nothing(db):
    row = _candidate(db, quality_score=70, quality_band=None)
    result = cli.backfill_bands(db, apply=False)
    assert result == {"updated": 1, "unscored": 0, "applied": False}

    db.expire_all()
    assert db.query(TrainingExample).filter(
        TrainingExample.id == row.id,
    ).first().quality_band is None


def test_backfill_apply_sets_the_band_from_the_score(db):
    useful = _candidate(db, quality_score=80, quality_band=None)
    noisy = _candidate(db, quality_score=10, quality_band=None,
                       input_text="A different low-scoring observation.")
    result = cli.backfill_bands(db, apply=True)
    assert result["updated"] == 2

    db.expire_all()
    assert db.query(TrainingExample).filter(
        TrainingExample.id == useful.id,
    ).first().quality_band == "useful"
    assert db.query(TrainingExample).filter(
        TrainingExample.id == noisy.id,
    ).first().quality_band == "noisy"


def test_backfill_leaves_a_scoreless_row_alone(db):
    row = _candidate(db)  # no quality_score
    result = cli.backfill_bands(db, apply=True)
    assert result["unscored"] == 1
    assert result["updated"] == 0

    db.expire_all()
    assert db.query(TrainingExample).filter(
        TrainingExample.id == row.id,
    ).first().quality_band is None


def test_backfill_never_makes_a_row_trainable(db):
    _candidate(db, quality_score=95, quality_band=None)
    cli.backfill_bands(db, apply=True)
    db.expire_all()
    row = db.query(TrainingExample).first()
    assert row.safe_to_train is False
    assert row.status == CANDIDATE


def test_a_row_that_already_has_a_band_is_skipped(db):
    row = _candidate(db, quality_score=95, quality_band="review")
    result = cli.backfill_bands(db, apply=True)
    assert result["updated"] == 0
    db.expire_all()
    # An existing (possibly hand-set) band is not overwritten.
    assert db.query(TrainingExample).filter(
        TrainingExample.id == row.id,
    ).first().quality_band == "review"


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def test_main_training_status_returns_zero(db, capsys):
    assert cli.main(["training-status"]) == 0
    assert "Training pipeline status" in capsys.readouterr().out


def test_main_requires_a_known_command(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["frobnicate"])
    assert excinfo.value.code != 0
