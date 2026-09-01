"""Command-line maintenance tasks for the training-example dataset.

Thin wrappers over `app/services/training.py` and `app/services/scoring.py` so
common dataset chores can run from a terminal (and from `run.bat`) without a
browser session. Nothing here promotes a candidate or trains a model — the only
mutating task is `score-backfill`, which fills a triage *band* on legacy rows
and never touches `approved` / `safe_to_train`.

Usage:
    python -m app.cli training-status
    python -m app.cli export-training [--out PATH]
    python -m app.cli export-eval [--out PATH]
    python -m app.cli score-backfill [--apply]
"""
from __future__ import annotations

import argparse
import sys
from typing import Optional

from app.database import SessionLocal, init_db
from app.models.learning import EXAMPLE_STATUS_LABELS, SPLIT_EVAL, SPLIT_TRAIN
from app.models.training_example import TrainingExample
from app.services import scoring, training


# ---------------------------------------------------------------------------
# Core operations (take a session so they are testable in isolation)
# ---------------------------------------------------------------------------

def training_status(db) -> dict:
    """The dataset review counts, as plain numbers."""
    return {
        "status_counts": training.status_counts(db),
        "band_counts": training.band_counts(db),
        "train_ready": len(training.get_approved_examples(db, split=SPLIT_TRAIN)),
        "eval_ready": len(training.get_approved_examples(db, split=SPLIT_EVAL)),
    }


def export_training(db, split: str = SPLIT_TRAIN) -> str:
    return training.export_approved_jsonl(db, split=split)


def export_eval(db) -> str:
    return training.export_eval_jsonl(db)


def backfill_bands(db, *, apply: bool) -> dict:
    """Assign a triage band to pending candidates that have a score but no band.

    These are legacy rows collected before the scorer wrote a band. `quality_score`
    is non-nullable and defaults to 0, so a 0 score is indistinguishable from
    "never scored" — those rows are left unbanded (reported as ``unscored``)
    rather than guessed at, since banding a sentinel 0 as noise would be a lie.
    Returns a summary; only writes when ``apply`` is true.
    """
    pending = (
        db.query(TrainingExample)
        .filter(TrainingExample.status.in_(training.PENDING_STATUSES))
        .all()
    )
    updated = 0
    unscored = 0
    for row in pending:
        if row.quality_band:
            continue
        if not row.quality_score:  # 0 (default sentinel) or None — no usable score
            unscored += 1
            continue
        if apply:
            row.quality_band = scoring.band_for_score(row.quality_score)
        updated += 1
    if apply and updated:
        db.commit()
    return {"updated": updated, "unscored": unscored, "applied": apply}


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def _print_status(summary: dict) -> None:
    print("Training pipeline status")
    print("  Lifecycle:")
    for key, label in EXAMPLE_STATUS_LABELS.items():
        print(f"    {label:<16} {summary['status_counts'].get(key, 0)}")
    print("  Triage bands (pending):")
    for band, count in summary["band_counts"].items():
        print(f"    {band:<16} {count}")
    print(f"  Train-ready: {summary['train_ready']}")
    print(f"  Eval-ready:  {summary['eval_ready']}")


def _write_or_print(jsonl: str, out: Optional[str], label: str) -> None:
    lines = jsonl.count("\n") if jsonl else 0
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(jsonl)
        print(f"Wrote {lines} {label} example(s) to {out}")
    else:
        sys.stdout.write(jsonl)
        print(f"# {lines} {label} example(s)", file=sys.stderr)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("training-status", help="print lifecycle and band counts")

    p_export = sub.add_parser("export-training", help="export the approved train split (JSONL)")
    p_export.add_argument("--out", help="file to write; omit to write to stdout")

    p_eval = sub.add_parser("export-eval", help="export the approved eval split (JSONL)")
    p_eval.add_argument("--out", help="file to write; omit to write to stdout")

    p_back = sub.add_parser(
        "score-backfill", help="assign a band to scored-but-unbanded pending rows"
    )
    p_back.add_argument(
        "--apply", action="store_true",
        help="write the changes; without it this is a dry run",
    )

    args = parser.parse_args(argv)

    # Sync the schema first, like every other standalone entrypoint
    # (manage.py, seed_community.py, app startup). Idempotent and never drops
    # data — this is what lets `run status` work against a DB the app hasn't
    # opened since the training-pipeline columns were added.
    init_db()

    db = SessionLocal()
    try:
        if args.command == "training-status":
            _print_status(training_status(db))
        elif args.command == "export-training":
            _write_or_print(export_training(db), args.out, "train")
        elif args.command == "export-eval":
            _write_or_print(export_eval(db), args.out, "eval")
        elif args.command == "score-backfill":
            result = backfill_bands(db, apply=args.apply)
            verb = "Banded" if result["applied"] else "Would band"
            print(f"{verb} {result['updated']} candidate(s); "
                  f"{result['unscored']} unscored row(s) left as-is.")
            if not result["applied"] and result["updated"]:
                print("Dry run — re-run with --apply to write.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
