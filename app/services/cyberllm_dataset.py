"""Dataset preparation for CyberLLM feedback — pure functions.

This module never touches the database or the filesystem; the CLI
scripts/prepare_cyberllm_feedback.py reads APPROVED TrainingExample rows
(source="cyberllm_feedback", safe_to_train=True) and calls these
functions, so the split / conflict / leakage rules are unit-testable
without a database.

Rules, in order:
1. Only APPROVED + safe_to_train rows are eligible. The caller enforces
   this; a row that is merely a user submission (CANDIDATE) is NOT
   ground truth and must never reach this module.
2. Contradictory labels: same dedup_hash (same instruction + input,
   output deliberately excluded) with different human_labels is a
   labelling conflict. ALL rows in the conflict group are excluded and
   reported — never silently pick the first label.
3. Duplicates: same dedup_hash + same label keep only the first row.
4. Split: deterministic by dedup_hash, 80 train / 10 eval / 10 held-out.
   Held-out is never used for training or tuning; it is the acceptance
   gate for a candidate.
5. Leakage: rows whose normalised input appears in a frozen-eval input
   set are excluded and reported. If no eval set is supplied, the CLI
   must say so explicitly — it must not claim "no leakage".
"""
from __future__ import annotations

import hashlib


def _normalise(text: str) -> str:
    return " ".join((text or "").strip().lower().split())


def find_conflicts(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (clean_rows, conflict_rows) for same-hash label conflicts."""
    by_hash: dict[str, list[dict]] = {}
    for row in rows:
        by_hash.setdefault(row.get("dedup_hash") or "", []).append(row)
    clean: list[dict] = []
    conflicts: list[dict] = []
    for group in by_hash.values():
        labels = {r.get("human_label") for r in group}
        if len(labels) > 1:
            conflicts.extend(group)
        else:
            clean.append(group[0])
    return clean, conflicts


def split_rows(rows: list[dict]) -> dict[str, list[dict]]:
    """Deterministic 80/10/10 split by dedup_hash."""
    out: dict[str, list[dict]] = {"train": [], "eval": [], "held_out": []}
    for row in rows:
        digest = row.get("dedup_hash") or hashlib.sha256(
            _normalise(row.get("input_text", "")).encode("utf-8")
        ).hexdigest()
        bucket = int(digest[:8], 16) % 100
        if bucket < 80:
            out["train"].append(row)
        elif bucket < 90:
            out["eval"].append(row)
        else:
            out["held_out"].append(row)
    return out


def leakage_rows(rows: list[dict], eval_inputs: set[str]) -> list[dict]:
    """Rows whose normalised input appears in the frozen eval set."""
    if not eval_inputs:
        return []
    normalised_eval = {_normalise(x) for x in eval_inputs}
    return [r for r in rows if _normalise(r.get("input_text", "")) in normalised_eval]


def prepare(rows: list[dict], eval_inputs: set[str] | None = None) -> dict:
    """Full preparation: conflicts -> duplicates -> leakage -> split."""
    clean, conflicts = find_conflicts(rows)
    leaked = leakage_rows(clean, eval_inputs) if eval_inputs is not None else []
    leaked_ids = {id(r) for r in leaked}
    kept = [r for r in clean if id(r) not in leaked_ids]
    splits = split_rows(kept)
    return {
        "splits": splits,
        "counts": {k: len(v) for k, v in splits.items()},
        "conflicts": conflicts,
        "leaked": leaked,
        "total_in": len(rows),
        "total_kept": len(kept),
        "leakage_checked": eval_inputs is not None,
    }
