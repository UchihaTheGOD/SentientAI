"""Export APPROVED CyberLLM feedback rows into train/eval/held-out JSONL.

Usage:
  python scripts/prepare_cyberllm_feedback.py --out data/cyberllm_feedback
  python scripts/prepare_cyberllm_feedback.py --out data/cyberllm_feedback --eval-inputs path/to/frozen_eval_inputs.jsonl

Only rows with source="cyberllm_feedback", status="approved" and
safe_to_train=True are exported. CANDIDATE rows (unreviewed user
feedback) are never exported — user feedback is not ground truth.

Without --eval-inputs the script prints a clear warning that leakage
against the frozen eval set was NOT checked; do not train on the
output until that check has run. No training is launched by this script.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.database import SessionLocal  # noqa: E402
from app.models.learning import APPROVED  # noqa: E402
from app.models.training_example import TrainingExample  # noqa: E402
from app.services.cyberllm_dataset import prepare  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Output directory (created if needed)")
    parser.add_argument("--eval-inputs", default=None, help="JSONL file with input_text per line (frozen eval)")
    args = parser.parse_args(argv)
    eval_inputs = None
    if args.eval_inputs:
        eval_inputs = set()
        for line in Path(args.eval_inputs).read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    eval_inputs.add(json.loads(line).get("input_text", ""))
                except json.JSONDecodeError:
                    eval_inputs.add(line)
    db = SessionLocal()
    try:
        rows = (
            db.query(TrainingExample)
            .filter(
                TrainingExample.source == "cyberllm_feedback",
                TrainingExample.status == APPROVED,
                TrainingExample.safe_to_train.is_(True),
            )
            .order_by(TrainingExample.id.asc())
            .all()
        )
        dicts = [
            {
                "id": r.id,
                "instruction": r.instruction,
                "input_text": r.input_text,
                "output_text": r.output_text,
                "human_label": r.human_label,
                "model_prediction": r.model_prediction,
                "dedup_hash": r.dedup_hash,
                "provenance": r.provenance,
                "reviewed_by": r.reviewed_by,
            }
            for r in rows
        ]
    finally:
        db.close()
    result = prepare(dicts, eval_inputs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for split, items in result["splits"].items():
        with (out_dir / f"{split}.jsonl").open("w", encoding="utf-8") as handle:
            for item in items:
                handle.write(json.dumps(item, sort_keys=True) + "\n")
    report = {
        "total_in": result["total_in"],
        "total_kept": result["total_kept"],
        "counts": result["counts"],
        "conflicts_excluded": len(result["conflicts"]),
        "leaked_excluded": len(result["leaked"]),
        "leakage_checked": result["leakage_checked"],
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not result["leakage_checked"]:
        print("WARNING: leakage against the frozen eval set was NOT checked. Do not train on this output until --eval-inputs has been run.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
