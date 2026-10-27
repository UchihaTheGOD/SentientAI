"""Batch evaluation: metrics, baselines, regression comparison.

Definitions (stated so results cannot be misread):
- A case is *decided* when the model returns likely_benign,
  needs_review, or likely_threat. Abstentions and errors are counted
  separately and excluded from accuracy, but an abstention on an
  expected threat still counts as a miss in threat recall: abstaining
  does not catch the threat.
- Accuracy = correct / decided. Threat recall = threats caught /
  all expected threats. False-positive rate = benign cases called
  threat / all expected benign.
- With no ground-truth labels, metrics are None and the result is
  reported as "not evaluated" — never as a fabricated score.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

CLASSES = ("likely_benign", "needs_review", "likely_threat")


@dataclass
class CaseResult:
    name: str
    kind: str
    text: str
    expected: str | None
    predicted: str
    latency_ms: int | None = None
    parse_ok: bool = True
    truncated: bool = False
    error: str = ""

    @property
    def abstained(self) -> bool:
        return self.predicted == "abstained"

    @property
    def decided(self) -> bool:
        return self.predicted in CLASSES

    @property
    def correct(self) -> bool | None:
        if self.expected is None or not self.decided:
            return None
        return self.predicted == self.expected

    def to_dict(self) -> dict:
        return {
            "name": self.name, "kind": self.kind, "text": self.text,
            "expected": self.expected, "predicted": self.predicted,
            "latency_ms": self.latency_ms, "parse_ok": self.parse_ok,
            "truncated": self.truncated, "error": self.error,
        }


@dataclass
class EvalResult:
    cases: list[CaseResult] = field(default_factory=list)
    metrics: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        return {"metrics": self.metrics,
                "cases": [c.to_dict() for c in self.cases]}


def load_cases_jsonl(path: Path) -> list[dict]:
    cases = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        cases.append({
            "name": str(row.get("name", "")),
            "kind": str(row.get("kind", "log")),
            "text": str(row.get("text", row.get("log_text", ""))),
            "expected": row.get("expected"),
        })
    return cases


def load_cases_csv(path: Path) -> list[dict]:
    cases = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cases.append({
                "name": row.get("name", ""),
                "kind": row.get("kind", "log"),
                "text": row.get("text", row.get("log_text", "")),
                "expected": row.get("expected") or None,
            })
    return cases


def load_cases(path: Path) -> list[dict]:
    if path.suffix.lower() == ".csv":
        return load_cases_csv(path)
    return load_cases_jsonl(path)


def compute_metrics(cases: list[CaseResult]) -> dict[str, Any] | None:
    labelled = [c for c in cases if c.expected is not None]
    if not labelled:
        return None
    decided = [c for c in labelled if c.decided]
    correct = sum(1 for c in decided if c.correct)
    matrix: dict[str, dict[str, int]] = {
        exp: {pred: 0 for pred in CLASSES} for exp in CLASSES}
    for c in decided:
        matrix[c.expected][c.predicted] += 1  # type: ignore[index]
    per_class: dict[str, dict[str, float | None]] = {}
    for cls in CLASSES:
        tp = matrix[cls][cls]
        fp = sum(matrix[other][cls] for other in CLASSES if other != cls)
        fn = sum(matrix[cls][other] for other in CLASSES if other != cls)
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision is not None and recall is not None
              and (precision + recall) else None)
        per_class[cls] = {"precision": precision, "recall": recall, "f1": f1,
                          "support": sum(matrix[cls].values())}
    threats = [c for c in labelled if c.expected == "likely_threat"]
    threat_caught = sum(1 for c in threats if c.predicted == "likely_threat")
    benign = [c for c in labelled if c.expected == "likely_benign"]
    benign_flagged = sum(1 for c in benign if c.predicted == "likely_threat")
    per_kind: dict[str, dict[str, int]] = {}
    for c in labelled:
        bucket = per_kind.setdefault(c.kind, {"total": 0, "correct": 0})
        bucket["total"] += 1
        if c.correct:
            bucket["correct"] += 1
    return {
        "total": len(labelled),
        "decided": len(decided),
        "abstained": sum(1 for c in labelled if c.abstained),
        "errors": sum(1 for c in labelled if c.error),
        "accuracy": (correct / len(decided)) if decided else None,
        "threat_recall": (threat_caught / len(threats)) if threats else None,
        "false_positive_rate": (benign_flagged / len(benign)) if benign else None,
        "confusion_matrix": matrix,
        "per_class": per_class,
        "per_kind": per_kind,
    }


def run_evaluation(analyze_fn: Callable[[str, str], dict],
                   cases: list[dict],
                   progress: Callable[[int, int], None] | None = None
                   ) -> EvalResult:
    """Run cases through ``analyze_fn(text, kind) -> api_result dict``."""
    results: list[CaseResult] = []
    for idx, case in enumerate(cases):
        if progress:
            progress(idx, len(cases))
        try:
            api = analyze_fn(case["text"], case.get("kind", "log"))
            shaped_class = api.get("classification", "unknown")
            results.append(CaseResult(
                name=case.get("name", f"case-{idx + 1}"),
                kind=case.get("kind", "log"), text=case["text"],
                expected=case.get("expected"),
                predicted=shaped_class
                if shaped_class in CLASSES else "abstained",
                latency_ms=api.get("latency_ms"),
                parse_ok=bool(api.get("parse_ok", True)),
                truncated=bool(api.get("truncated", False)),
            ))
        except Exception as exc:
            results.append(CaseResult(
                name=case.get("name", f"case-{idx + 1}"),
                kind=case.get("kind", "log"), text=case["text"],
                expected=case.get("expected"), predicted="error",
                error=str(exc)[:300]))
    if progress:
        progress(len(cases), len(cases))
    return EvalResult(cases=results, metrics=compute_metrics(results))


def save_baseline(result: EvalResult, path: Path) -> Path:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2),
                          encoding="utf-8")
    return Path(path)


def compare_baseline(new: EvalResult, baseline_path: Path) -> dict[str, Any]:
    """Diff a new run against a saved baseline (no history rewritten)."""
    old = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    old_cases = {c["name"]: c for c in old.get("cases", [])}
    improvements, regressions, unchanged = [], [], []
    for case in new.cases:
        prev = old_cases.get(case.name)
        if prev is None or prev.get("expected") is None:
            continue
        was = prev.get("predicted") == prev.get("expected")
        now = case.correct is True
        if now and not was:
            improvements.append(case.name)
        elif was and not now:
            regressions.append(case.name)
        else:
            unchanged.append(case.name)
    old_metrics = old.get("metrics") or {}
    new_metrics = new.metrics or {}
    deltas = {}
    for key in ("accuracy", "threat_recall", "false_positive_rate"):
        o, n = old_metrics.get(key), new_metrics.get(key)
        if o is not None and n is not None:
            deltas[key] = round(n - o, 4)
    verdict = ("regressed" if regressions and not improvements else
               "improved" if improvements and not regressions else
               "mixed" if improvements and regressions else "unchanged")
    return {"verdict": verdict, "improvements": improvements,
            "regressions": regressions, "unchanged": unchanged,
            "metric_deltas": deltas,
            "old_metrics": old_metrics, "new_metrics": new_metrics}


def export_eval_json(result: EvalResult, path: Path) -> Path:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2),
                          encoding="utf-8")
    return Path(path)


def export_eval_csv(result: EvalResult, path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["name", "kind", "expected", "predicted", "correct",
                         "latency_ms", "parse_ok", "truncated", "error"])
        for c in result.cases:
            writer.writerow([c.name, c.kind, c.expected, c.predicted,
                             c.correct, c.latency_ms, c.parse_ok,
                             c.truncated, c.error])
    return Path(path)
