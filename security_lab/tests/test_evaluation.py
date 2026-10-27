"""Evaluation metrics, baselines, and the not-evaluated guarantee."""

from ..evaluation import (compare_baseline, compute_metrics, load_cases,
                          run_evaluation, save_baseline)
from ..evaluation import CaseResult


def _fake_analyze(mapping):
    def analyze(text, kind):
        return {"classification": mapping[text], "latency_ms": 5,
                "parse_ok": True, "truncated": False}
    return analyze


def test_metrics_are_correct():
    cases = [
        {"name": "t1", "kind": "log", "text": "a", "expected": "likely_threat"},
        {"name": "t2", "kind": "log", "text": "b", "expected": "likely_threat"},
        {"name": "b1", "kind": "log", "text": "c", "expected": "likely_benign"},
        {"name": "b2", "kind": "log", "text": "d", "expected": "likely_benign"},
        {"name": "r1", "kind": "log", "text": "e", "expected": "needs_review"},
    ]
    mapping = {"a": "likely_threat", "b": "needs_review", "c": "likely_benign",
               "d": "likely_threat", "e": "needs_review"}
    result = run_evaluation(_fake_analyze(mapping), cases)
    m = result.metrics
    assert m["total"] == 5
    assert m["decided"] == 5
    assert m["accuracy"] == 3 / 5
    assert m["threat_recall"] == 1 / 2  # one threat missed (needs_review)
    assert m["false_positive_rate"] == 1 / 2  # one benign called threat
    assert m["confusion_matrix"]["likely_threat"]["likely_threat"] == 1
    assert m["confusion_matrix"]["likely_threat"]["needs_review"] == 1


def test_unlabelled_cases_are_not_evaluated():
    cases = [{"name": "x", "kind": "log", "text": "a", "expected": None}]
    result = run_evaluation(_fake_analyze({"a": "likely_threat"}), cases)
    assert result.metrics is None


def test_baseline_compare_detects_regression_and_improvement(tmp_path):
    cases = [
        {"name": "t1", "kind": "log", "text": "a", "expected": "likely_threat"},
        {"name": "t2", "kind": "log", "text": "b", "expected": "likely_benign"},
    ]
    old = run_evaluation(_fake_analyze({"a": "likely_threat",
                                        "b": "likely_benign"}), cases)
    path = tmp_path / "baseline.json"
    save_baseline(old, path)
    new = run_evaluation(_fake_analyze({"a": "needs_review",
                                        "b": "likely_threat"}), cases)
    diff = compare_baseline(new, path)
    assert diff["verdict"] == "regressed"
    assert diff["regressions"] == ["t1", "t2"]
    assert diff["improvements"] == []
    assert diff["metric_deltas"]["accuracy"] == -1.0


def test_load_cases_jsonl_and_csv(tmp_path):
    jsonl = tmp_path / "cases.jsonl"
    jsonl.write_text('{"name": "a", "kind": "log", "text": "hello", '
                     '"expected": "likely_benign"}\n')
    assert load_cases(jsonl)[0]["expected"] == "likely_benign"
    csv_path = tmp_path / "cases.csv"
    csv_path.write_text("name,kind,text,expected\nb,url,http://x,likely_threat\n")
    assert load_cases(csv_path)[0]["text"] == "http://x"


def test_case_result_properties():
    c = CaseResult("x", "log", "t", "likely_threat", "abstained")
    assert c.abstained is True
    assert c.decided is False
    assert c.correct is None
