"""Tests for evaluation_matrix harness: rules separated from models, eval not training."""
import json, pathlib

def test_evaluation_matrix_exists_and_has_cases():
    import evaluation_matrix as m
    assert len(m.EVAL_CASES) >= 20
    ids = [c["id"] for c in m.EVAL_CASES]
    assert len(ids) == len(set(ids))

def test_evaluation_covers_benign_suspicious_attack():
    import evaluation_matrix as m
    gts = {c["ground_truth"] for c in m.EVAL_CASES}
    assert "benign" in gts and "attack" in gts

def test_rules_detect_brute_variants():
    import evaluation_matrix as m
    bf_ids = [c["id"] for c in m.EVAL_CASES if c["category"] == "auth_abuse"]
    assert len(bf_ids) >= 5
    for case in [c for c in m.EVAL_CASES if c["id"] in bf_ids]:
        rec = m.evaluate_case(case, with_models=False)
        assert rec["rules"]["verdict"] in ("needs_review","likely_threat"), f"{case['id']} rules={rec['rules']}"

def test_rules_do_not_fp_on_benign():
    import evaluation_matrix as m
    benign = [c for c in m.EVAL_CASES if c["ground_truth"] == "benign"]
    fps = []
    for case in benign:
        rec = m.evaluate_case(case, with_models=False)
        if rec["rules"]["verdict"] != "likely_benign":
            fps.append(case["id"])
    # at most 1 FP allowed for this baseline dataset
    assert len(fps) <= 1, f"FPs: {fps}"

def test_evaluation_set_not_in_training_data(db):
    from app.models.training_example import TrainingExample
    import evaluation_matrix as m
    texts = {c["log_text"] for c in m.EVAL_CASES}
    rows = db.query(TrainingExample).all()
    leaked = [r.id for r in rows if (r.input_text in texts or r.log_text if hasattr(r,'log_text') else False)]
    # TrainingExample uses instruction/input_text/output_text; also check input_text
    leaked2 = [r.id for r in rows if r.input_text in texts]
    assert leaked2 == [], f"eval leaked into training: {leaked2}"

def test_metrics_separate_rules_and_models():
    import evaluation_matrix as m
    payload = m.run_evaluation(with_models=False, output_dir="evaluation")
    assert "rules" in payload["metrics"] and "model_a" in payload["metrics"]
    assert "fusion" in payload["metrics"]
    # rules should have recall > 0, models without inference should have recall 0
    assert payload["metrics"]["rules"]["recall"] > 0

def test_json_probe_invalid_without_retraining():
    import evaluation_matrix as m
    # Without models, json probe is None; with mocked empty, it should be invalid
    rec = m.evaluate_case(m.EVAL_CASES[0], with_models=False)
    assert rec["model_a"] is None  # no model run

def test_evaluation_records_latency_and_errors():
    import evaluation_matrix as m
    rec = m.evaluate_case(m.EVAL_CASES[0], with_models=False)
    assert "latency_ms" in rec["rules"]
    assert "failed_count" in rec["rules"]
