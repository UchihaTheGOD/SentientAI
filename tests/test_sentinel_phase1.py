"""Phase 1+ tests: loader dual-checkpoint, inference, fusion, incidents, containment, training."""
from __future__ import annotations
import pytest

def test_loader_both_models_load_and_duplicate_deduped():
    from app.services.sentinel_loader import ensure_loaded, get_models, _choose_checkpoint_b
    s = ensure_loaded()
    assert s.ready is True, f"loader not ready: {s}"
    assert s.a == "loaded"
    assert s.b == "loaded"
    assert s.tokenizer_vocab_size == 7053
    b = _choose_checkpoint_b()
    assert b is not None
    assert b.name == "best_autolab_checkpoint.pt"
    ms = get_models()
    assert "a" in ms and "b" in ms

def test_loader_smoke_both_process_same_sample():
    from app.services.sentinel_loader import get_models, get_tokenizer, _load_config
    import torch
    ms = get_models(); tok = get_tokenizer()
    ids = [2] + tok.encode("192.168.1.1 failed login 5 times").ids[:10]
    with torch.inference_mode():
        inp = torch.tensor([ids], dtype=torch.long)
        out_a = ms["a"](inp); out_b = ms["b"](inp)
        assert out_a["logits"].shape == out_b["logits"].shape
        assert float(out_a["logits"].abs().mean()) > 1e-6

def test_inference_produces_structure():
    from app.services.sentinel_loader import ensure_loaded
    from app.services.prompt_service import build_analysis_prompt
    from app.services.sentinel_inference import run_dual_inference
    s = ensure_loaded()
    assert s.ready
    prompt = build_analysis_prompt("2024-01-01 12:00:00 INFO user bob login failed ip 10.0.0.5")
    res = run_dual_inference(prompt, max_new_tokens=24, timeout_s=12)
    assert res["model_a"] is not None and res["model_b"] is not None
    assert "latency_ms" in res

def test_fusion_rules_deterministic():
    from app.services.sentinel_fusion import evaluate_rules, fuse
    benign = "2024-01-01 10:00:00 INFO user alice fetched /blog 200"
    assert evaluate_rules(benign)["verdict"] == "likely_benign"
    brute = "\n".join([f"2024-01-01 10:00:{i:02d} WARN 192.168.1.10 login failed for user admin 401" for i in range(6)])
    r = evaluate_rules(brute)
    assert r["failed_count"] >= 5
    scan = "nmap scan " + " ".join([f"port {p} open" for p in range(8000, 8015)])
    assert evaluate_rules(scan)["port_scan"] is True
    fused = fuse(brute, {"model_a":{"text":"provisional assessment: likely_threat","status":"ok"},"model_b":{"text":"provisional assessment: likely_threat","status":"ok"},"agreement":True})
    assert "components" in fused
    assert fused["note"].startswith("Models A and B are same family")

def test_incidents_and_containment_lifecycle(admin, admin_client, db):
    from app.services import incident_service
    fused = {"fused_score": 80, "fused_verdict": "likely_threat", "rules": {"evidence": ["test"]}}
    inf = {"model_a":{"text":"likely_threat","status":"ok"},"model_b":{"text":"likely_threat","status":"ok"},"agreement":True}
    inc = incident_service.create_incident(db, log_text="test log 192.168.1.99 failed 5 times", ip_address="192.168.1.99", fused=fused, inference=inf, prompt_path="prompts/prompt.txt")
    assert inc.id is not None
    assert inc.status == "pending_review"
    inc2 = incident_service.update_review(db, inc.id, admin.id, "confirmed_threat", note="looks real")
    assert inc2.status == "confirmed_threat"
    blk = incident_service.apply_temp_block(db, kind="ip", value="203.0.113.5", ttl_minutes=1, reason="test", created_by=admin.id, incident_id=inc.id)
    assert blk.active is True
    assert incident_service.is_blocked(db, "ip", "203.0.113.5") is True
    with pytest.raises(ValueError):
        incident_service.apply_temp_block(db, kind="ip", value="127.0.0.1", ttl_minutes=1)
    incident_service.revoke_block(db, blk.id, revoked_by=admin.id)
    assert incident_service.is_blocked(db, "ip", "203.0.113.5") is False
    blk2 = incident_service.apply_temp_block(db, kind="ip", value="198.51.100.9", ttl_minutes=1)
    from datetime import datetime, timezone, timedelta
    blk2.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert incident_service.is_blocked(db, "ip", "198.51.100.9") is False

def test_training_pipeline_transitions(db, admin):
    from app.services.training_pipeline import build_dataset, evaluate_candidate, save_candidate, approve_candidate, rollback
    from app.models.sentinel_incident import SentinelIncident
    from datetime import datetime, timezone
    reviewed = db.query(SentinelIncident).filter(SentinelIncident.status.in_(("confirmed_threat","false_positive"))).all()
    train, eval_set = build_dataset(reviewed)
    metrics = evaluate_candidate(train, eval_set)
    if not reviewed:
        assert metrics["status"] == "insufficient_data"
    assert callable(save_candidate) and callable(approve_candidate) and callable(rollback)
    for i in range(3):
        inc = SentinelIncident(log_text=f"dummy log {i} 10.0.0.{i} failed login", status="confirmed_threat", fused_verdict="likely_threat", created_at=datetime.now(timezone.utc))
        db.add(inc)
    db.commit()
    reviewed2 = db.query(SentinelIncident).filter(SentinelIncident.status.in_(("confirmed_threat","false_positive"))).all()
    train2, eval2 = build_dataset(reviewed2)
    assert len(train2) > 0
    m2 = evaluate_candidate(train2, eval2)
    assert m2["status"] in ("insufficient_data","evaluated")
