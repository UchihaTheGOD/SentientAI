def test_fusion_ignores_invalid():
    from app.services.classifier import fuse_classification
    benign="2024-01-01 10:00:00 INFO user alice fetched /blog 200"
    # An unparseable CyberLLM result must not move fusion away from the rules.
    inf={"source": "cyberllm", "status": "unparseable", "classification": "needs_review", "confidence": "low", "deterministic_findings": []}
    r=fuse_classification(benign, inf)
    assert r["fused_verdict"]=="likely_benign" and r["fused_score"]==0
    assert r["components"][1]["source"] == "cyberllm" and r["components"][1]["verdict"] is None
def test_fusion_empty_no_fake_threat():
    from app.services.classifier import fuse_classification
    inf={"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low", "deterministic_findings": []}
    r=fuse_classification("", inf)
    assert r["fused_verdict"]=="likely_benign" and r["fused_score"]==0
    assert r["model_status"] == "unavailable"
def test_fusion_valid_contributes():
    from app.services.classifier import fuse_classification
    log="\n".join([f"2024-01-01 10:00:{i:02d} WARN 198.51.100.23 login failed 401" for i in range(6)])
    inf={"source": "cyberllm", "status": "ok", "classification": "likely_threat", "confidence": "high",
         "summary": "Attack detected: 6 failures.", "indicators": ["198.51.100.23 6 failed logins 401"],
         "reasoning": "Repeated failures exceed threshold.", "deterministic_findings": []}
    r=fuse_classification(log, inf)
    assert r["model_classification"] == "likely_threat"
    assert r["components"][1]["source"] == "cyberllm" and r["components"][1]["verdict"] == "likely_threat"
    # Rules 40 + model 85 -> 62, i.e. needs_review under the 65 threat threshold.
    assert r["fused_score"] == 62 and r["fused_verdict"] == "needs_review"
def test_api_rejects_empty():
    from app.main import create_app
    from tests.conftest import Client
    from app.database import SessionLocal
    from app.services.auth_service import hash_password
    from app.models.user import User
    import uuid
    s=SessionLocal()
    uname=f"adm_empty_{uuid.uuid4().hex[:6]}"
    u=User(username=uname, email=f"{uname}@example.test", password_hash=hash_password("TestPassword123"), role="admin")
    s.add(u); s.commit(); s.refresh(u); s.expunge(u); s.close()
    app=create_app(); c=Client(app); c.login(uname)
    r=c._client.post("/api/sentinel/analyze", json={"log_text": "", "create_incident": False}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code==422
    r2=c._client.post("/api/sentinel/analyze", json={"log_text": "   ", "create_incident": False}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code==422
def test_api_valid_flow():
    from app.main import create_app
    from tests.conftest import Client
    from app.database import SessionLocal
    from app.services.auth_service import hash_password
    from app.models.user import User
    import uuid
    s=SessionLocal()
    uname=f"adm_valid_{uuid.uuid4().hex[:6]}"
    u=User(username=uname, email=f"{uname}@example.test", password_hash=hash_password("TestPassword123"), role="admin")
    s.add(u); s.commit(); s.refresh(u); s.expunge(u); s.close()
    app=create_app(); c=Client(app); c.login(uname)
    r=c._client.post("/api/sentinel/analyze", json={"log_text": "   \n\t  ", "create_incident": False}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code==422
    r2=c._client.post("/api/sentinel/analyze", json={"log_text": "2024-01-01 10:00:00 INFO GET / 200 user alice", "create_incident": False}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code==200
    data=r2.json()
    assert data["verdict"] in ("likely_benign","needs_review","likely_threat")
    assert data["classification"] is not None and data["classification"]["source"] == "cyberllm"
