def test_fusion_ignores_invalid():
    from app.services.sentinel_fusion import fuse
    benign="2024-01-01 10:00:00 INFO user alice fetched /blog 200"
    inf={"model_a": {"text": "likely_threat attack confirmed!!!", "status": "ok"}, "model_b": {"text": "likely_threat", "status": "ok"}}
    r=fuse(benign, inf)
    assert r["model_a_valid"] is False and r["model_b_valid"] is False
    assert r["fused_verdict"]=="likely_benign" and r["fused_score"]==0
    assert "invalid structure" in r["components"][1]["evidence"][0]
def test_fusion_empty_no_fake_threat():
    from app.services.sentinel_fusion import fuse
    inf={"model_a": {"text": "", "status": "empty"}, "model_b": {"text": "", "status": "empty"}}
    r=fuse("", inf)
    assert r["fused_verdict"]=="likely_benign" and r["fused_score"]==0
    assert r["model_a_valid"] is False
def test_fusion_valid_contributes():
    from app.services.sentinel_fusion import fuse
    valid_a=("Summary:\nAttack detected: 6 failures.\nIndicators:\n- 198.51.100.23 6 failed logins 401\nReasoning:\nRepeated failures exceed threshold.\nProvisional assessment: likely_threat\nInput status: valid")
    valid_b=("Summary:\nSuspicious repeated failures.\nIndicators:\n- same IP repeated\nReasoning:\nNeeds review.\nProvisional assessment: needs_review\nInput status: valid")
    log="\n".join([f"2024-01-01 10:00:{i:02d} WARN 198.51.100.23 login failed 401" for i in range(6)])
    inf={"model_a": {"text": valid_a, "status": "ok"}, "model_b": {"text": valid_b, "status": "ok"}, "agreement": None}
    r=fuse(log, inf)
    assert r["model_a_valid"] is True and r["model_b_valid"] is True
    assert r["components"][1]["structured_valid"] is True
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
    assert data["model_a"] is not None and data["model_b"] is not None
