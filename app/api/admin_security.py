"""Admin Security Center page."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import BackgroundTasks
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.auth_service import require_admin
from app.models.user import User
from app.models.attact_assessment import AttactAssessment, SecurityEvent
from app.models.sentinel_incident import SentinelIncident, TempBlock
from app.services.demo_cases import catalog
from app.template_env import templates

router = APIRouter(prefix="/admin/security", tags=["admin-security"])

@router.get("", response_class=HTMLResponse)
def admin_security(request: Request, category: str | None = None, severity: str | None = None, ip: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    assessments = db.query(AttactAssessment).order_by(AttactAssessment.created_at.desc()).limit(20).all()
    incidents = db.query(SentinelIncident).order_by(SentinelIncident.created_at.desc()).limit(50).all()
    q = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(200)
    events = q.all()
    if category:
        events = [e for e in events if e.category == category]
    if severity:
        events = [e for e in events if e.severity == severity]
    if ip:
        events = [e for e in events if (e.ip_address or "") == ip]
    blocks = db.query(TempBlock).order_by(TempBlock.created_at.desc()).limit(20).all()
    return templates.TemplateResponse("admin_security.html", {"request": request, "current_user": user, "user": user, "assessments": assessments, "incidents": incidents, "events": events, "blocks": blocks, "demo_cases": catalog(), "filters": {"category": category, "severity": severity, "ip": ip}})


def _per_day_series(day_labels: list[str], rows) -> list[int]:
    """Bucket SQL (day, count) rows onto the full day-label list, filling
    missing days with 0. ``rows`` come from func.date(created_at) GROUP BY,
    so the day is already a "YYYY-MM-DD" string."""
    counts = {label: 0 for label in day_labels}
    for day, n in rows:
        if day in counts:
            counts[day] = int(n)
    return [counts[label] for label in day_labels]


def _svg_grouped_bars(day_labels: list[str], series, *, height: int = 120) -> str:
    """Render a grouped vertical bar chart as inline SVG.

    ``day_labels`` is the x axis ("YYYY-MM-DD", oldest first); ``series`` is
    a list of (name, color, values) with one value per day. Server-generated
    (not user content), so the template renders it with ``| safe``. Every
    chart is accompanied by a table with the exact numbers.
    """
    n = len(day_labels)
    if n == 0 or not series:
        return ""
    max_v = max((v for _name, _color, values in series for v in values), default=0) or 1
    slot = 20  # px per day
    bar_w = max(3, (slot - 4) // max(1, len(series)))
    width = n * slot
    top = 8
    base = height - 22
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="Bar chart, {n} days">'
    ]
    for i, label in enumerate(day_labels):
        for j, (name, color, values) in enumerate(series):
            v = values[i]
            if v <= 0:
                continue
            bar_h = max(2, int(v / max_v * (base - top)))
            x = i * slot + 2 + j * bar_w
            y = base - bar_h
            parts.append(
                f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" fill="{color}">'
                f"<title>{label} {name}: {v}</title></rect>"
            )
    parts.append(
        f'<line x1="0" y1="{base}" x2="{width}" y2="{base}" stroke="#94a3b8" stroke-width="1"/>'
    )
    for i in (0, n // 2, n - 1):
        x = i * slot + 2
        parts.append(
            f'<text x="{x}" y="{height - 6}" font-size="9" fill="#64748b">{day_labels[i][5:]}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


@router.get("/dashboard", response_class=HTMLResponse)
def admin_security_dashboard(
    request: Request,
    days: int = 30,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Admin-only security dashboard: logins, signups, login attacks and
    attack detections over the last N days (default 30), plus Sentinel,
    scanner and CyberLLM counts.

    Read-only analytics — no actions, no auto-remediation, no new auth.
    Charts are server-rendered (no JavaScript library, no new dependency);
    every chart has its numbers in an adjacent table. IP addresses are
    never listed here: brute-force sources are shown as salted IP hashes
    with counts, and the Security Center detail pages already show IPs to
    admins.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import func

    from app.models.audit import AuditEvent
    from app.models.cyberllm_analysis import CyberLLMAnalysisEvent
    from app.models.training_example import TrainingExample
    from app.models.attact_assessment import AttactFinding

    days = days if days in (7, 30, 90) else 30
    now = datetime.now(timezone.utc)
    # Calendar-day window: the last `days` days including today. `since`
    # is midnight at the start of the first day, so the SQL window and the
    # day labels cover exactly the same days.
    today = now.date()
    first_day = today - timedelta(days=days - 1)
    since = datetime.combine(first_day, datetime.min.time(), tzinfo=timezone.utc)
    day_labels = [(first_day + timedelta(days=i)).isoformat() for i in range(days)]

    # -- Logins / signups (AuditEvent; IP stored as salted hash only) ------
    login_rows = (
        db.query(func.date(AuditEvent.created_at).label("day"), AuditEvent.event_type, func.count().label("n"))
        .filter(
            AuditEvent.created_at >= since,
            AuditEvent.event_type.in_(["auth.login", "auth.login_failed", "auth.register"]),
        )
        .group_by("day", AuditEvent.event_type)
        .all()
    )
    per_day: dict[str, dict[str, int]] = {
        label: {"auth.login": 0, "auth.login_failed": 0, "auth.register": 0}
        for label in day_labels
    }
    for day, event_type, n in login_rows:
        if day in per_day and event_type in per_day[day]:
            per_day[day][event_type] = int(n)
    logins = [per_day[d]["auth.login"] for d in day_labels]
    failed = [per_day[d]["auth.login_failed"] for d in day_labels]
    signups = [per_day[d]["auth.register"] for d in day_labels]
    total_logins = sum(logins)
    total_failed = sum(failed)
    total_signups = sum(signups)
    login_attempts = total_logins + total_failed
    failed_rate = (total_failed / login_attempts * 100) if login_attempts else 0.0

    # -- Security events (detections) ---------------------------------------
    def _grouped(model_col, *, event_type: str | None = None):
        q = db.query(model_col, func.count()).filter(SecurityEvent.created_at >= since)
        if event_type is not None:
            q = q.filter(SecurityEvent.event_type == event_type)
        return [(str(k) if k is not None else "(none)", int(n)) for k, n in q.group_by(model_col).all()]

    sec_by_category = sorted(_grouped(SecurityEvent.category), key=lambda kv: -kv[1])
    sec_by_severity = sorted(_grouped(SecurityEvent.severity), key=lambda kv: -kv[1])
    sec_by_source = sorted(_grouped(SecurityEvent.source), key=lambda kv: -kv[1])
    sec_by_type = sorted(_grouped(SecurityEvent.event_type), key=lambda kv: -kv[1])[:10]
    sec_per_day = _per_day_series(
        day_labels,
        db.query(func.date(SecurityEvent.created_at), func.count())
        .filter(SecurityEvent.created_at >= since)
        .group_by(func.date(SecurityEvent.created_at)).all(),
    )
    total_events = sum(v for _k, v in sec_by_category)

    # -- Login attacks: brute-force events ----------------------------------
    brute_total = (
        db.query(func.count(SecurityEvent.id))
        .filter(SecurityEvent.created_at >= since, SecurityEvent.event_type == "auth.brute_force")
        .scalar()
        or 0
    )
    brute_per_day = _per_day_series(
        day_labels,
        db.query(func.date(SecurityEvent.created_at), func.count())
        .filter(SecurityEvent.created_at >= since, SecurityEvent.event_type == "auth.brute_force")
        .group_by(func.date(SecurityEvent.created_at)).all(),
    )
    # Top sources as salted IP hashes with counts — never raw IPs here.
    brute_top_hashes = [
        (str(h)[:12] if h else "(none)", int(n))
        for h, n in (
            db.query(SecurityEvent.ip_hash, func.count())
            .filter(SecurityEvent.created_at >= since, SecurityEvent.event_type == "auth.brute_force")
            .group_by(SecurityEvent.ip_hash)
            .order_by(func.count().desc()).limit(10).all()
        )
    ]

    # -- Sentinel incidents --------------------------------------------------
    inc_by_verdict = sorted([
        (str(k) if k is not None else "(none)", int(n))
        for k, n in db.query(SentinelIncident.fused_verdict, func.count())
        .filter(SentinelIncident.created_at >= since)
        .group_by(SentinelIncident.fused_verdict).all()
    ], key=lambda kv: -kv[1])
    inc_by_status = sorted([
        (str(k) if k is not None else "(none)", int(n))
        for k, n in db.query(SentinelIncident.status, func.count())
        .filter(SentinelIncident.created_at >= since)
        .group_by(SentinelIncident.status).all()
    ], key=lambda kv: -kv[1])
    total_incidents = sum(v for _k, v in inc_by_verdict)

    # -- Scanner runs and findings ------------------------------------------
    assess_by_status = sorted([
        (str(k) if k is not None else "(none)", int(n))
        for k, n in db.query(AttactAssessment.status, func.count())
        .filter(AttactAssessment.created_at >= since)
        .group_by(AttactAssessment.status).all()
    ], key=lambda kv: -kv[1])
    finding_by_severity = sorted([
        (str(k) if k is not None else "(none)", int(n))
        for k, n in db.query(AttactFinding.severity, func.count())
        .filter(AttactFinding.created_at >= since)
        .group_by(AttactFinding.severity).all()
    ], key=lambda kv: -kv[1])
    total_assessments = sum(v for _k, v in assess_by_status)

    # -- CyberLLM: per-call records (no log text, no raw output) ------------
    cyb_by_class = sorted([
        (str(k) if k is not None else "(none)", int(n))
        for k, n in db.query(CyberLLMAnalysisEvent.classification, func.count())
        .filter(CyberLLMAnalysisEvent.created_at >= since)
        .group_by(CyberLLMAnalysisEvent.classification).all()
    ], key=lambda kv: -kv[1])
    cyb_by_source = sorted([
        (str(k) if k is not None else "(none)", int(n))
        for k, n in db.query(CyberLLMAnalysisEvent.decision_source, func.count())
        .filter(CyberLLMAnalysisEvent.created_at >= since)
        .group_by(CyberLLMAnalysisEvent.decision_source).all()
    ], key=lambda kv: -kv[1])
    cyb_per_day = _per_day_series(
        day_labels,
        db.query(func.date(CyberLLMAnalysisEvent.created_at), func.count())
        .filter(CyberLLMAnalysisEvent.created_at >= since)
        .group_by(func.date(CyberLLMAnalysisEvent.created_at)).all(),
    )
    total_cyb = sum(v for _k, v in cyb_by_class)

    # -- CyberLLM reviewed-only counts (human-reviewed analyses) -----------
    reviewed = (
        db.query(TrainingExample)
        .filter(
            TrainingExample.source == "cyberllm_feedback",
            TrainingExample.created_at >= since,
        )
        .all()
    )
    reviewed_by_status: dict[str, int] = {}
    reviewed_by_prediction: dict[str, int] = {}
    for row in reviewed:
        reviewed_by_status[row.status or "(none)"] = reviewed_by_status.get(row.status or "(none)", 0) + 1
        key = row.model_prediction or "(none)"
        reviewed_by_prediction[key] = reviewed_by_prediction.get(key, 0) + 1

    # -- Recent events -------------------------------------------------------
    recent = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(50).all()

    # -- All-time totals -----------------------------------------------------
    all_time = {
        "security_events": db.query(func.count(SecurityEvent.id)).scalar() or 0,
        "incidents": db.query(func.count(SentinelIncident.id)).scalar() or 0,
        "brute_force": db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.event_type == "auth.brute_force").scalar() or 0,
        "cyberllm_analyses": db.query(func.count(CyberLLMAnalysisEvent.id)).scalar() or 0,
    }

    login_chart = _svg_grouped_bars(day_labels, [
        ("Successful logins", "#2563eb", logins),
        ("Failed logins", "#dc2626", failed),
    ])
    signup_chart = _svg_grouped_bars(day_labels, [("Signups", "#16a34a", signups)])
    brute_chart = _svg_grouped_bars(day_labels, [("Brute-force events", "#ea580c", brute_per_day)])
    events_chart = _svg_grouped_bars(day_labels, [("Security events", "#7c3aed", sec_per_day)])
    cyb_chart = _svg_grouped_bars(day_labels, [("CyberLLM analyses", "#0d9488", cyb_per_day)])

    return templates.TemplateResponse("admin_security_dashboard.html", {
        "request": request, "current_user": user, "user": user,
        "days": days, "day_labels": day_labels,
        "logins": logins, "failed": failed, "signups": signups,
        "brute_per_day": brute_per_day, "sec_per_day": sec_per_day,
        "cyb_per_day": cyb_per_day,
        "total_logins": total_logins, "total_failed": total_failed,
        "total_signups": total_signups, "failed_rate": round(failed_rate, 1),
        "login_chart": login_chart, "signup_chart": signup_chart,
        "brute_total": int(brute_total), "brute_chart": brute_chart,
        "brute_top_hashes": brute_top_hashes,
        "total_events": total_events, "events_chart": events_chart,
        "sec_by_category": sec_by_category, "sec_by_severity": sec_by_severity,
        "sec_by_source": sec_by_source, "sec_by_type": sec_by_type,
        "total_incidents": total_incidents,
        "inc_by_verdict": inc_by_verdict, "inc_by_status": inc_by_status,
        "total_assessments": total_assessments,
        "assess_by_status": assess_by_status,
        "finding_by_severity": finding_by_severity,
        "total_cyb": total_cyb, "cyb_chart": cyb_chart,
        "cyb_by_class": cyb_by_class, "cyb_by_source": cyb_by_source,
        "reviewed_total": len(reviewed),
        "reviewed_by_status": sorted(reviewed_by_status.items(), key=lambda kv: -kv[1]),
        "reviewed_by_prediction": sorted(reviewed_by_prediction.items(), key=lambda kv: -kv[1]),
        "recent": recent, "all_time": all_time,
    })

@router.get("/reports/security", response_class=HTMLResponse)
def admin_security_reports(request: Request, test_type: str | None = None, status: str | None = None, severity: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return templates.TemplateResponse("admin_reports_security.html", {"request": request, "current_user": user, "user": user, "filters": {"test_type": test_type or "", "status": status or "", "severity": severity or ""}})

@router.get("/reports/security/{rid}", response_class=HTMLResponse)
def admin_security_report_detail(rid: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.security_lab import SecurityLabRun
    from app.models.attact_assessment import SecurityEvent
    import json as _j
    run = db.query(SecurityLabRun).filter(SecurityLabRun.id == rid).first()
    if not run:
        raise HTTPException(status_code=404)
    try: eids=_j.loads(run.event_ids or "[]")
    except Exception: eids=[]
    events=[]
    if eids:
        rows=db.query(SecurityEvent).filter(SecurityEvent.id.in_(eids)).all()
        events=[{"id": x.id, "event_type": x.event_type, "category": x.category, "severity": x.severity, "source": x.source, "evidence": (x.evidence or "")[:1200], "correlation_id": x.correlation_id, "created_at": x.created_at} for x in rows]
    # linked incident / candidate
    incident=None; candidate=None
    try:
        if getattr(run,"incident_id",None):
            from app.models.sentinel_incident import SentinelIncident
            incident=db.query(SentinelIncident).filter(SentinelIncident.id==run.incident_id).first()
    except Exception: pass
    try:
        if getattr(run,"training_candidate_id",None):
            from app.models.training_example import TrainingExample
            candidate=db.query(TrainingExample).filter(TrainingExample.id==run.training_candidate_id).first()
    except Exception: pass
    try: meta=_j.loads(run.meta_json or "{}")
    except Exception: meta={}
    try: fusion=_j.loads(run.fusion_json) if getattr(run,"fusion_json",None) else None
    except Exception: fusion=None
    return templates.TemplateResponse("admin_reports_security_detail.html", {"request": request, "current_user": user, "user": user, "run": run, "events": events, "incident": incident, "candidate": candidate, "meta": meta, "fusion": fusion})

@router.get("/assessments/{aid}", response_class=HTMLResponse)
def assessment_detail(aid: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.attact_assessment import AttactFinding
    a = db.query(AttactAssessment).filter(AttactAssessment.id == aid).first()
    if not a:
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    findings = db.query(AttactFinding).filter(AttactFinding.assessment_id == aid).all()
    return templates.TemplateResponse("admin_security_detail.html", {"request": request, "current_user": user, "user": user, "assessment": a, "findings": findings})

# ---------------------------------------------------------------------------
# Controlled async submit for Sentinel analysis (admin-gated, not middleware)
# ---------------------------------------------------------------------------

from fastapi import BackgroundTasks, HTTPException
from pydantic import BaseModel

class AnalyzeEventBody(BaseModel):
    event_id: int

class AnalyzeFindingBody(BaseModel):
    finding_id: int

def _run_event_analysis_bg(event_id: int, triggered_by: int | None):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        from app.services.sentinel_bridge import submit_security_event_for_analysis
        submit_security_event_for_analysis(db, event_id=event_id, triggered_by=triggered_by)
    except Exception as exc:
        import logging as _lg
        _lg.getLogger("sentientai.admin_security").exception("bg event analysis %s failed: %s", event_id, exc)
    finally:
        try: db.close()
        except Exception: pass

def _run_finding_analysis_bg(finding_id: int, triggered_by: int | None):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        from app.services.sentinel_bridge import submit_attact_finding_for_analysis
        submit_attact_finding_for_analysis(db, finding_id=finding_id, triggered_by=triggered_by)
    except Exception as exc:
        import logging as _lg
        _lg.getLogger("sentientai.admin_security").exception("bg finding analysis %s failed: %s", finding_id, exc)
    finally:
        try: db.close()
        except Exception: pass

@router.post("/analyze/event")
def analyze_event(body: AnalyzeEventBody, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    ev = db.query(SecurityEvent).filter(SecurityEvent.id == body.event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="event not found")
    # idempotency fast-path: already linked
    if ev.incident_id is not None:
        return {"status": "already_linked", "event_id": ev.id, "incident_id": ev.incident_id}
    # schedule background; logging of event already succeeded (deterministic)
    background_tasks.add_task(_run_event_analysis_bg, body.event_id, user.id)
    # also attempt synchronous short-circuit for tests (uses same DB session) if ?sync=1
    if request.query_params.get("sync") == "1":
        from app.services.sentinel_bridge import submit_security_event_for_analysis
        try:
            res = submit_security_event_for_analysis(db, event_id=body.event_id, triggered_by=user.id, request=request)
            inc = res.get("incident")
            return {"status": res.get("reason", "created"), "event_id": body.event_id, "incident_id": getattr(inc, "id", None), "is_duplicate": res.get("is_duplicate", False), "fused": res.get("fused")}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)[:500])
    return {"status": "queued", "event_id": body.event_id}

@router.post("/analyze/finding")
def analyze_finding(body: AnalyzeFindingBody, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.attact_assessment import AttactFinding
    f = db.query(AttactFinding).filter(AttactFinding.id == body.finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    if f.incident_id is not None:
        return {"status": "already_linked", "finding_id": f.id, "incident_id": f.incident_id}
    background_tasks.add_task(_run_finding_analysis_bg, body.finding_id, user.id)
    if request.query_params.get("sync") == "1":
        from app.services.sentinel_bridge import submit_attact_finding_for_analysis
        try:
            res = submit_attact_finding_for_analysis(db, finding_id=body.finding_id, triggered_by=user.id, request=request)
            inc = res.get("incident")
            return {"status": res.get("reason", "created"), "finding_id": body.finding_id, "incident_id": getattr(inc, "id", None), "is_duplicate": res.get("is_duplicate", False), "fused": res.get("fused")}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)[:500])
    return {"status": "queued", "finding_id": body.finding_id}

