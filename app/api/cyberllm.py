"""CyberLLM API — fine-tuned cybersecurity model analysis for SentientAI.

Follows the existing /api/sentinel/analyze conventions: authenticated
requests, validate_log_text input validation (8000-char cap), structured
JSON validation before anything is returned, and honest failure modes.

Endpoints:
  GET  /api/cyberllm/readiness        model/backend status (never claims a
                                       load that did not happen)
  POST /api/cyberllm/readiness/load   admin-only explicit load
  POST /api/cyberllm/screen           deterministic rules only, no model
  POST /api/cyberllm/analyze          full pipeline; 503 when the model is
                                       unavailable, with the real reason

Safety contract (mirrors the Sentinel moderation contract's honesty rule):
- Unparseable/truncated model output -> needs_review, confidence low, raw
  text preserved, no fabricated classification.
- Low-confidence output -> needs_review.
- A high-severity deterministic finding (e.g. cloud-metadata SSRF,
  credential-file probing) can override a benign or needs-review model
  verdict to likely_threat, transparently: the model verdict stays in
  model_classification and the override evidence is shown.
- No MITRE ATT&CK field exists in any response.
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.cyberllm_analysis import CyberLLMAnalysisEvent
from app.models.user import User
from app.services import cyberllm_rules
from app.services.cyberllm_evidence import check_evidence
from app.services.auth_service import get_current_user, get_current_user_optional, require_admin
from app.services.cyberllm_identity import (
    identity_answer,
    is_identity_question,
    sanitize_cleaned_fields,
    sanitize_identity_text,
)
from app.template_env import templates
from app.services.cyberllm_inference import ModelUnavailable, generate
from app.services.cyberllm_loader import ensure_loaded, get_status
from app.services.cyberllm_schema import parse_model_output
from app.services.log_validation import MAX_LOG_CHARS, validate_log_text
from app.services.ratelimit import limit_cyberllm_analyze

logger = logging.getLogger("sentientai.cyberllm.api")
router = APIRouter(tags=["cyberllm"])


def _record_analysis_event(
    db: Session | None,
    *,
    kind: str,
    classification: str | None,
    confidence: str | None,
    decision_source: str,
    truncated: bool,
    latency_ms: int | None,
    user_id: int | None,
) -> None:
    """Best-effort per-call record for the admin Security Dashboard.

    One row per analyze call: outcome + timing only, no log text, no raw
    model output. A failed write must never break the analysis response.
    """
    if db is None:
        return
    try:
        db.add(CyberLLMAnalysisEvent(
            kind=kind,
            classification=classification,
            confidence=confidence,
            decision_source=decision_source,
            truncated=1 if truncated else 0,
            latency_ms=latency_ms,
            user_id=user_id,
        ))
        db.commit()
    except Exception:
        logger.warning("CyberLLM analysis event record failed", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass


@router.get("/api/cyberllm/readiness")
def readiness(user: User | None = Depends(get_current_user_optional)):
    """Model liveness for everyone, operational detail for signed-in users.

    The Security Lab's backend manager polls this endpoint without a
    session only to learn whether the backend answers (HTTP 200), so
    anonymous callers still get a 200 with liveness fields. Server
    paths, device, memory, adapter hash, and load time are private
    operational information and are returned only to authenticated
    callers — the base model name is not disclosed to anonymous callers.
    Model loading itself stays admin-only.
    """
    s = get_status()
    if user is None:
        return {"ready": s.ready, "state": s.state}
    return {
        "ready": s.ready,
        "state": s.state,
        "reason": s.reason,
        "base_model": s.base_model,
        "model_root": s.model_root,
        "adapter_dir": s.adapter_dir,
        "adapter_sha256": s.adapter_sha256,
        "device": s.device,
        "quantization": s.quantization,
        "load_ms": s.load_ms,
        "rss_mb": s.rss_mb,
    }


@router.get("/cyberllm", response_class=HTMLResponse)
def cyberllm_page(request: Request, user: User = Depends(get_current_user)):
    """Website form for CyberLLM analysis. Mirrors the /sentinel page: login
    required, same CSRF double-submit protection as every other form page,
    and the form calls POST /api/cyberllm/analyze — no new API surface."""
    if user is None:
        return RedirectResponse(url="/login?next=/cyberllm", status_code=303)
    s = get_status()
    return templates.TemplateResponse("cyberllm.html", {
        "request": request, "current_user": user, "user": user, "status": s,
    })


@router.post("/api/cyberllm/readiness/load")
def readiness_load(user: User = Depends(require_admin)):
    s = ensure_loaded()
    return {"ready": s.ready, "state": s.state, "reason": s.reason, "load_ms": s.load_ms}


class ScreenRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_LOG_CHARS)


@router.post("/api/cyberllm/screen")
def screen(req: ScreenRequest, user: User = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    findings = cyberllm_rules.screen(req.text)
    return {
        "findings": findings,
        "suggested_classification": cyberllm_rules.suggested_classification(findings),
        "note": "Deterministic rules only; no model inference.",
    }


class AnalyzeRequest(BaseModel):
    log_text: str = Field(..., min_length=1, max_length=MAX_LOG_CHARS)
    kind: str = Field(default="log", pattern="^(log|http_request|url|vulnerability)$")
    max_new_tokens: int | None = Field(default=None, ge=16, le=512)


@router.post("/api/cyberllm/analyze")
def analyze(
    req: AnalyzeRequest,
    user: User = Depends(get_current_user),
    _rate: None = Depends(limit_cyberllm_analyze),
    db: Session = Depends(get_db),
):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        text = validate_log_text(req.log_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    findings = cyberllm_rules.screen(text)
    # Deterministic identity path (no model call): the classification
    # template wraps every input, so an identity question would otherwise
    # be analysed as if it were a log line. Answer it directly with the
    # canonical identity ("CyberLLM developed by Gaurav Singh Bisht").
    # Shape-preserving: the same response fields as a normal analysis.
    if is_identity_question(text):
        latency_ms = 0
        _record_analysis_event(
            db, kind=req.kind, classification="likely_benign",
            confidence="high", decision_source="identity_rule",
            truncated=False, latency_ms=latency_ms, user_id=user.id,
        )
        return {
            "kind": req.kind, "classification": "likely_benign",
            "model_classification": None, "confidence": "high",
            "needs_review": False, "decision_source": "identity_rule",
            "summary": identity_answer(),
            "indicators": [], "reasoning": identity_answer(),
            "limitations": [], "recommended_actions": [],
            "deterministic_findings": findings, "parse_ok": True,
            "truncated": False, "output_tokens": 0,
            "latency_ms": latency_ms, "raw_output": None,
            "note": "Identity question answered directly; no model call.",
        }
    start = time.perf_counter()
    try:
        gen = generate(req.kind, text, max_new_tokens=req.max_new_tokens)
    except ModelUnavailable as exc:
        _record_analysis_event(
            db, kind=req.kind, classification=None, confidence=None,
            decision_source="model_unavailable", truncated=False,
            latency_ms=int((time.perf_counter() - start) * 1000),
            user_id=user.id,
        )
        raise HTTPException(status_code=503, detail={
            "error": "model_unavailable",
            "reason": str(exc),
            "deterministic_findings": findings,
            "hint": "Load the model via POST /api/cyberllm/readiness/load (admin), "
                    "or run on a machine with enough free RAM for the checkpoint.",
        }) from exc
    except Exception as exc:
        # Any other generation failure (OOM, tokenizer, runtime) is
        # also a model-unavailable condition: it must not fall
        # through to the generic 500 handler, which would discard
        # the deterministic findings computed above.
        logger.exception("CyberLLM inference failed")
        _record_analysis_event(
            db, kind=req.kind, classification=None, confidence=None,
            decision_source="model_error", truncated=False,
            latency_ms=int((time.perf_counter() - start) * 1000),
            user_id=user.id,
        )
        raise HTTPException(status_code=503, detail={
            "error": "model_error",
            "reason": f"{type(exc).__name__}: {exc}",
            "deterministic_findings": findings,
            "hint": "The model failed during generation; deterministic "
                    "rules still apply. Check the server log.",
        }) from exc
    latency_ms = int((time.perf_counter() - start) * 1000)
    # Defence in depth: generate() already sanitizes the raw output at the
    # choke point; apply the identity sanitizer again here (idempotent) so
    # the raw passthrough below can never leak a base-model identity claim.
    gen = {**gen, "raw": sanitize_identity_text(gen["raw"])[0]}
    cleaned, parse_ok = parse_model_output(gen["raw"])
    if parse_ok:
        # Sanitize the cleaned string fields as well, so no identity claim
        # survives inside summary/reasoning/indicators/limitations/actions.
        cleaned = sanitize_cleaned_fields(cleaned)
    if not parse_ok:
        _record_analysis_event(
            db, kind=req.kind, classification="needs_review",
            confidence="low", decision_source="unparseable_output",
            truncated=gen["truncated"], latency_ms=latency_ms,
            user_id=user.id,
        )
        return {
            "kind": req.kind, "classification": "needs_review",
            "model_classification": None, "confidence": "low",
            "needs_review": True, "decision_source": "unparseable_output",
            "summary": "Model output could not be parsed as valid JSON; no classification is asserted.",
            "indicators": [], "reasoning": "",
            "limitations": ["Model output was truncated or malformed; human review required."],
            "recommended_actions": [], "deterministic_findings": findings,
            "parse_ok": False, "truncated": gen["truncated"],
            "output_tokens": gen["output_tokens"], "latency_ms": latency_ms,
            "raw_output": gen["raw"],
            "note": "Unparseable output is never upgraded into a confident verdict.",
        }
    model_cls = cleaned["classification"]
    # Deterministic evidence check: numbers the model reports must agree
    # with numbers stated in the input. A mismatch (or a truncated
    # generation) never silently keeps a confident verdict.
    model_text = " ".join(
        [cleaned["summary"], cleaned["reasoning"]] + list(cleaned["indicators"])
    )
    mismatches = check_evidence(text, model_text)
    # Severity justification: a confident threat verdict with no cited
    # indicators and no reasoning is an assertion, not evidence. It is
    # downgraded to needs_review, with the original verdict preserved.
    if (
        model_cls == "likely_threat"
        and cleaned["confidence"] == "high"
        and not cleaned["indicators"]
        and len(cleaned["reasoning"].strip()) < 20
    ):
        mismatches.append(
            "severity justification: high-confidence likely_threat with "
            "no cited indicators or reasoning"
        )
    if mismatches or gen["truncated"]:
        reasons = list(mismatches)
        if gen["truncated"]:
            reasons.append("model output hit its token budget (truncated)")
        high_for_mismatch = [f for f in findings if f["severity"] == "high"]
        if not high_for_mismatch:
            _record_analysis_event(
                db, kind=req.kind, classification="needs_review",
                confidence="low",
                decision_source="evidence_mismatch" if mismatches else "truncated_output",
                truncated=gen["truncated"], latency_ms=latency_ms,
                user_id=user.id,
            )
            return {
                "kind": req.kind, "classification": "needs_review",
                "model_classification": model_cls, "confidence": "low",
                "needs_review": True,
                "decision_source": "evidence_mismatch"
                if mismatches else "truncated_output",
                **{k: cleaned[k] for k in ("summary", "indicators", "reasoning", "recommended_actions")},
                "limitations": list(cleaned["limitations"])
                + [f"Evidence inconsistency: {r}" for r in reasons],
                "deterministic_findings": findings, "parse_ok": True,
                "truncated": gen["truncated"], "output_tokens": gen["output_tokens"],
                "latency_ms": latency_ms, "raw_output": gen["raw"],
                "note": "Model output contradicts the input evidence or was "
                        "truncated; no confident verdict is asserted.",
            }
        # High-severity deterministic finding still overrides, but the
        # mismatch/truncation is preserved as a limitation, not hidden.
        cleaned = {**cleaned, "limitations": list(cleaned["limitations"])
                   + [f"Evidence inconsistency: {r}" for r in reasons]}
    high = [f for f in findings if f["severity"] == "high"]
    if high and model_cls in ("likely_benign", "needs_review"):
        # High-severity deterministic patterns (metadata SSRF, credential
        # probing) are narrow and evidence-cited; they escalate a benign or
        # uncertain model verdict to likely_threat, transparently.
        _record_analysis_event(
            db, kind=req.kind, classification="likely_threat",
            confidence="high", decision_source="deterministic_override",
            truncated=gen["truncated"], latency_ms=latency_ms,
            user_id=user.id,
        )
        return {
            "kind": req.kind, "classification": "likely_threat",
            "model_classification": model_cls, "confidence": "high",
            "needs_review": False, "decision_source": "deterministic_override",
            **{k: cleaned[k] for k in ("summary", "indicators", "reasoning", "limitations", "recommended_actions")},
            "deterministic_findings": findings, "parse_ok": True,
            "truncated": gen["truncated"], "output_tokens": gen["output_tokens"],
            "latency_ms": latency_ms, "raw_output": None,
            "note": f"Model verdict was {model_cls}; overridden to likely_threat by "
                    "high-severity deterministic finding(s). The model verdict is "
                    "preserved in model_classification for audit.",
        }
    needs_review = model_cls == "needs_review" or cleaned["confidence"] == "low"
    _record_analysis_event(
        db, kind=req.kind, classification=model_cls,
        confidence=cleaned["confidence"], decision_source="model",
        truncated=gen["truncated"], latency_ms=latency_ms,
        user_id=user.id,
    )
    return {
        "kind": req.kind, "classification": model_cls,
        "model_classification": model_cls, "confidence": cleaned["confidence"],
        "needs_review": needs_review, "decision_source": "model",
        **{k: cleaned[k] for k in ("summary", "indicators", "reasoning", "limitations", "recommended_actions")},
        "deterministic_findings": findings, "parse_ok": True,
        "truncated": gen["truncated"], "output_tokens": gen["output_tokens"],
        "latency_ms": latency_ms, "raw_output": None,
        "note": "Low-confidence model output; treat as uncertain." if needs_review else "",
    }
