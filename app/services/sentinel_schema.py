"""Structured Sentinel model output parser + 4-way fusion.

Real models emit free-text; we parse for: vulnerability_detected, category,
severity, confidence, evidence, reasoning_summary, remediation, limitations.
Fallbacks handle empty/error/timeout gracefully.
"""
from __future__ import annotations
import re, json, logging
from typing import Any

logger = logging.getLogger("sentientai.sentinel.schema")

CATEGORIES = {"sqli","xss","traversal","auth","access","csrf","methods","rate-limit","headers-cookies","info-disclosure","benign","unknown"}

def _norm_cat(raw: str | None) -> str | None:
    if not raw:
        return None
    s = re.sub(r"[^a-z0-9-]", "-", raw.strip().lower())
    s = re.sub(r"-+", "-", s).strip("-")
    if s in CATEGORIES:
        return s
    # aliases
    alias = {"injection": "sqli", "cross-site": "xss", "path-traversal":"traversal","authz":"access","cors":"headers-cookies"}
    return alias.get(s)

def parse_model_text(text: str | None, status: str | None) -> dict[str, Any]:
    """Parse free-text model output into structured fields. Never raises."""
    if not text or (status and status in ("empty","error","timeout","unavailable")):
        return {
            "vulnerability_detected": None, "category": None, "severity": "info",
            "confidence": "low", "evidence": [], "reasoning_summary": "",
            "remediation": "", "limitations": ["model produced no usable output"],
            "raw_status": status, "parse_error": None,
        }
    low = text.lower()
    # vulnerability flag
    vuln = None
    if any(k in low for k in ["likely_threat","high risk","exploitable","vulnerable","attack detected"]):
        vuln = True
    elif any(k in low for k in ["likely_benign","no threat","no indicator","benign"]):
        vuln = False
    # category hint
    cat = None
    for c in ["sqli","xss","traversal","csrf","auth","access","cors","injection","path traversal"]:
        if c in low:
            cat = _norm_cat(c) or c
            break
    # severity
    sev = "medium"
    if any(k in low for k in ["critical","high"]):
        sev = "high"
    elif "low" in low:
        sev = "low"
    elif "info" in low:
        sev = "info"
    # confidence
    conf = "low"
    if "high confidence" in low:
        conf = "high"
    elif "medium" in low:
        conf = "medium"
    # evidence lines (bounded)
    ev = [l.strip()[:300] for l in text.splitlines() if l.strip()][:6]
    return {
        "vulnerability_detected": vuln,
        "category": cat,
        "severity": sev,
        "confidence": conf,
        "evidence": ev,
        "reasoning_summary": text[:800],
        "remediation": "",
        "limitations": ["parsed from free-text; requires human review"],
        "raw_status": status,
        "parse_error": None,
    }

def _verdict(score: int) -> str:
    if score >= 65:
        return "likely_threat"
    if score >= 35:
        return "needs_review"
    return "likely_benign"

def fuse_structured(log_text: str, inference: dict, rules: dict | None = None) -> dict[str, Any]:
    """4-way compare: Model A, Model B, rules, fusion.

    Returns dict with model_a_struct/model_b_struct/rules/fused and ground truth placeholder.
    """
    from app.services.sentinel_fusion import evaluate_rules as _eval, fuse as _fuse
    if rules is None:
        rules = _eval(log_text)
    # base fusion already combines rules+model verdicts
    legacy = _fuse(log_text, inference)
    ma = (inference.get("model_a") or {})
    mb = (inference.get("model_b") or {})
    sa = parse_model_text(ma.get("text"), ma.get("status"))
    sb = parse_model_text(mb.get("text"), mb.get("status"))
    # agreement on vulnerability flag
    agreement = None
    if sa["vulnerability_detected"] is not None and sb["vulnerability_detected"] is not None:
        agreement = sa["vulnerability_detected"] == sb["vulnerability_detected"]
    return {
        "model_a_struct": sa,
        "model_b_struct": sb,
        "rules": rules,
        "legacy_fusion": legacy,
        "fused_verdict": legacy.get("fused_verdict"),
        "fused_score": legacy.get("fused_score"),
        "agreement": agreement,
        "note": legacy.get("note"),
        "components": legacy.get("components"),
    }
