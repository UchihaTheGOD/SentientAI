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

# --- Prompt.txt structured contract ---
SENTINEL_VERDICTS = {"likely_benign", "needs_review", "likely_threat"}
SENTINEL_INPUT_STATUSES = {"valid", "empty", "malformed", "insufficient_evidence"}

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

def validate_sentinel_output(text: str | None, status: str | None = None) -> dict[str, Any]:
    raw = text or ""
    errors: list[str] = []
    if not raw.strip():
        errors.append("empty output")
        return {"valid": False, "verdict": None, "input_status": None, "summary": None, "indicators": None, "reasoning": None, "errors": errors, "raw_text": raw, "raw_status": status}
    has_summary = bool(re.search(r"^summary\s*:", raw, flags=re.IGNORECASE | re.MULTILINE))
    has_indicators = bool(re.search(r"^indicators\s*:", raw, flags=re.IGNORECASE | re.MULTILINE))
    has_reasoning = bool(re.search(r"^reasoning\s*:", raw, flags=re.IGNORECASE | re.MULTILINE))
    has_provisional = bool(re.search(r"provisional assessment\s*:", raw, flags=re.IGNORECASE))
    has_input_status = bool(re.search(r"input status\s*:", raw, flags=re.IGNORECASE))
    if not has_summary:
        errors.append("missing Summary section")
    if not has_indicators:
        errors.append("missing Indicators section")
    if not has_reasoning:
        errors.append("missing Reasoning section")
    if not has_provisional:
        errors.append("missing Provisional assessment")
    if not has_input_status:
        errors.append("missing Input status")
    verdict = None
    pm = re.search(r"provisional assessment\s*:\s*(likely_benign|needs_review|likely_threat)", raw, flags=re.IGNORECASE)
    if pm:
        verdict = pm.group(1).strip().lower()
        if verdict not in SENTINEL_VERDICTS:
            errors.append(f"invalid provisional verdict: {pm.group(1)!r}")
            verdict = None
        if len(re.findall(r"provisional assessment\s*:", raw, flags=re.IGNORECASE)) > 1:
            errors.append("multiple Provisional assessment sections")
            verdict = None
        # also reject if the provisional line contains more than one distinct verdict token
        pl = re.search(r"provisional assessment\s*:.*", raw, flags=re.IGNORECASE)
        if pl and len([v for v in SENTINEL_VERDICTS if v in pl.group(0).lower()]) > 1:
            errors.append("multiple verdicts in provisional line")
            verdict = None
    else:
        if has_provisional:
            pr = re.search(r"provisional assessment\s*:.*", raw, flags=re.IGNORECASE)
            errors.append(f"invalid provisional verdict value: {(pr.group(0)[:120] if pr else '')!r}")
    input_status = None
    im = re.search(r"input status\s*:\s*(valid|empty|malformed|insufficient_evidence)", raw, flags=re.IGNORECASE)
    if im:
        input_status = im.group(1).strip().lower()
        if input_status not in SENTINEL_INPUT_STATUSES:
            errors.append(f"invalid input status: {im.group(1)!r}")
            input_status = None
    else:
        if has_input_status:
            ir = re.search(r"input status\s*:.*", raw, flags=re.IGNORECASE)
            errors.append(f"invalid input status value: {(ir.group(0)[:120] if ir else '')!r}")
    summary = indicators = reasoning = None
    try:
        m = re.search(r"summary\s*:\s*(.*?)(?=\n\s*indicators\s*:|\n\s*reasoning\s*:|\n\s*provisional assessment\s*:|\n\s*input status\s*:|\Z)", raw, flags=re.IGNORECASE | re.DOTALL)
        if m:
            summary = m.group(1).strip()[:800]
            if not summary:
                errors.append("Summary section empty")
        m2 = re.search(r"indicators\s*:\s*(.*?)(?=\n\s*reasoning\s*:|\n\s*provisional assessment\s*:|\n\s*input status\s*:|\Z)", raw, flags=re.IGNORECASE | re.DOTALL)
        if m2:
            block = m2.group(1).strip()
            lines = [l.strip() for l in block.splitlines() if l.strip()]
            indicators = [l[:300] for l in lines][:10]
            if not indicators:
                errors.append("Indicators section empty")
            elif len(indicators) == 1 and indicators[0].lower() in ("none observed", "none", "- none observed"):
                indicators = ["None observed"]
        m3 = re.search(r"reasoning\s*:\s*(.*?)(?=\n\s*provisional assessment\s*:|\n\s*input status\s*:|\Z)", raw, flags=re.IGNORECASE | re.DOTALL)
        if m3:
            reasoning = m3.group(1).strip()[:1200]
            if not reasoning:
                errors.append("Reasoning section empty")
    except Exception as exc:
        errors.append(f"section extract failed: {exc}")
    if status and status != "ok":
        errors.append(f"inference status not ok: {status}")
    valid = len(errors) == 0 and verdict is not None and input_status is not None and has_summary and has_indicators and has_reasoning
    return {"valid": bool(valid), "verdict": verdict, "input_status": input_status, "summary": summary, "indicators": indicators, "reasoning": reasoning, "errors": errors, "raw_text": raw, "raw_status": status}

def parse_sentinel_text(text: str | None, status: str | None = None) -> dict[str, Any]:
    v = validate_sentinel_output(text, status)
    if v["valid"]:
        sev = "high" if v["verdict"] == "likely_threat" else "medium" if v["verdict"] == "needs_review" else "info"
        return {"vulnerability_detected": v["verdict"] == "likely_threat", "category": None, "severity": sev, "confidence": "low", "evidence": v["indicators"] or [], "reasoning_summary": v["reasoning"] or v["summary"] or "", "remediation": "", "limitations": ["parsed from structured output; requires human review"], "raw_status": status, "parse_error": None, "structured_valid": True, "verdict": v["verdict"], "input_status": v["input_status"], "validation_errors": []}
    return {"vulnerability_detected": None, "category": None, "severity": "info", "confidence": "low", "evidence": [], "reasoning_summary": "", "remediation": "", "limitations": ["model produced no usable output"] + v["errors"], "raw_status": status, "parse_error": "; ".join(v["errors"]) if v["errors"] else "invalid output", "structured_valid": False, "verdict": None, "input_status": v.get("input_status"), "validation_errors": v["errors"]}


def parse_model_text(text: str | None, status: str | None) -> dict[str, Any]:
    """Parse model output. Tries strict structured first, falls back to legacy heuristic (marked invalid)."""
    if not text or (status and status in ("empty","error","timeout","unavailable")):
        return {"vulnerability_detected": None, "category": None, "severity": "info", "confidence": "low", "evidence": [], "reasoning_summary": "", "remediation": "", "limitations": ["model produced no usable output"], "raw_status": status, "parse_error": None, "structured_valid": False, "verdict": None, "input_status": None, "validation_errors": ["empty or error status"]}
    strict = validate_sentinel_output(text, status)
    if strict["valid"]:
        return parse_sentinel_text(text, status)
    low = text.lower()
    vuln = None
    if any(k in low for k in ["likely_threat","high risk","exploitable","vulnerable","attack detected"]):
        vuln = True
    elif any(k in low for k in ["likely_benign","no threat","no indicator","benign"]):
        vuln = False
    cat = None
    for c in ["sqli","xss","traversal","csrf","auth","access","cors","injection","path traversal"]:
        if c in low:
            cat = _norm_cat(c) or c
            break
    sev = "medium"
    if any(k in low for k in ["critical","high"]):
        sev = "high"
    elif "low" in low:
        sev = "low"
    elif "info" in low:
        sev = "info"
    conf = "low"
    if "high confidence" in low:
        conf = "high"
    elif "medium" in low:
        conf = "medium"
    ev = [l.strip()[:300] for l in text.splitlines() if l.strip()][:6]
    return {"vulnerability_detected": vuln, "category": cat, "severity": sev, "confidence": conf, "evidence": ev, "reasoning_summary": text[:800], "remediation": "", "limitations": ["parsed from free-text; requires human review"] + strict["errors"], "raw_status": status, "parse_error": "; ".join(strict["errors"]) if strict["errors"] else None, "structured_valid": False, "verdict": strict.get("verdict"), "input_status": strict.get("input_status"), "validation_errors": strict["errors"]}

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
