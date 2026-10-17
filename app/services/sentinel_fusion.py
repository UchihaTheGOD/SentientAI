"""Fusion + deterministic rules — transparent layer over model outputs."""
from __future__ import annotations
import re
import ipaddress
import logging
logger = logging.getLogger("sentientai.sentinel.fusion")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
def _extract_ips(text: str) -> list[str]:
    cands = IP_RE.findall(text or "")
    out = []
    for c in cands:
        try:
            ipaddress.ip_address(c)
            out.append(c)
        except Exception:
            pass
    return list(dict.fromkeys(out))

def _segment_log_text(text: str) -> list[str]:
    if not text or not text.strip():
        return []
    tmp = text
    tmp = re.sub(r'\s*\|\s*', '\n', tmp)
    tmp = re.sub(r'\s*;\s*', '\n', tmp)
    tmp = re.sub(r'\}\s*\{', '}\n{', tmp)
    tmp = re.sub(r'\}\s*,\s*\{', '}\n{', tmp)
    tmp = re.sub(r'(?=\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', '\n', tmp)
    tmp = re.sub(r'(?=\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', '\n', tmp)
    segments = [s.strip() for s in tmp.splitlines() if s.strip()]
    if len(segments) == 1 and len(text) > 200:
        alt = re.sub(r'(?=\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*?(?:failed|401|403))', '\n', tmp, flags=re.IGNORECASE)
        alt_segs = [s.strip() for s in alt.splitlines() if s.strip()]
        if len(alt_segs) > len(segments):
            segments = alt_segs
    return segments if segments else [text.strip()]

def _segment_has_failed(seg: str) -> bool:
    t = seg.lower()
    if re.search(r'\blogin failed\b|\bauthentication failed\b|\bfailed login\b|\bfailed\b|\binvalid\b|\bunauthorized\b', t):
        return True
    if re.search(r'\b401\b|\b403\b', t):
        return True
    return False

def _count_failed_logins(text: str) -> int:
    """Count failed-login events robustly across formatting variants."""
    if not text or not text.strip():
        return 0
    segments = _segment_log_text(text)
    if len(segments) > 1:
        return sum(1 for s in segments if _segment_has_failed(s))
    seg = segments[0] if segments else ""
    if not seg:
        return 0
    t = seg.lower()
    pattern = re.compile(r'login failed|authentication failed|failed login|failed|invalid|unauthorized|\b401\b|\b403\b')
    hits = [(m.start(), m.end(), m.group(0)) for m in pattern.finditer(t)]
    if not hits:
        return 0
    collapsed = 0
    i = 0
    while i < len(hits):
        collapsed += 1
        cur_end = hits[i][1]
        j = i + 1
        while j < len(hits) and hits[j][0] - cur_end < 40:
            cur_type = "status" if hits[j][2] in ("401", "403") else "primary" if hits[i][2] not in ("401","403") else "status"
            hit_type = "status" if hits[i][2] in ("401","403") else "primary"
            nxt_type = "status" if hits[j][2] in ("401","403") else "primary"
            if hit_type != nxt_type:
                gap = t[cur_end:hits[j][0]]
                if "} " in gap or "}{" in gap:
                    break
                cur_end = hits[j][1]
                j += 1
            else:
                # same type nearby: count as separate event (e.g. "login failed login failed")
                break
        i = j
    return collapsed

def _success_after_fail(text: str) -> bool:
    t = (text or "").lower()
    if not t.strip():
        return False
    fail_pat = re.compile(r"failed|invalid|unauthorized|\b401\b|\b403\b|login failed|authentication failed")
    succ_pat = re.compile(r"login success|authenticated|\b200\b| success")
    fail_m = fail_pat.search(t)
    if not fail_m:
        return False
    for sm in succ_pat.finditer(t):
        if sm.start() > fail_m.start():
            return True
    return False
def _port_scan_indicators(text: str) -> tuple[bool, list[str]]:
    t = (text or "")
    ports = re.findall(r"port\s+(\d{1,5})", t, re.IGNORECASE)
    ports += re.findall(r"DPT[=:](\d+)", t)
    ports += re.findall(r"dport[=: ](\d+)", t, re.IGNORECASE)
    uniq = list(dict.fromkeys(ports))
    evidence = []
    if len(uniq) >= 8:
        evidence.append(f"{len(uniq)} distinct ports probed: {', '.join(uniq[:12])}")
        return True, evidence
    if any(k in t.lower() for k in ["nmap", "port scan", "syn scan"]):
        evidence.append("port scan keyword present")
        return True, evidence
    return False, evidence
def evaluate_rules(log_text: str) -> dict:
    ips = _extract_ips(log_text)
    failed = _count_failed_logins(log_text)
    scan, scan_ev = _port_scan_indicators(log_text)
    success_after = _success_after_fail(log_text)
    evidence = []
    risks = []
    score = 0
    if failed >= 5:
        evidence.append(f"repeated failed logins: {failed} occurrences (threshold 5)")
        score += 40
        risks.append("auth_abuse")
    if success_after:
        evidence.append("successful login after repeated failures (possible brute-force success)")
        score += 25
        risks.append("success_after_fail")
    if scan:
        evidence.extend(scan_ev)
        score += 35
        risks.append("port_scan")
    if failed > 0 and not scan and len(ips) == 1 and failed >= 3:
        evidence.append(f"single IP {ips[0] if ips else 'unknown'} repeated failures")
    score = min(100, score)
    if score >= 60:
        verdict = "likely_threat"
    elif score >= 30:
        verdict = "needs_review"
    else:
        verdict = "likely_benign"
    return {"score": score, "verdict": verdict, "evidence": evidence, "risks": risks, "ips": ips, "failed_count": failed, "success_after_fail": success_after, "port_scan": scan}
def _verdict_from_model_text(text: str) -> str | None:
    """Legacy keyword heuristic (used only when strict validation unavailable)."""
    t = (text or "").lower()
    for v in ["likely_threat","needs_review","likely_benign"]:
        if v in t:
            return v
    if any(k in t for k in ["likely threat","high risk","malicious","attack"]):
        return "likely_threat"
    if any(k in t for k in ["benign","normal","no threat","no indicator"]):
        return "likely_benign"
    if any(k in t for k in ["review","suspicious","inconclusive","uncertain"]):
        return "needs_review"
    return None

def _structured_verdict(text: str | None, status: str | None) -> tuple[str | None, bool, list[str]]:
    """Return (verdict, is_valid_structured, errors) using strict Sentinel validation.

    Only outputs passing validate_sentinel_output are considered valid model
    verdicts. Invalid/empty outputs return (None, False, errors) and must not
    contribute confidence to fusion.
    """
    try:
        from app.services.sentinel_schema import validate_sentinel_output
        res = validate_sentinel_output(text, status)
        if res["valid"]:
            return res["verdict"], True, []
        return None, False, res["errors"]
    except Exception as exc:
        return None, False, [f"validation error: {exc}"]

def fuse(log_text: str, inference: dict) -> dict:
    rules = evaluate_rules(log_text)
    ma = (inference.get("model_a") or {})
    mb = (inference.get("model_b") or {})
    ta = (ma.get("text") or "")
    tb = (mb.get("text") or "")
    # Strict validation: only structured-valid outputs count
    va, va_valid, va_errors = _structured_verdict(ta, ma.get("status"))
    vb, vb_valid, vb_errors = _structured_verdict(tb, mb.get("status"))
    # Fallback for backward compat only if needed for diagnostics, but not fused:
    # legacy keywords are recorded as legacy_verdict but not weighted unless valid
    legacy_va = _verdict_from_model_text(ta) if not va_valid else None
    legacy_vb = _verdict_from_model_text(tb) if not vb_valid else None
    agreement = inference.get("agreement")
    model_scores = {"likely_benign": 10, "needs_review": 50, "likely_threat": 85}
    components = []
    components.append({"source":"rules","verdict":rules["verdict"],"score":rules["score"],"evidence":rules["evidence"]})
    total = rules["score"] * 0.5
    w_sum = 0.5
    for ver, label, is_valid, errs, legacy in [(va, "model_a", va_valid, va_errors, legacy_va), (vb, "model_b", vb_valid, vb_errors, legacy_vb)]:
        if ver and is_valid:
            ms = model_scores.get(ver, 50)
            status_ok = (ma if label=="model_a" else mb).get("status") == "ok"
            w = 0.25 if status_ok else 0.12
            components.append({"source":label,"verdict":ver,"score":ms,"evidence":[f"model output contains '{ver}' (structured valid)"],"status": (ma if label=="model_a" else mb).get("status"), "structured_valid": True})
            total += ms * w
            w_sum += w
        else:
            # Record why invalid; never assign fabricated confidence
            detail = "; ".join(errs[:2]) if errs else "no verdict keyword in output"
            if legacy and not is_valid:
                detail = f"legacy keyword '{legacy}' ignored (invalid structure: {detail})"
            components.append({"source":label,"verdict":None,"score":None,"evidence":[detail],"status": (ma if label=="model_a" else mb).get("status"), "structured_valid": False, "validation_errors": errs})
    num = rules["score"]*0.5
    den = 0.5
    for ver, label, is_valid in [(va,"model_a", va_valid),(vb,"model_b", vb_valid)]:
        if ver and is_valid:
            w = 0.25 if ((ma if label=="model_a" else mb).get("status")=="ok") else 0.12
            num += model_scores[ver]*w
            den += w
    fused_score = int(round(num/den)) if den else rules["score"]
    if fused_score >= 65:
        fused_verdict = "likely_threat"
    elif fused_score >= 35:
        fused_verdict = "needs_review"
    else:
        fused_verdict = "likely_benign"
    note = "Models A and B are same family (Sentinel finetune); agreement is not independent confirmation"
    return {"fused_score": fused_score, "fused_verdict": fused_verdict, "rules": rules, "components": components, "agreement": agreement, "note": note, "model_a_verdict": va, "model_b_verdict": vb, "model_a_valid": va_valid, "model_b_valid": vb_valid}
