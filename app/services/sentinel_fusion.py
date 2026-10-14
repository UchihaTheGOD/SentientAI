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
def _count_failed_logins(text: str) -> int:
    t = (text or "").lower()
    lines = t.splitlines()
    c = 0
    for ln in lines:
        if any(k in ln for k in ["failed", "invalid", "unauthorized", " 401", " 403", "login failed", "authentication failed"]):
            c += 1
    return c
def _success_after_fail(text: str) -> bool:
    t = (text or "").lower()
    lines = t.splitlines()
    fail_idx = next((i for i,l in enumerate(lines) if any(k in l for k in ["failed","invalid","unauthorized"," 401"," 403"])), -1)
    succ_idx = next((i for i,l in enumerate(lines) if any(k in l for k in ["login success","authenticated"," 200"," success"])), -1)
    return succ_idx > fail_idx and fail_idx != -1 and succ_idx != -1
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
def fuse(log_text: str, inference: dict) -> dict:
    rules = evaluate_rules(log_text)
    ma = (inference.get("model_a") or {})
    mb = (inference.get("model_b") or {})
    ta = (ma.get("text") or "")
    tb = (mb.get("text") or "")
    va = _verdict_from_model_text(ta)
    vb = _verdict_from_model_text(tb)
    agreement = inference.get("agreement")
    model_scores = {"likely_benign": 10, "needs_review": 50, "likely_threat": 85}
    components = []
    components.append({"source":"rules","verdict":rules["verdict"],"score":rules["score"],"evidence":rules["evidence"]})
    total = rules["score"] * 0.5
    w_sum = 0.5
    for ver, label in [(va, "model_a"), (vb, "model_b")]:
        if ver:
            ms = model_scores.get(ver, 50)
            status_ok = (ma if label=="model_a" else mb).get("status") == "ok"
            w = 0.25 if status_ok else 0.12
            components.append({"source":label,"verdict":ver,"score":ms,"evidence":[f"model output contains '{ver}'"],"status": (ma if label=="model_a" else mb).get("status")})
            total += ms * w
            w_sum += w
        else:
            components.append({"source":label,"verdict":None,"score":None,"evidence":["no verdict keyword in output"],"status": (ma if label=="model_a" else mb).get("status")})
    num = rules["score"]*0.5
    den = 0.5
    for ver, label in [(va,"model_a"),(vb,"model_b")]:
        if ver:
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
    return {"fused_score": fused_score, "fused_verdict": fused_verdict, "rules": rules, "components": components, "agreement": agreement, "note": note, "model_a_verdict": va, "model_b_verdict": vb}
