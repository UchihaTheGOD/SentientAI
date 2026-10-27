"""Evaluation matrix — independent ground-truth harness for Sentinel."""
from __future__ import annotations
import json, time, re
from typing import Dict, Any, List, Optional
from pathlib import Path

EVAL_CASES: List[Dict[str, Any]] = [
    {"id": "benign-01", "category": "benign", "subcategory": "word_contains_select", "ground_truth": "benign", "log_text": "2024-01-01 10:00:00 INFO user alice viewed SELECTION committee report 200"},
    {"id": "benign-02", "category": "benign", "subcategory": "normal_fetch", "ground_truth": "benign", "log_text": "2024-01-01 10:00:01 INFO user bob fetched /blog/hello-world 200"},
    {"id": "benign-03", "category": "benign", "subcategory": "passwd_no_traversal", "ground_truth": "benign", "log_text": "2024-01-01 10:00:02 INFO backup stored etc/passwd snapshot without traversal 200"},
    {"id": "benign-04", "category": "benign", "subcategory": "single_401", "ground_truth": "benign", "log_text": "2024-01-01 10:00:03 WARN 192.168.1.50 GET /login 401 one failure"},
    {"id": "benign-05", "category": "benign", "subcategory": "task_failed_disk", "ground_truth": "benign", "log_text": "2024-01-01 10:00:04 ERROR Task failed: disk full on host db01"},
    {"id": "benign-06", "category": "benign", "subcategory": "normal_api_200", "ground_truth": "benign", "log_text": "2024-01-01 10:00:05 INFO 10.0.0.5 GET /api/posts 200 duration 12ms"},
    {"id": "benign-07", "category": "benign", "subcategory": "nmap_doc", "ground_truth": "benign", "log_text": "2024-01-01 10:00:06 INFO docs: nmap is discussed in chapter 3"},
    {"id": "benign-08", "category": "benign", "subcategory": "failed_fetch_resource", "ground_truth": "benign", "log_text": "2024-01-01 10:00:07 WARN failed to fetch resource /blog/hello-world 200"},
    {"id": "susp-01", "category": "benign", "subcategory": "two_failures", "ground_truth": "suspicious", "log_text": "\n".join(["2024-01-01 10:00:12 WARN 192.168.1.10 login failed 401"]*2)},
    {"id": "susp-02", "category": "benign", "subcategory": "win_ini_no_dots", "ground_truth": "suspicious", "log_text": "2024-01-01 10:00:13 INFO user viewed win.ini docs 200"},
    {"id": "attack-bf-01", "category": "auth_abuse", "subcategory": "brute_newline_6", "ground_truth": "attack", "log_text": "\n".join([f"2024-01-01 10:00:{i:02d} WARN 192.168.1.10 login failed for user admin 401" for i in range(6)])},
    {"id": "attack-bf-02", "category": "auth_abuse", "subcategory": "brute_singleline_space_6", "ground_truth": "attack", "log_text": " ".join([f"2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401" for _ in range(6)])},
    {"id": "attack-bf-03", "category": "auth_abuse", "subcategory": "brute_comma_6", "ground_truth": "attack", "log_text": ", ".join([f"2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401" for _ in range(6)])},
    {"id": "attack-bf-04", "category": "auth_abuse", "subcategory": "brute_pipe_6", "ground_truth": "attack", "log_text": " | ".join([f"2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401" for _ in range(6)])},
    {"id": "attack-bf-05", "category": "auth_abuse", "subcategory": "brute_json_6", "ground_truth": "attack", "log_text": " ".join(['{"event":"login","status":401,"msg":"login failed","ip":"192.168.1.10"}']*6)},
    {"id": "attack-bf-06", "category": "auth_abuse", "subcategory": "brute_syslog_6", "ground_truth": "attack", "log_text": "\n".join(['Jan 15 10:00:00 host sshd[123]: Failed password for admin from 192.168.1.10 port 22']*6)},
    {"id": "attack-bf-07", "category": "auth_abuse", "subcategory": "brute_mixed_ts", "ground_truth": "attack", "log_text": "2024-01-01T10:00:00Z 192.168.1.10 login failed 401\nJan 15 10:00:05 host sshd: Failed password for root from 192.168.1.10\n2024-01-01 10:00:10 WARN 192.168.1.10 login failed 401\n2024-01-01 10:00:11 WARN 192.168.1.10 login failed 401\n2024-01-01 10:00:12 WARN 192.168.1.10 login failed 401\n2024-01-01 10:00:13 WARN 192.168.1.10 login failed 401"},
    {"id": "attack-bf-08", "category": "auth_abuse", "subcategory": "success_after_fail_singleline", "ground_truth": "attack", "log_text": " ".join(['login failed 401']*5) + " login success 200"},
    {"id": "attack-scan-01", "category": "port_scan", "subcategory": "nmap_ports", "ground_truth": "attack", "log_text": "nmap scan " + " ".join([f"port {p} open" for p in range(8000, 8015)])},
    {"id": "attack-xss-01", "category": "xss", "subcategory": "reflected_tag", "ground_truth": "attack", "log_text": "2024-01-01 10:00:20 INFO GET /search?q=<script>alert(1)</script> 200"},
    {"id": "attack-sqli-01", "category": "sqli", "subcategory": "union_select", "ground_truth": "attack", "log_text": "2024-01-01 10:00:21 INFO GET /search?q=' UNION SELECT * FROM users-- 500"},
    {"id": "attack-trav-01", "category": "traversal", "subcategory": "dots_etc_passwd", "ground_truth": "attack", "log_text": "2024-01-01 10:00:22 INFO GET /download?file=../../etc/passwd 200"},
    {"id": "attack-cmdi-01", "category": "cmdi", "subcategory": "command_injection", "ground_truth": "attack", "log_text": "2024-01-01 10:00:30 INFO GET /api/run?cmd=; cat /etc/passwd 200"},
    {"id": "attack-ssrf-01", "category": "ssrf", "subcategory": "metadata_ip", "ground_truth": "attack", "log_text": "2024-01-01 10:00:31 INFO GET /fetch?url=http://169.254.169.254/latest/meta-data/ 200"},
    {"id": "attack-ssti-01", "category": "ssti", "subcategory": "template", "ground_truth": "attack", "log_text": "2024-01-01 10:00:32 INFO GET /render?tpl={{7*7}} 200"},
    {"id": "attack-upload-01", "category": "upload", "subcategory": "null_byte", "ground_truth": "attack", "log_text": "2024-01-01 10:00:33 INFO POST /upload filename=shell.php%00.jpg 200"},
]

def _try_parse_json(text):
    import json as _j
    if not text or not text.strip():
        return {"parsed": None, "valid": False, "error": "empty"}
    import re as _re
    m = _re.search(r'\{.*\}', text, _re.DOTALL)
    cand = m.group(0) if m else text
    try:
        obj = _j.loads(cand)
    except Exception as e:
        return {"parsed": None, "valid": False, "error": f"json_parse_error:{type(e).__name__}"}
    if not isinstance(obj, dict):
        return {"parsed": obj, "valid": False, "error": "not_object"}
    if "verdict" not in obj:
        return {"parsed": obj, "valid": False, "error": "missing_verdict"}
    if obj["verdict"] not in ("likely_benign", "needs_review", "likely_threat"):
        return {"parsed": obj, "valid": False, "error": "invalid_verdict"}
    return {"parsed": obj, "valid": True, "error": None}

def _verdict_from_text(text):
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

GROUND_TO_EXPECTED = {"benign": "likely_benign", "suspicious": "likely_benign", "attack": "likely_threat"}
IS_POSITIVE_GT = {"benign": False, "suspicious": False, "attack": True}
IS_POSITIVE_PRED = {"likely_benign": False, "needs_review": True, "likely_threat": True}

def evaluate_case(case, with_models=False, max_new_tokens=48, timeout_s=12):
    from app.services.security_rules import evaluate_rules
    from app.services.classifier import fuse_classification
    import time as _t
    log_text = case["log_text"]
    t0 = _t.perf_counter()
    rules = evaluate_rules(log_text)
    rule_ms = int((_t.perf_counter()-t0)*1000)
    rec = {"id": case["id"],"category": case["category"],"subcategory": case["subcategory"],"ground_truth": case["ground_truth"],"expected_verdict": GROUND_TO_EXPECTED.get(case["ground_truth"]),"is_positive_gt": IS_POSITIVE_GT.get(case["ground_truth"], False),"log_text": log_text,"log_len": len(log_text),"rules": {"verdict": rules.get("verdict"), "score": rules.get("score"), "evidence": rules.get("evidence"), "failed_count": rules.get("failed_count"), "latency_ms": rule_ms, "raw": rules},"fusion": None,"classification": None,"model_a": None,"model_b": None,"agreement": None,"fusion_latency_ms": None}
    if not with_models:
        fused = fuse_classification(log_text, {"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low", "deterministic_findings": []})
        rec["fusion"] = {"verdict": fused.get("fused_verdict"), "score": fused.get("fused_score"), "components": fused.get("components")}
        rec["fusion_latency_ms"] = 0
        return rec
    from app.services.classifier import classify_log
    t1 = _t.perf_counter()
    inf = classify_log(log_text, kind="log", max_new_tokens=max_new_tokens)
    total_ms = int((_t.perf_counter()-t1)*1000)
    # Single CyberLLMv1 classification (no dual model, no agreement).
    rec["classification"] = {"classification": inf.get("classification"), "confidence": inf.get("confidence"),
                             "status": inf.get("status"), "summary": inf.get("summary"),
                             "output_tokens": inf.get("output_tokens"), "latency_ms": inf.get("latency_ms"),
                             "raw_output": inf.get("raw_output"), "error": inf.get("error"),
                             "json_valid": inf.get("parse_ok")}
    rec["model_a"] = None
    rec["model_b"] = None
    rec["agreement"] = None
    fused = fuse_classification(log_text, inf)
    rec["fusion"] = {"verdict": fused.get("fused_verdict"), "score": fused.get("fused_score"), "components": fused.get("components"), "note": fused.get("note")}
    rec["fusion_latency_ms"] = total_ms
    return rec

def _prf(tp, fp, fn):
    precision = tp/(tp+fp) if (tp+fp) else None
    recall = tp/(tp+fn) if (tp+fn) else None
    f1 = (2*precision*recall/(precision+recall)) if (precision is not None and recall is not None and (precision+recall)) else None
    return precision, recall, f1

def aggregate_metrics(records):
    sources = ["rules", "classification", "fusion"]
    out = {}
    for src in sources:
        tp=fp=tn=fn=0
        empty=invalid_json=total=0
        per_category={}
        for r in records:
            gt_pos = r["is_positive_gt"]
            if src == "rules":
                pred_verdict = (r["rules"] or {}).get("verdict")
            elif src == "fusion":
                pred_verdict = (r["fusion"] or {}).get("verdict")
            else:
                m = r.get(src) or {}
                pred_verdict = m.get("parsed_verdict") or m.get("classification")
                if m.get("status") in ("empty", None) or not pred_verdict:
                    empty += 1
                if not m.get("json_valid"):
                    invalid_json += 1
            if pred_verdict not in ("likely_benign","needs_review","likely_threat"):
                pred_pos = False
                if src in ("rules","fusion") and pred_verdict is None:
                    empty += 1
            else:
                pred_pos = IS_POSITIVE_PRED.get(pred_verdict, False)
            if gt_pos and pred_pos:
                tp+=1
            elif not gt_pos and pred_pos:
                fp+=1
            elif not gt_pos and not pred_pos:
                tn+=1
            elif gt_pos and not pred_pos:
                fn+=1
            total+=1
            cat = r["category"]
            per_category.setdefault(cat, {"tp":0,"fp":0,"tn":0,"fn":0,"n":0})
            per_category[cat]["n"]+=1
            if gt_pos and pred_pos:
                per_category[cat]["tp"]+=1
            elif not gt_pos and pred_pos:
                per_category[cat]["fp"]+=1
            elif not gt_pos and not pred_pos:
                per_category[cat]["tn"]+=1
            elif gt_pos and not pred_pos:
                per_category[cat]["fn"]+=1
        precision, recall, f1 = _prf(tp,fp,fn)
        out[src] = {"n": total, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "empty": empty, "invalid_json": invalid_json if src == "classification" else None, "per_category": per_category}
    return out

def run_evaluation(with_models=False, max_new_tokens=48, timeout_s=12, output_dir="evaluation"):
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for case in EVAL_CASES:
        rec = evaluate_case(case, with_models=with_models, max_new_tokens=max_new_tokens, timeout_s=timeout_s)
        records.append(rec)
    metrics = aggregate_metrics(records)
    ts = time.strftime("%Y%m%d_%H%M%S")
    payload = {"meta": {"n_cases": len(records), "with_models": with_models, "timestamp": ts, "model": "CyberLLMv1 (Qwen3-1.7B + LoRA v8, data-v3.2)"}, "cases": records, "metrics": metrics}
    (out_dir / "latest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / f"results_{ts}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel evaluation matrix")
    parser.add_argument("--with-models", action="store_true")
    parser.add_argument("--max-new-tokens", type=int, default=48)
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--output-dir", type=str, default="evaluation")
    args = parser.parse_args()
    payload = run_evaluation(with_models=args.with_models, max_new_tokens=args.max_new_tokens, timeout_s=args.timeout, output_dir=args.output_dir)
    print(json.dumps(payload["metrics"], indent=2))
