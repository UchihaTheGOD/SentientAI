"""Live CyberLLM inference battery — REAL weights, via the integration code.

Usage (from the SentientAI checkout):
  CYBERLLM_BASE_DIR=<base> CYBERLLM_ADAPTER_DIR=<adapter> \\
  CYBERLLM_ADAPTER_SHA256=<sha> .venv/bin/python scripts/cyberllm_live_test.py

Loads the model through app.services.cyberllm_loader / cyberllm_inference
(the exact code the API endpoint uses), then runs representative inputs and
prints a JSON report: load time, per-case latency, RSS, classification,
parse validity, and truncation flags. Nothing here is mocked or replayed.
Exit code 0 only if the model loaded and every case produced a response
(a needs_review verdict still counts as a response; a crash does not).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services import cyberllm_rules  # noqa: E402
from app.services.cyberllm_inference import ModelUnavailable, generate  # noqa: E402
from app.services.cyberllm_loader import ensure_loaded, get_status  # noqa: E402
from app.services.cyberllm_schema import parse_model_output  # noqa: E402

CASES = [
    {
        "name": "benign_sudo",
        "kind": "log",
        "text": "Oct 24 07:12:01 web-1 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
        "expect": "likely_benign",
    },
    {
        "name": "single_ssh_failure_review",
        "kind": "log",
        "text": "Oct 24 07:10:22 proxy-9 sshd[310]: Failed password for ruth from 203.0.113.124 port 22 ssh2",
        "expect": "needs_review",
    },
    {
        "name": "web_scan_threat",
        "kind": "log",
        "text": (
            '203.0.113.153 - - [24/Oct/2026:15:00:50 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0"\n'
            '203.0.113.153 - - [24/Oct/2026:15:01:51 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0"\n'
            '203.0.113.153 - - [24/Oct/2026:15:02:51 +0000] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
        ),
        "expect": "likely_threat",
    },
    {
        "name": "ssrf_metadata_miss_case",
        "kind": "http_request",
        "text": "GET /fetch?u=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
        "expect": "likely_threat (model historically said likely_benign; deterministic layer must catch it)",
    },
    {
        "name": "cve_truncation_case",
        "kind": "vulnerability",
        "text": (
            "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; "
            "Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and "
            "Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to "
            "execute arbitrary code via crafted packets, aka Windows SMB Remote Code Execution "
            "Vulnerability. This vulnerability is different from those described in CVE-2017-0143, "
            "CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148."
        ),
        "expect": "valid JSON or safe needs_review degradation (pilot v8 truncated this item at 512 tokens)",
    },
]


def rss_mb() -> float | None:
    try:
        import psutil

        return round(psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024, 1)
    except Exception:
        return None


def main() -> int:
    t0 = time.perf_counter()
    status = ensure_loaded()
    load_ms = int((time.perf_counter() - t0) * 1000)
    report: dict = {
        "checkpoint": {
            "base_model": status.base_model,
            "adapter_dir": status.adapter_dir,
            "adapter_sha256": status.adapter_sha256,
        },
        "loaded": status.ready,
        "load_state": status.state,
        "load_reason": status.reason,
        "load_ms": load_ms,
        "rss_mb_after_load": status.rss_mb,
        "cases": [],
    }
    if not status.ready:
        print(json.dumps(report, indent=2))
        print("MODEL DID NOT LOAD — no inference attempted.", file=sys.stderr)
        return 2
    ok = True
    for case in CASES:
        try:
            gen = generate(case["kind"], case["text"])
            cleaned, parse_ok = parse_model_output(gen["raw"])
            findings = cyberllm_rules.screen(case["text"])
            final = None
            if parse_ok:
                final = cleaned["classification"]
                if any(f["severity"] == "high" for f in findings) and final == "likely_benign":
                    final = "likely_threat (deterministic_override)"
            else:
                final = "needs_review (unparseable_output)"
            report["cases"].append({
                "name": case["name"], "kind": case["kind"],
                "expected": case["expect"], "model_classification": cleaned["classification"] if parse_ok else None,
                "final_classification": final, "confidence": cleaned["confidence"] if parse_ok else "low",
                "parse_ok": parse_ok, "truncated": gen["truncated"],
                "output_tokens": gen["output_tokens"], "latency_ms": gen["latency_ms"],
                "deterministic_findings": [f["rule"] for f in findings],
                "raw_head": gen["raw"][:300],
            })
        except Exception as exc:
            ok = False
            report["cases"].append({"name": case["name"], "error": f"{type(exc).__name__}: {exc}"})
    report["rss_mb_after_cases"] = rss_mb()
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
