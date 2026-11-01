"""Benchmark the Stage 4/5 intelligence layer (reproducible numbers).

Measures, on THIS machine:
  1. rule-engine latency (analyze_text) over a representative corpus,
  2. build_intelligence latency (rules path, no MITRE load),
  3. MITRE cold-load time + cached resolve latency + RSS delta,
  4. worker end-to-end job time with a STUBBED model — i.e. pipeline
     overhead (DB + intelligence + incident + collection) EXCLUDING
     inference. Real inference latency, GPU VRAM, and queue throughput
     under load can only be measured on the Windows PC (GTX 1660
     SUPER) with the real model; this script never claims them.

Usage: python scripts/bench_intelligence.py
"""
from __future__ import annotations

import os
import resource
import statistics
import sys
import tempfile
import time
from pathlib import Path

# Repo root on sys.path (running a file puts scripts/ there, not the root).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Temp DB + test env BEFORE importing the app (engine binds at import).
_TMP = Path(tempfile.mkdtemp(prefix="sentientai-bench-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'bench.db'}"
os.environ["SECRET_KEY"] = "bench-secret-key-not-used-anywhere-else"
os.environ["ENVIRONMENT"] = "test"

CORPUS = [
    "GET /blog/hello-world 200",
    "User john failed to log in",
    "GET /search?q=select+statement",
    "id=1 UNION SELECT password FROM users--",
    "<script>alert(document.cookie)</script>",
    "GET /files/../../etc/passwd",
    "q=test; id",
    "GET /proxy?url=http://169.254.169.254/latest/meta-data/",
    "name={{7*7}}",
    '<?xml <!ENTITY xxe SYSTEM "file:///etc/passwd">',
    "page=php://filter/convert.base64-encode/resource=index",
    "GET /uploads/c99.php?cmd=id",
    "GET /fetch?u=http://metadata.google.internal/",
    "User-Agent: Nmap 7.94",
    "GET /wp-admin",
    "GET /.git/HEAD",
    "GET /api/users/42 200",
    "password reset instructions sent to your email",
    "http.200 | category=web_attack | route=/search | method=GET | id=1 UNION SELECT password FROM users--",
    "http.200 | category=ssrf | route=/fetch | method=GET | GET /fetch?u=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
]


def _percentile(values, pct):
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(len(ordered) * pct / 100)))
    return ordered[idx]


def _summarize(name, samples_ms):
    print(f"{name}: n={len(samples_ms)} mean={statistics.mean(samples_ms):.3f}ms "
          f"p50={_percentile(samples_ms, 50):.3f}ms "
          f"p95={_percentile(samples_ms, 95):.3f}ms "
          f"max={max(samples_ms):.3f}ms "
          f"throughput={1000.0 / statistics.mean(samples_ms):.0f}/s")


def main():
    from app.services.attack_intelligence import build_intelligence
    from app.services.attack_rules import analyze_text

    # 1. Rule-engine latency.
    samples = []
    for _ in range(50):
        for text in CORPUS:
            start = time.perf_counter()
            analyze_text(text)
            samples.append((time.perf_counter() - start) * 1000)
    _summarize("analyze_text", samples)

    # 2. build_intelligence (rules path; MITRE load skipped).
    samples = []
    for _ in range(50):
        for text in CORPUS:
            start = time.perf_counter()
            build_intelligence(text, mitre=False)
            samples.append((time.perf_counter() - start) * 1000)
    _summarize("build_intelligence (rules-only)", samples)

    # 3. MITRE cold load + cached resolves + RSS.
    from app.services.mitre_attack import MitreAttack

    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = time.perf_counter()
    mitre = MitreAttack.load_default()
    load_ms = (time.perf_counter() - start) * 1000
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(f"mitre cold load: {load_ms:.0f}ms, RSS delta: "
          f"{(rss_after - rss_before) / 1024:.0f}MB "
          f"(bundle 55MB on disk; version {mitre.dataset_info()['version']})")
    samples = []
    for _ in range(1000):
        start = time.perf_counter()
        mitre.resolve("T1110.003")
        samples.append((time.perf_counter() - start) * 1_000_000)
    print(f"mitre cached resolve: mean={statistics.mean(samples):.1f}us "
          f"p95={_percentile(samples, 95):.1f}us")

    # 4. Worker end-to-end with a stubbed model (pipeline overhead only).
    from app.database import SessionLocal, init_db
    import app.services.automation as auto
    from app.services.security_events import log_event

    init_db()
    auto.classify_log = lambda *a, **kw: {
        "source": "cyberllm", "status": "ok",
        "classification": "likely_threat", "model_classification": "likely_threat",
        "confidence": "high", "summary": "Stubbed threat.",
        "indicators": [], "reasoning": "Benchmark stub.",
        "limitations": [], "recommended_actions": ["Review."],
        "deterministic_findings": [], "parse_ok": True, "truncated": False,
        "output_tokens": 42, "latency_ms": 0, "raw_output": "{}", "error": None,
    }
    s = SessionLocal()
    samples = []
    for _ in range(10):
        # Fresh batch per round; each process_one call handles one job.
        for text in CORPUS:
            log_event(s, event_type="http.200", category="bench",
                      severity="medium", source="bench", route="/bench",
                      method="GET", http_status=200, evidence=text)
        for _ in CORPUS:
            start = time.perf_counter()
            auto.process_one(s)
            samples.append((time.perf_counter() - start) * 1000)
    _summarize("worker job (stubbed model; pipeline overhead only)", samples)
    print("NOTE: inference latency, GPU VRAM, and loaded-queue throughput "
          "are NOT measured here; they require the Windows PC + real model.")
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
