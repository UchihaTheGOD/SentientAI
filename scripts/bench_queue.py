"""Queue throughput + worker-path intelligence with the REAL model.

Measures what the rules-only benchmark cannot: end-to-end job latency
with genuine inference, jobs/hour (one-at-a-time worker, so throughput
is ~3600 / mean job latency), and the worker-path classification /
MITRE fields on real jobs.

SAFETY — read before running:
- Run ONLY against a disposable validation database (a worktree copy),
  never the main project's production database. This script CREATES
  security events, incidents, and training candidates in the target
  DB (candidates stay unapproved, safe_to_train=False, by design).
- It does NOT enable the background worker, does NOT touch settings,
  does NOT approve anything, does NOT modify model weights or the
  adapter. It calls process_one() directly in this process.
- The model loads lazily on the first job (set CYBERLLM_BASE_DIR /
  CYBERLLM_ADAPTER_DIR before running, or use the project-local
  cyberLLMv1/{base,adapter} layout). If the model is unavailable,
  jobs fail after retries and the script reports that honestly —
  it never fabricates a latency.
- Expect roughly --events x single-inference latency (minutes, not
  seconds, on a GTX 1660 SUPER). Default 5 events.

Usage (from the project root, with the project venv):
  python scripts/bench_queue.py [--events 5] [--db PATH]
  --db defaults to the DATABASE_URL environment value, else ./app.db.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

CORPUS = [
    "GET /blog/hello-world 200",
    "id=1 UNION SELECT password FROM users--",
    "GET /proxy?url=http://169.254.169.254/latest/meta-data/",
    "GET /uploads/c99.php?cmd=id",
    "<script>alert(document.cookie)</script>",
]


def _percentile(values, pct):
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(len(ordered) * pct / 100)))
    return ordered[idx]


def main() -> int:
    import os

    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=5)
    parser.add_argument("--db", default=None)
    args = parser.parse_args()
    if args.db:
        os.environ["DATABASE_URL"] = f"sqlite:///{args.db}"
    elif "DATABASE_URL" not in os.environ:
        os.environ["DATABASE_URL"] = "sqlite:///./app.db"
    os.environ.setdefault("SECRET_KEY", "bench-queue-secret")
    os.environ.setdefault("ENVIRONMENT", "test")

    from app.database import SessionLocal, init_db
    from app.models.automation import AutomationJob
    from app.services.cyberllm_loader import get_status
    from app.services.security_events import log_event
    import app.services.automation as auto

    init_db()
    before = get_status()
    print(f"readiness before: ready={before.ready} state={before.state} "
          f"device={before.device} base={before.base_model} "
          f"adapter_dir={before.adapter_dir}")
    s = SessionLocal()
    event_ids = []
    for i in range(args.events):
        ev = log_event(
            s, event_type="http.200", category="bench", severity="medium",
            source="bench", route="/bench", method="GET", http_status=200,
            evidence=CORPUS[i % len(CORPUS)])
        event_ids.append(ev.id)
    print(f"logged {len(event_ids)} events; processing one at a time...")
    deadline = time.time() + 90 * 60
    while time.time() < deadline:
        done = s.query(AutomationJob).filter(
            AutomationJob.event_id.in_(event_ids),
            AutomationJob.status.in_(("completed", "failed"))).count()
        if done >= len(event_ids):
            break
        job = auto.process_one(s)
        if job is None:
            break
    jobs = s.query(AutomationJob).filter(
        AutomationJob.event_id.in_(event_ids)).all()
    rows = []
    for job in jobs:
        rows.append({
            "event_id": job.event_id, "status": job.status,
            "verdict": job.verdict, "attack_type": job.attack_type,
            "mitre_technique": job.mitre_technique,
            "incident_id": job.incident_id,
            "training_example_id": job.training_example_id,
            "latency_ms": job.latency_ms,
            "error": (job.error_message or "")[:200],
        })
    completed = [r for r in rows if r["status"] == "completed"]
    latencies = [r["latency_ms"] for r in completed if r["latency_ms"] is not None]
    after = get_status()
    print(f"readiness after: ready={after.ready} state={after.state} "
          f"device={after.device} load_ms={after.load_ms} rss_mb={after.rss_mb}")
    print(json.dumps({"jobs": rows}, indent=2, ensure_ascii=False))
    if latencies:
        mean_s = statistics.mean(latencies) / 1000
        print(f"completed={len(completed)} failed={len(rows) - len(completed)} "
              f"mean_latency={mean_s:.1f}s p95={_percentile(latencies, 95) / 1000:.1f}s "
              f"max={max(latencies) / 1000:.1f}s "
              f"throughput_jobs_per_hour={3600 / mean_s:.1f}")
    else:
        print(f"completed=0 failed={len(rows)} — no latency measured; "
              f"the model path did not complete (see job errors above).")
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
