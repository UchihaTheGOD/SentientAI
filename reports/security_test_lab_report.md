# Security Test Lab Report — SentientAI (2026-10-17)

## Summary
Implemented Security Test Lab + Log Analyzer inside existing Admin Security Center, real-model Sentinel analysis, and end-to-end evidence flow without mocks.

## Problems discovered
- SecurityEvent<->Incident was automatic only for direct analyze; middleware/ATTACT had no explicit bridge (now `sentinel_bridge` + `/admin/security/analyze/*`).
- Inner TestClient vs outer Session stale reads → events_window 0 until fresh SessionLocal.
- Naive created_at vs utc offset hid events; fixed with 900s window + tz-aware.

## Files modified
- Added `app/models/security_lab.py`, `app/services/security_lab.py`+`security_lab_runner.py`, `app/api/security_lab_api_a.py`+`b.py`, `app/templates/admin_security.html` (Lab+Log Analyzer), `app/static/js/security_lab_*.js` (3 parts), `app/database` import, `app/main` routers, `prompts/prompt.txt` (reordered), `app/static/css/public.css`, `tests/test_security_lab_phase.py`.

## Routes
- POST/GET /api/security/lab/run|runs|runs/{id}|analyze|log-analyze (admin), GET /admin/security (renders Lab+Analyzer), footer already updated.

## DB
- New table `security_lab_runs` via create_all + _add_missing_columns; no destructive migration.

## Prompt
- Locked BASE_DIR/prompts/prompt.txt, mtime cache, explicit errors, 6 sections (Summary/Input status/Indicators/Reasoning/Provisional/Recommendation), survives validate_sentinel_output, both models receive same build_analysis_prompt with budget 508 middle-drop.

## Model A/B results (real checkpoints)
- Typical: A `Ġconfidence .` (ok, 2 tokens, ~900ms) B empty/repetition (~1700ms), structured_valid False, fusion rule-based, latencies recorded, truncation middle-drop when >508 ids. Honest degraded reporting; retrain needed for quality.

## Fusion
- Rules 0.5 + model 0.25 (0.12 degraded), invalid never weighted, limitations listed, components surfaced.

## Event->Incident->AI review
- Lab synthetic `lab.synthetic.*` with synthetic True; real probes `suspicious_input.*`/`auth.login_failed`. analyze builds log_text, runs inference, creates SentinelIncident + CANDIDATE safe_to_train=False deduped (0 extra on repeat), appears in /admin/training.

## Tests
- 7 new lab tests PASS + 26 targeted combined PASS; manual lab: xss detected, login 3x401 detected, port_scan synthetic, bad target 400, dedup 0 extra.

## Full suite
- --co 480+ tests; sampled subsets PASS; no regressions in non-model subsets.

## Limitations / next
- Checkpoints garbled → rule-based most of time; prompt truncation unavoidable (530>508); single-process lock prevents concurrent lab; retrain for structured quality.

