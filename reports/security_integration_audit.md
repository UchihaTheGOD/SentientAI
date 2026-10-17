# Security Integration Audit — SentientAI (2026-10-17)

## 1) App structure
- FastAPI `create_app()` in `app/main.py`: middleware outer->inner = `SecurityEventsMiddleware` -> `SecurityHeadersMiddleware` -> `CSRFMiddleware` -> routes. Lifespan `init_db()` + `init_sentinel(background=True)` fail-open.
- Routes: `admin.py`, `auth.py` (/login ratelimited), `blog.py` (/search), `sentinel.py` (/api/sentinel/analyze), `security_a.py` + `security_b.py` (ATTACT/triage/demo), `admin_security.py` (Security Center page). Templates `base_public.html`, `admin*.html`, `partials/admin_nav.html`; footer already updated to requested text.
- DB `app/database.py` SQLite model-driven `_add_missing_columns`. Models: `User`, `SecurityEvent/AttactAssessment/AttactFinding`, `SentinelIncident/TempBlock`, `TrainingExample` + `learning.py` lifecycle.
- Tests: `tests/conftest.py` throwaway SQLite + CSRF-aware Client wrapper; 33 modules 480+ cases.

## 2) Paths traced

### Website -> SecurityEventsMiddleware -> SecurityEvent
Middleware assigns correlation_id (16-hex), trusted_client_ip (TRUSTED_PROXY_*), checks `is_blocked` pre-dispatch, logs `http.{401,403,429}` (skip /static unless traversal) and `suspicious_input.{xss,sqli,traversal}` from query+path+q even on 200; dedups per correlation_id. `security_events.log_event` redacts secrets, caps evidence 4000/meta 8000, hashes IP, stores session_digest, correlation/duration. Login failures also logged as `auth.login_failed` in `api/auth.py` (middleware skips /login for suspicious_input).

### ATTACT
`POST /api/security/attact/run` (admin) -> `services/attact_runner.run_and_persist` -> `ATTACT/runner._run` (BoundedClient 6s/120 req, `scope.validate_url` loopback-or-allowlist). Persists `AttactAssessment` + per-finding `AttactFinding`; for confirmed/potential creates `SecurityEvent` attact.finding. Triage via `POST /api/security/findings/{id}/triage`.

### Sentinel -> Fusion -> Incident -> TrainingExample -> AI review
`POST /api/sentinel/analyze` (auth) validates log_text 1..8000, builds prompt via `prompt_service.build_analysis_prompt` (BASE_DIR/prompts/prompt.txt locked, control-token sanitized, template `<instruction>{base}</instruction><input>{log}</input><output>`). Inference `sentinel_inference.run_dual_inference` (real checkpoints `local_models/sentinel/sentinel_best_model.pt` + `best_autolab_checkpoint.pt`, loader lazy, semaphore 2, budget max_pos 768-max_new-4=508 middle-drop preserving <output>=8, timeout 12s). Validation `sentinel_schema.validate_sentinel_output` requires Summary/Indicators/Reasoning/Provisional/Input status; fusion `sentinel_fusion.fuse` rules 0.5 + model 0.25 (0.12 degraded), invalid outputs `structured_valid=False` never weighted; incident `incident_service.create_incident` + `SecurityEvent` sentinel.analysis. Collector `collection.collect_from_incident` (needs_review/likely_threat or score>=threshold) creates TrainingExample CANDIDATE safe_to_train=False deduped by dedup_hash; appears in `Admin->AI review` ordered by quality_score, review apply_review gates safe_to_train.

### Bridge (explicit integration)
`services/sentinel_bridge.submit_security_event_for_analysis` + `submit_attact_finding_for_analysis` (used by `admin_security /analyze/event|finding` with ?sync=1, 10-min dedup via containment_meta key, benign threshold 35). Prevents duplicates linking event/finding.incident_id.

### AI review workflow
`admin.py` pending queue + rejected, approve/reject/needs_edit (admin), export JSONL only is_trainable=train.

## 3) Works / Partial / Disconnected
- Works: middleware events, ATTACT persist/export/redaction, Sentinel loader/inference/fusion/schema (real ckpts load but produce garbled structured output; fallback to rules correctly flagged), incident dedup, training candidate review.
- Partial: SecurityEvent <-> SentinelIncident automatic only for direct analyze; ATTACT/middleware events stayed disconnected until explicit bridge (now wired); demo harness works but evidence minimal; truncation only logged.
- Disconnected: No admin GUI to launch controlled tests end-to-end request->event->model->incident->candidate (gap to close with Lab + Log Analyzer). Security Center had 5 stacked cards but no lab; no duplicate includes, long evidence needs wrapping/expandable.

## 4) Duplicate GUI
Single Security Center `admin_security.html` including `admin_nav` only; no duplicate full-page panels. Nav consistent. Lab/Analyzer will be in same template.

## 5) Tests baseline
`pytest --co -q` 480+ tests; targeted propagation 23 PASS (14 propagation + 9 path). Full `tests -q` heavy due to model load (250s timeout), but short runs PASS; no regressions expected for non-model tests.

## 6) Risks to address in impl
Checkpoints structured_valid often False -> must label rule-based/degraded not success; token truncation surfaced; missing/empty prompt -> 500; target safety loopback/allowlist only, bounded timeouts/counts; idempotent candidates (dedup_hash/incident dedup_key); admin guard all new routes.
