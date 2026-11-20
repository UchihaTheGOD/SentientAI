# SentientAI Repository Architecture Audit

Branch: `feature/cyberllm-desktop-portable` (code commit `8a5aee9`, on top of
`dcf7c2b` → `27691dd` → `58b10b7` → `77f1118` → user-pushed `main` commit
`c542cc7`, "Integrate CyberLLM security analysis", 2026-10-27).
Audit date: 2026-10-28. This report describes the repository as it stands on
this branch. Nothing in it is a plan: every claim below was read from the
code or measured by a run recorded in `reports/TEST_RESULTS.md`.

## 1. What SentientAI is

A FastAPI + Jinja2 + SQLAlchemy community/security platform with an
integrated cybersecurity assistant, **CyberLLMv1**, and a deterministic
rules layer. The website, its security features, authentication, database,
incident workflows, and deterministic detection rules are the product. The
AI model is one replaceable inference service inside it, not the product.

- Entry: `run.py` → uvicorn `app.main:app` on `127.0.0.1:8000`
  (`run.py` enables reload; the desktop GUI starts uvicorn directly,
  without reload).
- Stack: FastAPI 0.115.6, Jinja2 templates, SQLAlchemy 2.0, SQLite file
  database, pytest (`pytest.ini`: `testpaths = tests`, `addopts = -q`).
- Auth: JWT sessions (python-jose HS256), Argon2id password hashes,
  CSRF double-submit middleware, sliding-window rate limiting, audit log.
  Registration is a form POST that redirects to login; **every new
  registration is role `user`** — promotion is a CLI action (`manage.py`)
  or an admin-only API call, never something a request can grant itself.
  Login failures return one identical message for unknown user and wrong
  password. Register/login are rate-limited.
- Model identity: CyberLLMv1 = Qwen/Qwen3-1.7B base
  (`70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`, Apache-2.0) + pilot v8 LoRA
  adapter, expected SHA-256
  `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`.
  CyberLLMv1 is the name of the fine-tuned system, not a claim that the
  foundation model was trained from scratch. Attribution and the base
  licence are preserved in the setup docs.

## 2. Request flows (the whole system in five paths)

### 2.1 Log analysis (the Log Analyzer page, `/sentinel`)

`POST /api/sentinel/analyze` (authenticated, CSRF, rate-limited)
→ `validate_log_text` (max 8000 chars; log text is untrusted data and is
never executed)
→ `classify_log(log_text, kind="log")` (single shared classifier)
→ `fuse_classification` (rules 50% + confident model 50%; high-severity
deterministic finding escalates to `likely_threat` transparently; SSRF
override preserved; unavailable / unparseable / truncated / mismatch /
unjustified-threat results fall back to `needs_review`)
→ optional `incident_service.create_incident` (only when requested)
→ JSON: `classification`, `rules`, `fusion` (score/verdict/components/
note), `risk_score`, `verdict`, `incident_id`, `evidence`, `latency_ms`,
`inference_latency_ms`.

The page (`sentinel.html` + `sentinel_form.js`) displays the fusion
verdict, the CyberLLMv1 classification with its `source` and `status`,
the fusion note, evidence, and latency — so the user can see whether a
result came from the model, the rules, both, or neither.

### 2.2 CyberLLM API (`/api/cyberllm/*`)

- `GET /api/cyberllm/readiness` (unauthenticated): model identity, ready
  flag, state, reason, device, adapter SHA.
- `POST /api/cyberllm/readiness/load` (admin-only): trigger a load.
- `POST /api/cyberllm/screen`: rules-only screening, no model needed.
- `POST /api/cyberllm/analyze` (authenticated, CSRF, rate-limited):
  kinds `log`, `http_request`, `url`, `vulnerability`; returns
  `classification`, `model_classification`, `confidence`,
  `decision_source` (`model` / `deterministic_override` /
  `unparseable_output` / `evidence_mismatch` / `truncated_output`),
  `deterministic_findings`, `parse_ok`, `truncated`, `output_tokens`,
  `latency_ms`, and `raw_output` only when unparseable.
- There is deliberately **no MITRE field** in any response: the model has
  never demonstrated reliable exact technique-ID prediction, and
  presenting an ID would fabricate a finding.

### 2.3 Security events and ATT&CK findings → incidents → training

`app/api/admin_security.py` → `sentinel_bridge.submit_security_event_for_analysis`
/ `submit_attact_finding_for_analysis`
→ CyberLLMv1 classification + rules → `SentinelIncident` (dedup by
`hash(ip + log_head)` in a 10-minute window; idempotent on existing
`incident_id`)
→ `collection.collect_from_incident` (redacts, truncates, dedups, scores
advisory-only, writes a CANDIDATE with `safe_to_train=False`)
→ human review → approve/reject → dataset preparation with leakage
detection → `scripts/promote_cyberllm_candidate.py` (approval-gated,
backup + byte-for-byte rollback). Moderation is **human-only**: the
contract test asserts the collection code records
`model_removed_human_review_only` and never a fabricated model verdict.

### 2.4 Website security lab runs (not the desktop GUI)

`app/api/security_lab_api.py` → `security_lab_runner.run_lab_test` and
`attact_runner.run_and_persist` (both live; the dead duplicates
`security_lab_run2.py` and `security_lab_runner_a.py` were removed) →
`LabRun` rows → reports list/detail pages. The runs API mirrors the
incident storage columns, including the legacy-named `model_a_*` fields
(see §4); new rows always set `model_b_* = None`.

### 2.5 Admin user management (three surfaces, one backend)

- Website HTML admin panel (list/detail/delete; non-admin only,
  self-delete refused, username confirmation).
- JSON API `app/api/admin_users.py` (list/detail/role/active/suspend/
  create/password-reset/audit-events), registered in `app/main.py`.
  Every mutation is backend-enforced: `require_admin`, no self
  role-change/deactivation/suspension, last-admin guard, `token_version`
  bump (session invalidation), audit record. There is deliberately **no
  delete endpoint** — deactivation is the reversible control.
- CLI `manage.py` (create-admin/set-role/list-users/seed-admin).
- The desktop GUI talks to the JSON API only; it never touches the
  database directly.

### 2.6 Desktop GUI (`security_lab/`, PySide6)

Nine pages: Control Center, Authorized Scanner, Model Testing &
Evaluation, User Management, Reports & History, Case Management,
Classroom Demo, Diagnostics, Settings. `BackendManager` starts the
*existing* backend (`python -m uvicorn app.main:app`) and polls its
readiness; there is no second model loader. The scanner is detection-only
(GET-only, authorization + allowlist gates, private/loopback/link-local/
metadata blocking, manual redirect containment, rate limit, request cap,
deadline, stop event, evidence redaction). The demo/simulator pages are
labelled SIMULATED and never present simulated output as a model
prediction. Packaging: PyInstaller spec bundles the GUI only — never the
backend dependencies or the model weights.

## 3. Component inventory

| Area | Key modules | Status |
|---|---|---|
| Loader / inference | `app/services/cyberllm_loader.py`, `cyberllm_inference.py`, `cyberllm_schema.py` | Kept, single shared service |
| Classifier / fusion | `app/services/classifier.py`, `security_rules.py`, `log_validation.py`, `cyberllm_rules.py`, `cyberllm_evidence.py` | Kept, migrated to CyberLLMv1 |
| Event bridge | `app/services/sentinel_bridge.py` | Kept, migrated (despite the name, it is the live event→incident path, not old-model code) |
| Feedback / dataset | `app/services/cyberllm_feedback.py`, `cyberllm_dataset.py`, `training.py`, `collection.py` | Kept |
| Website lab | `app/services/security_lab.py`, `security_lab_runner.py`, `attact_runner.py`, `demo_cases.py` | Kept |
| Old Sentinel models | `sentinel_loader.py`, `sentinel_inference.py`, `sentinel_moderation.py`, `sentinel_schema.py`, `sentinel_model.py`, `prompt_service.py`, root `config.py`, `prompts/prompt.txt` | Removed (see CLEANUP_REPORT) |
| Old-model tests | prompt/readiness/propagation/phase1 tests | Removed; replaced by classifier, log-validation, and contract tests |
| Admin users API | `app/api/admin_users.py`, `app/models/audit.py` (7 new event types) | Added on the Security Lab branch |
| Desktop GUI | `security_lab/` (backend, client, scanner, gui, packaging) | Added on the Security Lab branch |
| Startup | `run.bat` (.venv first, then venv), `run.sh` (Linux/macOS counterpart), `run.py` | Fixed/added on this branch |

## 4. Deliberately retained legacy names (not obsolete code)

- `SentinelIncident.model_a_text / model_a_status` are storage columns.
  The classifier slot (`model_a_*`) now holds the single CyberLLMv1
  classification; `model_b_*` is always `None` for new rows. Renaming the
  columns would require a database migration for zero user benefit and
  would break historical records, so the columns stay and the
  presentation layer was migrated instead (see CLEANUP_REPORT).
- `app/api/security_lab_api.py` still emits the `model_a_*` /
  `model_b_*` storage-mirror fields for backward compatibility; no
  supported consumer displays them as two models any more.
- The feature name "Sentinel" survives in page titles and the incident
  workflow (the website's security-lab feature), which is distinct from
  the removed Sentinel AI models.

## 5. What was broken, and what fixed it

| Broken / risky | Fix (branch) |
|---|---|
| Log Analyzer returned `model_a` / `model_b` / `agreement` / `prompt` with `model_status: unavailable` and no CyberLLMv1 contribution | Migration `27691dd`: single classifier + fusion; obsolete fields removed from `/api/sentinel/analyze`; see CYBERLLM_INTEGRATION_REPORT for the loader-unavailability diagnosis |
| `run.bat` only accepted `venv`, while the dev environment is `.venv` | `run.bat` now tries `.venv` then `venv`; `run.sh` added for Linux/macOS |
| Portability test rejected any project path containing `D:` | Assertion replaced with a project-tree membership check; the project-local equality assertion is the real guarantee |
| Promotion/rollback subprocess tests passed a stripped Linux-only env (`PATH=/usr/bin:/bin`, no SystemRoot) | Tests inherit the parent env and override only `CYBERLLM_MODEL_ROOT` |
| Moderation-contract (and two other) tests read UTF-8 sources with the locale codec (CP1252 on Windows) | `read_text(encoding="utf-8")`; the moderation test also uses a repo-root-relative path instead of a CWD-relative one |
| Incomplete model directory was masked by the missing-torch error in torch-less venvs | Loader now validates artifacts before checking torch, so the actionable file error is reported first |
| Reports list/detail still displayed "Model A" / "Model B" | Single CyberLLMv1 badge in the list; detail page labels the live slot CyberLLMv1 and shows a Model B block only for historical rows |

## 6. Honesty contracts (non-negotiable, enforced by code and tests)

- No fabricated AI predictions, confidence values, MITRE mappings, or
  evidence. Statuses are `ok`, `unavailable`, `error`, `unparseable`,
  or `truncated` where applicable.
- Rules-only results are never labelled as AI verdicts
  (`decision_source` / `source` fields distinguish model, rules,
  deterministic override, and unavailable).
- Missing model files, SHA mismatch, and missing torch are reported as
  readiness reasons, never silently replaced by a download (an explicit
  `CYBERLLM_MODEL_ROOT` is a promise, not a hint).
- Simulations are labelled SIMULATED; the demo never presents simulated
  output as a real model prediction.
- Commands inside submitted security logs are data to analyze, never
  instructions to run.
