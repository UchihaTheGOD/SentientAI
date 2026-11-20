# Migration report — obsolete Sentinel models removed, CyberLLMv1 integrated

Branch: `feature/cyberllmv1-portable-runtime`
Parent commit: `58b10b7ec52e6e0e0d9857d8eade88b084d1ac4f` (previous audit, which
concluded Sentinel was live — **superseded by the user's 2026-10-27 master
task, which states explicitly that the old models are obsolete and must be
removed, while the SentientAI project itself is kept**).
Base: `c542cc79a29f3846bbd880dee01ac0f4c7fc6277`
Checkpoint before this migration (outside the repo):
`~/workspace/sentientai-checkpoint-migration-20261027.patch`
(SHA-256 `2747561184cc3fbfeecccb8876a56a6050333ce304b6b2d08720e1b81f167211`)
Removed files are also copied to `~/workspace/sentientai-removed-legacy-20261027/`
for recovery. Nothing was pushed or merged; remote `main` is untouched.

## What was wrong

SentientAI's security workflows were wired to two checkpoints of a small
custom transformer (Model A / Model B) that the repo's own diagnostics
showed to be ineffective (0% structured-valid output on a 26-case probe),
yet every workflow — analyze, bridge, demo, lab, moderation — went
through dual-model inference, a Sentinel tokenizer, a prompt file, and
a model-agreement calculation. Six tests failed in this VM solely
because those checkpoints were absent, and the application could not
start a security analysis without pretending the models were there.
CyberLLMv1, the intended replacement, existed only as a separate
endpoint (`/api/cyberllm/analyze`) and was never used by any workflow.

## What changed (summary)

1. **New classification adapter** `app/services/classifier.py`:
   `classify_log()` wraps CyberLLMv1 generation + JSON schema + the same
   evidence checks the CyberLLM endpoint uses, and `fuse_classification()`
   fuses rules (50%) with a confident model verdict (50%). Unavailable,
   unparseable, truncated, evidence-mismatched, or unjustified
   high-confidence-threat outputs all degrade to `needs_review` with the
   model's original verdict preserved in `model_classification`. A
   high-severity deterministic finding (SSRF/metadata) still overrides a
   benign model verdict. One confident model cannot alone flip a benign
   log to `likely_threat` (rules 0 + model 85 = 42 = `needs_review`) —
   that is a deliberate safety property, tested explicitly.
2. **Deterministic rules preserved verbatim** in `app/services/security_rules.py`
   (moved from `sentinel_fusion.py`: same thresholds, scores, verdicts).
3. **Workflows migrated, not deleted**: `POST /api/sentinel/analyze`,
   the bridge (`submit_security_event_for_analysis`,
   `submit_attact_finding_for_analysis`), demo runs, and security-lab
   analyze all now call `classify_log` + `fuse_classification` and
   create incidents through the same `incident_service` (now taking a
   `classification` dict). Incidents, blocks, review queue, training
   candidates, and security events are unchanged in behaviour.
4. **Moderation is human-only**: the Sentinel moderation model is gone,
   and CyberLLMv1 is a security-log classifier, not a content-moderation
   classifier, so it is not forced into that role. Candidates are born
   from a moderator's decision (as before) and are never auto-approved;
   the stored status is `model_removed_human_review_only`.
5. **Startup**: no model loads at startup any more. CyberLLMv1 loads
   lazily on explicit load/analyze; a missing model returns 503
   `model_unavailable` (CyberLLM endpoint) or rules-only fusion
   (Sentinel-style workflows), never a fabricated verdict.
6. **Breaking API changes (documented, intentional)**:
   - `POST /api/sentinel/analyze` no longer returns `model_a`,
     `model_b`, `agreement`, `agreement_detail`, or `prompt_chars`,
     and no longer accepts `extra_prompt` (that was Sentinel prompt
     input). It returns `classification` (full adapter result),
     `rules`, `fusion`, `risk_score`, `verdict`, `incident_id`,
     `evidence`, `latency_ms`.
   - `GET /api/sentinel/readiness` no longer returns `a`/`b`/
     `missing_files`/`vocab_size`; it returns `classifier:
     "cyberllm"`, `base_model`, `model_root`, `device`, `reason`,
     `rules_available: true`, `legacy_models: "removed"`.
   - `GET /api/sentinel/prompt/status` and
     `POST /api/sentinel/prompt/reload` are gone (404).
   - Lab analyze no longer returns `model_a`/`model_b`/`agreement`/
     `prompt_path`/`prompt_chars`/`prompt_truncated`; it returns
     `classification` + `fusion`.
   - Demo runs return `classification` instead of `inference`
     (dual-model dict).
   - The Sentinel page no longer shows Model A/B panels or a prompt
     preview; it shows the CyberLLMv1 classification.
7. **Docs updated**: `README.md` (§2, §3, §4, §11, §12, §14, §15, §17,
   §18, tree), `CYBERLLM_PORTABLE_SETUP.md` (§4), `WINDOWS_TEST_CHECKLIST.md`
   (stale 651/644/6/1 expectation removed). Historical reports
   (`CYBERLLM_INTEGRATION_REPORT.md`, `Documentation/*`, the previous
   architecture audit) were left untouched as history, not rewritten.

## Files removed (git rm)

- `app/services/sentinel_loader.py` (checkpoint discovery, tokenizer
  loading, `ensure_loaded`, `get_status`, background load)
- `app/services/sentinel_inference.py` (dual inference, agreement)
- `app/services/sentinel_moderation.py` (model moderation)
- `app/services/sentinel_schema.py` (Sentinel structured validation,
  `fuse_structured`)
- `app/services/sentinel_fusion.py` (rules moved to `security_rules.py`;
  dual-model fusion deleted)
- `app/services/prompt_service.py` (Sentinel prompt file, tag template;
  `validate_log_text`/`MAX_LOG_CHARS` moved verbatim to
  `app/services/log_validation.py`)
- `sentinel_model.py`, `config.py` (root Sentinel model + config)
- `prompts/prompt.txt` (Sentinel prompt template; `prompts/` dir removed)
- Tests exclusively for the old models: `test_prompt_and_readiness.py`,
  `test_prompt_path_resolution.py`, `test_prompt_propagation_a.py`,
  `test_prompt_propagation_b.py`, `test_prompt_propagation_c.py`,
  `test_sentinel_phase1.py`, `test_sentinel_architecture_audit.py`
  (the previous audit's tests, superseded by this migration).

No obsolete checkpoint was downloaded. No checkpoint file was present
in the repo to delete (they were gitignored runtime artifacts).

## Files added / changed

- Added: `app/services/classifier.py`, `app/services/security_rules.py`,
  `app/services/log_validation.py`, `tests/test_classifier.py` (9 tests,
  mocked generation — unit level only, not real inference),
  `tests/test_log_validation.py` (4 tests), this report.
- Changed: `app/api/sentinel.py`, `app/api/security.py` (demo),
  `app/api/security_lab_api.py`, `app/api/cyberllm.py` (import only),
  `app/main.py` (lifespan), `app/services/incident_service.py`,
  `app/services/sentinel_bridge.py`, `app/services/collection.py`,
  `app/templates/sentinel.html`, `app/static/js/sentinel_form.js`,
  `evaluation_matrix.py`, `evaluation_moderation.py`,
  `README.md`, `CYBERLLM_PORTABLE_SETUP.md`,
  `WINDOWS_TEST_CHECKLIST.md`, and the test files listed in §Test results.
- Unchanged (kept): `app/services/training_pipeline.py` (reviewed-incident
  dataset builder, no model training — its `local_models/sentinel/candidates`
  path is dataset JSON storage, not checkpoints), `app/models/sentinel_incident.py`,
  `app/models/security_lab.py`, `app/models/training_example.py` (see §Remaining references).

## Test results

Baseline (previous commit `58b10b7`): 657 tests, 650 passed, 6 failed
(Sentinel artifact tests), 1 skipped.
Final full suite (JUnit, Linux VM, re-run after all fixes):
**617 tests, 616 passed, 0 failed, 1 skipped, 0 errors.**
The count drop (−40 vs the previous 657) is the deleted old-model
tests minus the new classifier/validation tests, not lost coverage
of preserved behaviour: every preserved workflow (rules, fusion,
analyze auth, incidents, review, blocks, demo, lab, bridge,
moderation candidates) is covered by migrated tests.

The first full run showed 2 tests still asserting old response fields
(`test_evaluation_matrix::test_metrics_separate_rules_and_models`,
`test_security_lab_phase::test_lab_analyze_creates_incident_and_candidate`).
Both were migrated to assert `classification` and the absence of
`model_a`/`model_b`, then re-run (15/15 in that subset) and confirmed
by the final full run above.

Skipped: `test_templates::test_navigation_links_point_at_real_routes[partials/nav.html]`
(pre-existing, unrelated).

Real inference levels: (1) unit tests with mocks — done; (2) integration
tests with a mocked classifier — done (bridge, lab, reports); (3) actual
model loading — NOT done in this VM (no 1.7B weights, adapter dir empty
here); (4) actual inference with intended base+adapter — NOT done here;
(5) GPU inference on the target Windows machine — NOT tested. None is
claimed as passed.

## Remaining legacy references (justified)

- Route paths `/api/sentinel/*`, `/sentinel`, `/admin/sentinel/incidents`
  — kept for API compatibility; they are now powered by CyberLLMv1 +
  rules, not by Sentinel models.
- `SentinelIncident` / `TempBlock` model names and `sentinel_*` columns
  in `TrainingExample` / `SecurityLabRun` — existing database schema.
  Renaming them would require a destructive migration; instead,
  `incident_service` documents that the classifier slot (`model_a_*`)
  holds the single CyberLLMv1 summary/status, `model_b_*` is always
  `None`, and `agreement` is always `None`. New rows never fabricate
  a second model.
- `training_pipeline.py` candidate directory
  `local_models/sentinel/candidates/` — dataset JSON storage, not
  checkpoints; no model is loaded from it.
- `Documentation/*`, `CYBERLLM_INTEGRATION_REPORT.md`, and the previous
  architecture audit — historical records of a retired architecture,
  deliberately not rewritten.
- `app/models/attact_assessment.py` comment mentioning `model_a /
  model_b` as a source enum value — a historical source label in a
  comment, not code; new events use `cyberllm` / `rules` sources.
- Admin report templates show stored `model_a_status` /
  `model_b_status` for historical lab runs; new runs store the
  CyberLLMv1 status in the classifier slot and `None` for the second
  slot, and the templates render `None` as "Not run".

## Deployment (Windows, PowerShell)

```powershell
cd D:\path\to\SentientAI
git branch --show-current   # feature/cyberllmv1-portable-runtime
git rev-parse HEAD
# CyberLLMv1 (required, primary) — do NOT download any Sentinel checkpoint
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --check
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-base
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-adapter
(Get-FileHash cyberLLMv1\adapter\adapter_model.safetensors -Algorithm SHA256).Hash
# Expected: d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1
Copy-Item .env.example .env
run.bat start
Invoke-RestMethod http://127.0.0.1:8000/api/sentinel/readiness | ConvertTo-Json -Depth 5
Invoke-RestMethod http://127.0.0.1:8000/api/cyberllm/readiness | ConvertTo-Json -Depth 5
run.bat test
```

Report back: adapter SHA match, `cuda_available`, both readiness JSONs,
one real CyberLLM analyze response, and exact test counts. Do not
label Windows inference as passed until you have run it.
