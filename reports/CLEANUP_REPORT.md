# SentientAI Cleanup Report

Branch: `feature/cyberllm-desktop-portable` (code commit `8a5aee9`).
Scope: everything removed between the user's pushed `main` commit
`c542cc7` and this branch's HEAD, plus the changes made on this branch.
Deletion lists below were produced from `git diff --name-status
c542cc7..dcf7c2b` and `git show --name-status 27691dd`, and the
"references checked" column was verified by grep over the current tree
(no live code imports any deleted module).

## 1. Deletion manifest

### 1.1 Old Sentinel AI model code (migration `27691dd`)

| File | Why it is safe to remove |
|---|---|
| `app/services/sentinel_loader.py` | Loader for the old custom-Transformer checkpoint (`sentinel_best_model.pt`). Nothing loads that checkpoint any more; the only loader is `cyberllm_loader.py`. |
| `app/services/sentinel_inference.py` | Model A / model B inference (`run_dual_inference`). Replaced by `classifier.py` + `cyberllm_inference.py`. |
| `app/services/sentinel_moderation.py` | Moderation through the old models. Moderation is now human-only by contract (`test_sentinel_moderation_contract.py` asserts the old name appears nowhere in `collection.py` except as a guard). |
| `app/services/sentinel_schema.py` | Output schemas for the old models. Superseded by `cyberllm_schema.py` and the classifier contract. |
| `app/services/prompt_service.py` | Prompt status/reload service for the old models. Its routes were removed (they now 404); no template or API consumer references it. |
| `sentinel_model.py` (repo root) | Old model definition wrapper. No importer remains. |
| `config.py` (repo root) | Obsolete root configuration for the old-model setup. Configuration is now environment-based (see PORTABILITY_REPORT). |
| `prompts/prompt.txt` | Prompt text for the old models. The CyberLLMv1 prompts are the frozen trained templates used verbatim by the inference service. |

### 1.2 Dead duplicate runners (earlier branch commits)

| File | Why it is safe to remove |
|---|---|
| `app/services/security_lab_run2.py` | Unreferenced duplicate of the lab runner. The live runner is `security_lab_runner.py`, imported by `app/api/security_lab_api.py`. |
| `app/services/security_lab_runner_a.py` | Unreferenced variant of the same runner. Same live import as above. |

### 1.3 Temporary diagnostic scripts (earlier branch commits)

`_diag_tmp.py`, `_diag_db.py`, `_diag2_tmp.py`, `_diag3_tmp.py`,
`_phase2_quick.py`, `_quick_logits.py`, `_quick_logits2.py`,
`_sentinel_diag2.py`, `_sentinel_diag_phase2.py` — scratch diagnostics
from the audit phase, never imported by the application or the test
suite, removed so the repo root is not mistaken for product code.

### 1.4 Old-model tests (migration `27691dd`)

`tests/test_prompt_and_readiness.py`,
`tests/test_prompt_path_resolution.py`,
`tests/test_prompt_propagation_a.py`,
`tests/test_prompt_propagation_b.py`,
`tests/test_prompt_propagation_c.py`,
`tests/test_sentinel_phase1.py` — these tested the deleted modules and
prompt plumbing. They were replaced, not dropped silently: new coverage
is `tests/test_classifier.py`, `tests/test_log_validation.py`, and the
updated moderation/contract tests. (`tests/test_sentinel_architecture_audit.py`
was added by an earlier branch commit and removed again by the migration;
its net effect on the branch is zero.)

### 1.5 References checked for every deletion

- `grep -rn "sentinel_loader|sentinel_inference|sentinel_moderation|sentinel_schema|prompt_service|sentinel_model" app/ tests/ security_lab/`
  returns only the moderation-contract guard assertion. No live importer
  of any deleted module remains.
- `grep -rn "security_lab_run2|security_lab_runner_a" app/` returns
  nothing; the live imports are `security_lab_runner.run_lab_test` and
  `attact_runner.run_and_persist`.
- The full suite was run after the migration and again on this branch
  (see TEST_RESULTS.md): the only failures ever observed were the
  environment issues fixed on this branch, not missing-module errors.

## 2. What was NOT deleted, and why

- **Useful deterministic rules** (`security_rules.py`, `cyberllm_rules.py`):
  they are a separate detection layer, not a second model, and the rules
  engine is the supported fallback when inference is unavailable.
- **The website, auth, database, incident workflows, security reports,
  and training/feedback pipeline**: explicitly out of scope for removal;
  they are the product the model serves.
- **Database migrations and historical records**: legacy-named columns
  (`model_a_*` / `model_b_*`) are retained as storage (see
  ARCHITECTURE_AUDIT §4). Historical rows keep their values; new rows
  set `model_b_* = None`.
- **Evaluation records** (`evaluation/latest.json`,
  `evaluation/moderation_latest.json`): left modified-but-unstaged in the
  working tree and excluded from every commit and patch on this branch.
  They are working-tree churn, not a change to ship.
- **Model weights, datasets, credentials, user uploads, database files**:
  never committed, never deleted. Weights are gitignored and live in
  `cyberLLMv1/` (project-local) or a user-configured directory.
- **Research reports** (`reports/migration_obsolete_models_removed.md`
  and the other pre-existing reports): retained; this report supplements
  them, it does not replace the migration record.
- **Removed files backup**: the deleted legacy files were copied to
  `~/workspace/sentientai-removed-legacy-20261027/` (outside the repo)
  at migration time, and every removal is reversible through Git history
  (`git show 27691dd^:<path>`).

## 3. Changes on this branch (no deletions)

- Modified (commit `8a5aee9`, 12 files): `run.bat`, `run.sh` (new),
  `app/services/cyberllm_loader.py`, `app/static/js/security_reports.js`,
  `app/templates/admin_reports_security.html`,
  `app/templates/admin_reports_security_detail.html`, and six test files
  (see the commit message for the per-file reasons).
- Added (this commit): the six reports in `reports/` —
  `ARCHITECTURE_AUDIT.md`, `CLEANUP_REPORT.md`,
  `CYBERLLM_INTEGRATION_REPORT.md`, `TEST_RESULTS.md`,
  `PORTABILITY_REPORT.md`, `RELEASE_READINESS.md`.
- The API's `model_a_*` / `model_b_*` storage-mirror fields in
  `app/api/security_lab_api.py` were intentionally **kept**: renaming
  them would require a database migration for zero user benefit, and
  historical rows legitimately carry old values. What changed is the
  presentation: no supported consumer displays two models any more.
