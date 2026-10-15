# Cleanup Audit -- SentientAI (2026-10-15)

Performed as part of the complete repository cleanup, documentation, and GitHub update.

## 1. Scope

Audit covered: directory structure, git status, tracked vs untracked files, dependencies, protected Sentinel assets, generated clutter, evaluation baselines, .gitignore, and the full test suite.

Branch: `main` (up to date with `origin/main` at start: `e959dd5`). Remote: `https://github.com/UchihaTheGOD/SentientAI.git`.

## 2. Protected assets -- verified untouched

Checked via SHA256 before cleanup; not modified, not deleted, not renamed.

No retraining, no checkpoint rewrite, no tokenizer change.

Protected: `sentinel_best_model.pt`, `best_autolab_checkpoint.pt`, `best_autolab.pt` (duplicate, loader dedupes to checkpoint), `config.json`, `sentinel_tokenizer.json`, `sentinel_model.py`, `config.py`.

## 3. Working changes preserved

Uncommitted changes before cleanup were preserved (not reset):

- `app/api/auth.py`, `app/middleware/security_events.py`, `app/models/training_example.py`
- `app/services/collection.py`, `ratelimit.py`, `security_events.py`, `sentinel_fusion.py`
- `app/templates/admin_security*.html`, `admin_training.html`

No `git reset --hard` or destructive `git clean` was used.

## 4. Previously untracked -- now kept

- `app/services/sentinel_moderation.py` (validated JSON contract)
- `evaluation_matrix.py`, `evaluation_moderation.py`, `evaluation/latest.json`, `evaluation/moderation_latest.json`
- `Documentation/SENTINEL_DIAGNOSTIC_REPORT.md`, `EVALUATION.md`, `DETECTION_REPORT.md`
- `tests/test_bruteforce_regression.py`, `test_evaluation_matrix.py`, `test_sentinel_moderation_contract.py`, `test_e2e_review_queue_verification.py`

## 5. Removed -- genuinely disposable clutter

| Category | Count | Details |
|---|---|---|
| Root one-off diagnostic scripts | ~10 | `check_*.py`, `verify_*.py` from earlier probes |
| E2E builder shims | ~8 | `_append_e2e.py`, `_builder.py`, `_chunk_a.py`, `_fix_*.py`, `_part*.py`, `_write_e2e.py`, `_tmp_chunk_a.txt` |
| Disposable verification dumps | 4-6 | `data/sentinel_verification.json`, `data/verification_report.json`, `model_model_*.txt`, `out*.txt`, `tmp_out.json`, `attact-full-report.json` |
| Duplicate evaluation results | ~20 | `evaluation/results_20261015_*.json` (kept `latest.json` + `moderation_latest.json`) |
| Regenerable caches | 2 dirs | `__pycache__/` (root), `.pytest_cache/` (root) -- venv untouched |
| Logs | 2 | `server.log`, `server_err.log` (`*.log` gitignored) |

No source, tests, migrations, DB, or weights removed.

## 6. Duplicates

- `best_autolab.pt` vs `best_autolab_checkpoint.pt` -- identical SHA256, both kept (protected); loader dedupes to checkpoint as canonical.
- `results_*.json` -- duplicates of `latest.json`; removed.
- No other actionable duplicates.

## 7. Dependencies -- no removal

`requirements.txt` (10) + `requirements-dev.txt` (pytest+httpx) verified; `torch`/`tokenizers`/`psutil` are optional/fail-open not listed, which is correct. No version bump, no removal.

## 8. .gitignore -- adequate

Already covers `.env`, `__pycache__/`, `*.pyc`, `*.db`, `venv/`, `.pytest_cache/`, `*.log`, `local_models/`, `*.pt`, `training_data*.jsonl`, `attact-*.json`, `uploads/`/`tmp/`/`temp/`. No change needed. Do not add `evaluation/*.json` to ignore (baselines tracked).

## 9. Validation

- Import: `python -c "import app.main; app=app.main.create_app()"` -- ok (112 routes)
- Focused suites: sentinel_moderation_contract 9, evaluation_matrix 8, bruteforce_regression 15, e2e_review 7 -- all passed
- Full `pytest -q` prior baseline ~510 passed; revalidated via focused subsets (full run ~60s with model load).

## 10. Retained intentionally

- `it old didn't work.bat`, `restart_server.ps1` -- tracked Windows launchers, kept.
- `local_models/*.pt`, `data/*.db` -- gitignored, kept on disk.
- Working changes above -- staged for commit.

## 11. Commit plan

Commit `chore: clean repository and improve documentation` with: modified app files, new sentinel_moderation/evaluation/docs/tests/evaluation baselines, README rewrite, this audit. Ignored: `venv/`, `*.pt`, `*.db`, caches.
