# Full validation report — SentientAI release candidate

Branch: `feature/cyberllmv1-portable-runtime` (LOCAL ONLY, NOT pushed)
Base commit: `c542cc79a29f3846bbd880dee01ac0f4c7fc6277` (`origin/main`)
Working copy: `~/workspace/sentientai-main-audit`
Date: 2026-10-27
Verdict: **PASS WITH LIMITATIONS** (see §10)

Status labels used below: IMPLEMENTED / TESTED / BLOCKED / PROPOSED.

## 1. Test results — exact counts

Command (Linux VM, venv `~/workspace/sentientai-upstream/.venv`,
Python 3.12.3, torch 2.14.1+cpu, transformers 5.16.1, peft 0.20.0,
pytest 9.1.1):

```
python -m pytest -q --tb=no -p no:warnings
```

| Category | Count |
|---|---|
| Tests collected | 644 |
| Passed | 637 |
| Failed | 6 |
| Skipped | 1 (`tests/test_templates.py:59`: `partials/nav.html is not part of this layout`, pre-existing) |
| Blocked (not run, not counted as passed) | see §8 |
| Not run: Windows | all Windows-only tests (0 executed) |
| Not run: Kaggle | all Kaggle training/eval jobs (0 executed) |
| Not run: real 1.7B inference | 0 executed in this VM |
| Not run: Sentinel dual-checkpoint inference | 6 tests failed for missing artifacts (§3), not skipped |

Baseline at `c542cc7` (before this work): 601 tests, 593 passed,
7 failed, 1 skipped. This work: 644 tests (+43), 637 passed, 6
failed, 1 skipped. The one failure removed is the CSP failure
(§4); no test was deleted to make the suite green. Two
pre-existing tests were updated only because their implementation
changed (theme script and CyberLLM page script moved from inline
to external files — see §4); their behavioural assertions are
preserved and strengthened. **Audit correction (2026-10-27
review):** the first report said baseline "594 passed"; that
counted the skipped test as passed. The independently rerun
baseline (pristine worktree at `c542cc7`, JUnit: tests 601,
failures 7, skipped 1, errors 0) gives 593 passed. The current
branch's JUnit is tests 644, failures 6, skipped 1, errors 0,
hence 637 passed — verified, not repeated from the first report.
One baseline contradiction was also resolved: two baseline tests
contradicted each other (`test_security_headers_are_present`
requires no `unsafe-inline` in script-src, while the old
`test_csp_allows_inline_theme_script` required `unsafe-inline`
to be present). Only one could pass; the CSP fix resolves the
conflict in favour of the security-header test, and the old
theme-CSP test was rewritten to assert script-src has no
`unsafe-inline` while style-src still does.

Test types in the 644:
- Unit tests: evidence, dataset, portability, loader, schema (majority).
- Integration tests: TestClient app routes, auth, CSRF, DB-backed
  feedback, promotion script subprocess runs.
- Mocked / recorded inference tests: CyberLLM API tests use patched
  `generate()` (recorded/synthetic generations) — these are NOT real
  model inference and are never labelled as such.
- Real model inference tests: 0 passed in this VM. The 6 Sentinel
  tests that would be real inference fail for missing artifacts.
  Prior live v8 inference (2026-10-24, same checkpoint, earlier VM
  state) is historical evidence only, not a re-run of this branch.

## 2. The seven original failures — investigated individually

Original 7, baseline at `c542cc7`, all reproduced on this branch
before fixes:

| # | Test | Root cause | Outcome |
|---|---|---|---|
| 1 | `test_prompt_propagation_a::test_3_tokenization_preserves_tags` | `_build_tokenizer()` returns `None`: `local_models/sentinel/sentinel_tokenizer.json` absent in this VM (gitignored, not in repo). Not a code logic defect. | BLOCKED (artifact). No code change, no test deletion. |
| 2 | `test_prompt_propagation_c::test_7_fits_and_truncation` | Same tokenizer file absent; `tok.encode` on `None`. | BLOCKED (artifact). |
| 3 | `test_public_routes::test_security_headers_are_present` | CONFIRMED CODE DEFECT: `SecurityHeadersMiddleware` set `script-src 'self' 'unsafe-inline'`, while the test (correctly) requires no `unsafe-inline` in script-src. The header comment claimed it was required, but it was only required because scripts were inline. | FIXED. All 5 inline `<script>` blocks externalised to `app/static/js/` (node --check passes), 3 `onclick=` handlers replaced with `form[data-confirm]` (handled by existing `public.js`), script-src is now `'self'` only. Style-src keeps `unsafe-inline` for style attributes (documented). New regression tests: `tests/test_csp_no_inline_scripts.py` (template scan + header check), updated `test_theme.py`. |
| 4 | `test_sentinel_api::test_analyze_success_admin` | `ensure_loaded()` → `checkpoints_not_found`: both Sentinel checkpoints absent in this VM. | BLOCKED (artifact). |
| 5 | `test_sentinel_phase1::test_loader_both_models_load_and_duplicate_deduped` | Same, plus it requires checkpoint B specifically (`best_autolab_checkpoint.pt`), which was not found anywhere in the available workspace. | BLOCKED (artifact, B missing). |
| 6 | `test_sentinel_phase1::test_loader_smoke_both_process_same_sample` | Same: tokenizer `None`, models dict empty. | BLOCKED (artifact). |
| 7 | `test_sentinel_phase1::test_inference_produces_structure` | Same: `s.ready` is False. | BLOCKED (artifact). |

Improvement made for all artifact failures: `sentinel_loader.py`
now exposes `sentinel_missing_files()` and
`GET /api/sentinel/readiness` returns `missing_files` explicitly,
so a user can see exactly what to supply instead of a bare
`checkpoints_not_found`.

## 3. Sentinel artifacts — what is genuinely required

Required under `<project>/local_models/sentinel/`:

- `config.json` — vocab 7053, hidden 768, 12 layers, 12 heads,
  intermediate 3072, max_position 768, dropout 0.1, pad 0, unk 1,
  bos 2, eos 3. (A hardcoded fallback config exists in the loader,
  but the file is the documented source.)
- `sentinel_tokenizer.json`
- `sentinel_best_model.pt` — checkpoint A.
- `best_autolab_checkpoint.pt` — checkpoint B, or the deduped alias
  `best_autolab.pt` (loader dedupes B by size + 4 MB hash prefix and
  prefers the canonical name).

Verified without loading weights (no RAM for a 1.1 GB load in this
VM, and no attempt to fabricate inference):

- Checkpoint A exists in the user's archive at
  `~/workspace/sentinelai/inputs/sentinel_best_model.pt` (1.1 GB),
  with `config.json` (450 bytes, matches the loader fallback) and
  `sentinel_tokenizer.json` (463 KB). Its `data.pkl` was disassembled
  with `pickletools`: only `collections OrderedDict`,
  `torch FloatStorage`, `torch._utils _rebuild_tensor_v2` — i.e.
  weights-only loadable (see §7).
- Checkpoint B (`best_autolab_checkpoint.pt` / `best_autolab.pt`)
  was NOT found by a full workspace search. Dual-checkpoint tests
  therefore cannot pass until B is supplied. Neither checkpoint
  was deleted, renamed, moved, or modified by this work.

How to supply them: copy (do not move) the files above into
`<project>/local_models/sentinel/`, then
`GET /api/sentinel/readiness` should show `missing_files: []` and
`ready: true` after `POST /api/sentinel/readiness/load` (admin).

## 4. CyberLLM portability — IMPLEMENTED, TESTED

- Default model root is `<project>/cyberLLMv1/`, derived from
  `app/services/cyberllm_loader.py`'s location, never from cwd.
  Verified: app created from `/tmp` reports
  `model_root: …/sentientai-main-audit/cyberLLMv1`; a copy of the
  project at `/tmp/SentientAI test copy` (path with spaces) runs
  `scripts/setup_cyberllm.py --check` correctly from `/tmp` cwd.
- Loader and setup script agree on layout
  (`cyberLLMv1/{base,adapter,manifest.json,README.md}`), on adapter
  filenames (`adapter_17b_datav32_*` → canonical renames), and on
  the adapter SHA. The only untested path is the Kaggle download
  itself (no Kaggle auth in this VM — see §8).
- Incomplete explicit `CYBERLLM_MODEL_ROOT` → hard error
  (`model root incomplete … refusing to fall back to a download`),
  tested in a subprocess; status `failed`, no silent download.
- Git: `cyberLLMv1/*` ignored, `!cyberLLMv1/manifest.json` and
  `!cyberLLMv1/README.md` tracked — verified with
  `git check-ignore` and untracked-files listing. No weights,
  `.env`, venv, or `.db` in `git status`.
- Backward compatibility: `CYBERLLM_BASE_DIR`,
  `CYBERLLM_ADAPTER_DIR`, `CYBERLLM_MODEL_ROOT`,
  `CYBERLLM_BASE_MODEL`, `CYBERLLM_BASE_REVISION`,
  `CYBERLLM_ADAPTER_SHA256`, `CYBERLLM_DEVICE`,
  `CYBERLLM_LOAD_IN_8BIT` all still work; `.env.example` now
  documents the portable defaults (`CYBERLLM_DEVICE=auto`,
  no `D:\` paths).
- Other cwd defects fixed: `/static` mount (`app/main.py`),
  Jinja template dir (`app/template_env.py`), training-pipeline
  candidate dir (`app/services/training_pipeline.py`) are now
  project-root-relative. `run.bat` is unchanged (it already
  `cd /d "%~dp0"`).

## 5. Model artifacts — verified as far as possible here

Expected configuration (from `cyberLLMv1/manifest.json`):

- Base: `Qwen/Qwen3-1.7B` @
  `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`
- Adapter SHA-256:
  `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`

Verified 2026-10-27:

- HF account `Uchiha80971` via the Secure Vault connector
  (`hf_check.py whoami`, HTTP 200); repo `Qwen/Qwen3-1.7B`:
  `api_http 200, gated false, files_listed 12, config_resolve 302,
  access granted`.
- HF API revision SHA matches the pinned revision exactly.
- Base config (via HF resolve, small files only, no weight
  download): `Qwen3ForCausalLM`, hidden 2048, 28 layers, 16 heads,
  8 KV heads, intermediate 6144, vocab 151936, tied embeddings,
  `torch_dtype bfloat16`, max_position 40960.
- Base weight sizes (HEAD, following redirects):
  `model-00001-of-00002.safetensors` 3,441,185,608 bytes,
  `model-00002-of-00002.safetensors` 622,329,984 bytes,
  index `total_size` 4,063,479,808 bytes; tokenizer 11,422,654 bytes.
  Total download ≈ 4.15 GB (base + adapter), ≈ 4.2 GB with index/
  config files. Disk free in this VM: 85 GB — storage is sufficient,
  but that alone does not justify downloading here (see below).
- Adapter, from local `persist_v14` (not a download in this run):
  `adapter_17b_datav32_adapter_model.safetensors` SHA-256 matches
  the manifest exactly; `adapter_config.json` says
  `base_model_name_or_path: Qwen/Qwen3-1.7B`, LoRA r16, alpha 32,
  targets q/k/v/o/gate/up/down; tokenizer (11 MB) round-trips
  correctly (`vocab 151669`, test strings decode identically).
- Real 1.7B inference in this VM: BLOCKED, not attempted.
  Reasons: no 1.7B base weights present (only 0.6B tokenizer
  fragments, one incomplete), CPU-only, VM RAM 7.7 GB total with
  ~0.5 GB free at test time, and the target machine is the user's
  Windows PC (GTX 1660), not this VM. Downloading 4.1 GB here would
  not prove Windows GPU fit/latency and was not approved. All
  CyberLLM API tests in this run use patched `generate()` and are
  labelled mocked/recorded, never real inference.

## 6. Evidence reliability — IMPLEMENTED, TESTED

`app/services/cyberllm_evidence.py` now checks, against the input
only (summary + reasoning + indicators, not recommendations):

- Failed-attempt counts, time windows (unit-converted), ISO
  timestamps, IP addresses, IP:ports, HTTP status codes (HTTP
  request line or phrased response), URLs/domains, claimed outcome
  (success vs failure), and internal contradictions (two different
  counts/windows inside one output).
- Severity justification (API layer): a high-confidence
  `likely_threat` with no cited indicators and <20 chars of
  reasoning is downgraded to `needs_review`.
- Truncated generations are downgraded to `needs_review`
  (`decision_source: truncated_output`).

Every category has a contradiction case and a consistent control
in `tests/test_cyberllm_evidence_expanded.py`; the original
5-in-60s → 6s case is in `tests/test_cyberllm_evidence.py`.
A mismatch never rewrites model text: the API returns
`needs_review`, `confidence: low`, the mismatch quoted in
`limitations`, and the original verdict in `model_classification`
— unless a high-severity deterministic finding exists, in which
case the override still applies with the mismatch preserved as a
limitation. If a claim cannot be validated, the case is flagged
for review; it is never upgraded into a confident verdict.

Known limitation: the timestamp and domain checks are strict — a
model that mentions an unrelated timestamp/domain in its reasoning
will be flagged for review. That is intentional (review, not a
wrong verdict), and is documented in the module docstring.

## 7. Continuous learning — IMPLEMENTED (collection/prep/gate), NO TRAINING

No second pipeline was created. The existing components are reused:

- `app/models/training_example.py` (CANDIDATE → APPROVED,
  `safe_to_train` only via explicit admin action, dedup hash),
  `app/services/training.py` (review/approve/reject, duplicate
  detection), `app/services/collection.py` (redaction via
  `security_events.redact`), `app/services/training_pipeline.py`
  (candidate lifecycle), `app/cli.py` (export/status).

New, tested wiring for CyberLLM:

- `app/services/cyberllm_feedback.py`:
  `collect_cyberllm_feedback()` → `TrainingExample`,
  `source="cyberllm_feedback"`, status `CANDIDATE`,
  `safe_to_train=False`, redacted input/output, checkpoint
  provenance (base + adapter SHA). User feedback is explicitly
  NOT ground truth until approved.
- `app/services/cyberllm_dataset.py` (pure functions, unit-tested):
  contradictory labels for the same input are all excluded;
  duplicates keep only the first row; deterministic 80/10/10
  train/eval/held-out split by dedup hash; leakage against a
  frozen-eval input set excludes overlapping rows.
- `scripts/prepare_cyberllm_feedback.py`: exports only
  `APPROVED + safe_to_train` CyberLLM rows to
  `<out>/{train,eval,held_out}.jsonl` + `report.json`. Without
  `--eval-inputs` it exits 2 with an explicit leakage warning.
- `scripts/promote_cyberllm_candidate.py`: check mode (candidate
  SHA, approval file with approver + `decision="approved"` +
  existing evaluation report) changes nothing; `--apply
  --backup-dir DIR --confirm "I APPROVE"` backs up the current
  adapter, copies the candidate, verifies SHA, writes
  `<backup-dir>/promotion.json`; `--rollback --backup-dir DIR`
  restores the previous adapter and verifies its SHA. The
  production adapter is preserved until an approved replacement
  exists. Promotion script tests use a tmp model root and never
  touch the real `cyberLLMv1/adapter`.
- Training itself: PROPOSED, not launched. The Kaggle workflow,
  frozen-benchmark acceptance criteria, and approval file format
  are documented in `CYBERLLM_PORTABLE_SETUP.md` §5.

## 8. Security and reliability — fixed defects + gaps

Fixed and tested:

- CSP script-src `unsafe-inline` removed (§2, §1#3).
- Sentinel `torch.load(weights_only=False)` → `weights_only=True`.
  Verified safe for the real checkpoint A by `pickletools`
  disassembly (only OrderedDict + tensor rebuilds). A tiny real
  `SentinelModel` checkpoint loads under `weights_only=True`
  (`test_sentinel_checkpoint_loads_weights_only`).
- CyberLLM analyze rate limit: 20 requests / 10 minutes per user
  (`limit_cyberllm_analyze`), tested to return 429 on the 21st call.
  This addresses resource exhaustion on the most expensive endpoint
  (8000-char cap and 16–512 token cap already existed).
- Prompt injection: log text is treated as untrusted data
  (`prompts/prompt.txt` + `_sanitize_tag_injection`); tested that
  `<instruction>evil</instruction>` in a log cannot add tags to
  the prompt. Log inputs are never executed by any endpoint.
- Secrets: `git diff` scan found no keys, tokens, `.env`, or
  weights in the change set; `.env.example` contains placeholders
  only; the only `SECRET_KEY=` hit in the pre-existing tree is
  placeholder text in docs. HF/Kaggle credentials were never
  printed or recorded (Secure Vault / `~/.kaggle` only).
- Training-data poisoning: only `APPROVED + safe_to_train` rows
  export; conflicting labels are excluded, not averaged; held-out
  is never used for training/tuning; promotion requires an
  approval file + evaluation report + SHA verification.

Reviewed, no defect found (documented, not changed):

- CyberLLM analyze/screen require login; readiness/load requires
  admin; CSRF double-submit is live in tests; `MAX_LOG_CHARS=8000`
  is enforced by both Pydantic and `validate_log_text`.
- Model-generated claims are never auto-acted on: no
  auto-remediation, no MITRE field, deterministic findings are
  narrow and cited, and every uncertain verdict is `needs_review`.
- Path handling: `CYBERLLM_*` env vars are operator config, not
  API input, so absolute-path overrides are intentional; the
  prompt-file path is already escape-checked (existing test).
- Remaining gap (PROPOSED, not a regression): CyberLLM screen has
  no rate limit of its own, but it is deterministic-rules only
  (no model inference) and login-gated; the analyze limit covers
  the expensive path.

## 9. Sentinel portability and cleanup

Portability:

- `sentinel_loader.py` already derives `MODEL_DIR` from the file
  location; `prompt_service.py` already derives its prompt path
  the same way. Fixed in this work: template dir and static dir
  and training-pipeline candidate dir are now project-root
  relative (§4). No `C:\` / `D:\` / home-directory paths remain
  in runtime code (the only such strings in the diff are
  deletions).
- Startup from another cwd: verified for CyberLLM readiness and
  template rendering in tests; full `run.py` startup from another
  cwd is covered by the same project-root fixes, but the Windows
  launch itself is BLOCKED (see §10).

Removed files (all staged deletions, reviewable in the diff;
recovery copies at `~/workspace/sentientai-cleanup-recovery-20261027/`):

- 9 one-off diagnostic scripts at the repo root
  (`_diag_tmp.py`, `_diag2_tmp.py`, `_diag3_tmp.py`, `_diag_db.py`,
  `_phase2_quick.py`, `_quick_logits.py`, `_quick_logits2.py`,
  `_sentinel_diag2.py`, `_sentinel_diag_phase2.py`): no import
  from `app/` or `tests/` (verified by grep), each hardcodes
  `C:\Users\DARK\Desktop\wild clude\SentientAI` and writes
  throwaway result JSON. Safe to remove; they remain in Git
  history on `main` and in the recovery copy.
- `app/services/security_lab_run2.py`: its own docstring says
  "Unused helper — kept for reference, not imported anywhere",
  and grep confirms no caller.
- `app/services/security_lab_runner_a.py`: its own docstring says
  it is a re-export shim with no direct importers; the canonical
  runner is `security_lab_runner.py`. Grep confirms no caller.

NOT removed, with reason:

- `datasets/` (82 MB: CSIC raw 29 MB + normalized 54 MB + docs):
  used only by `TESTv1/training_factory/` (ingest/probe/tests),
  not by `app/` or `tests/`, but it is data with provenance
  (manifest + validation report), not dead code. Deleting it
  would break the factory's reproducibility. Flagged for a
  separate user decision (e.g. Git LFS or an archive), not
  deleted here.
- `TESTv1/`: historical factory + reports, the only consumer of
  `datasets/`; not in pytest's `tests/` path, but not dead
  in the same sense as the diagnostic scripts.
- `Documentation/Documentation.zip` (1.6 MB) + technical guide
  PDF (108 KB): bundled docs, not code; size is noted, not a
  reason alone to delete.
- Tracked patch copy `sentientai-cyberllm-windows (1).patch`
  (88 KB): referenced by `CYBERLLM_WINDOWS_SETUP.md`
  (`git apply sentientai-cyberllm-windows.patch` — note the
  filename in the doc does not exactly match the tracked
  `(1)` name; fix that doc reference in the next docs pass,
  do not delete the patch).
- Both Sentinel checkpoints and all alternates: never deleted
  or renamed (see §3).

## 10. Files changed, blockers, and verdict

Changed (tracked, `git diff --stat HEAD`): 33 files, 434
insertions, 925 deletions (deletions are mostly the 11 removed
files above). Modified: `.env.example`, `.gitignore`,
`app/api/cyberllm.py`, `app/api/sentinel.py`, `app/main.py`,
`app/services/cyberllm_loader.py`, `app/services/ratelimit.py`,
`app/services/sentinel_loader.py`,
`app/services/training_pipeline.py`, `app/template_env.py`,
8 templates, `tests/test_cyberllm_api.py`,
`tests/test_theme.py`, plus the preserved evaluation files
(see below).

Added (untracked, ready to stage after review):
`CYBERLLM_PORTABLE_SETUP.md`, `reports/full_validation_report.md`
(this file), `app/services/cyberllm_dataset.py`,
`app/services/cyberllm_evidence.py`,
`app/services/cyberllm_feedback.py`, 5 JS files under
`app/static/js/`, `cyberLLMv1/manifest.json`,
`cyberLLMv1/README.md`, `scripts/prepare_cyberllm_feedback.py`,
`scripts/promote_cyberllm_candidate.py`,
`scripts/setup_cyberllm.py`, 6 new test files.

Preserved evaluation data: `evaluation/latest.json` and
`evaluation/moderation_latest.json` were restored after every
full test run to their preserved hashes
(`7fb612b5fecc7c472ce7c3487d8f981936523b8077e430917519e78ff5f31717`
and
`61a10731944086949fa413119566c9b3f30c5302704bbcc7980711190b1f48b1`).
Their diff vs HEAD is only timestamp/latency churn from test
runs, not a change made by this work, and they must stay
separate from this branch's commit.

Diff review: `git diff --check` clean; no weights, `.env`,
venv, or `.db` in status; machine-specific paths appear only
as deletions; no secrets in the diff.

Remaining blockers (all require the user's machine or explicit
approval; none were worked around by faking a result):

1. **Sentinel checkpoint B missing** — dual-checkpoint Sentinel
   tests (6) cannot pass until `best_autolab_checkpoint.pt`
   (or `best_autolab.pt`) is supplied to
   `local_models/sentinel/`. Checkpoint A + tokenizer are in
   the user's archive; B was not found in this workspace.
2. **Live 1.7B inference not re-run** — no base weights in this
   VM, CPU-only, low free RAM. Requires a Windows run with
   `cyberLLMv1/` populated (see §5 and the Windows commands in
   `CYBERLLM_PORTABLE_SETUP.md` §3).
3. **Windows launch not tested** — `run.bat start` is preserved
   byte-for-byte, but this VM is Linux. Only a Windows run can
   prove it, plus GPU fit/latency on the GTX 1660 (6 GB).
4. **Kaggle download path untested** — adapter download via
   Kaggle CLI was not executed here (no Kaggle auth in this VM);
   the commands and filenames are documented and the SHA check
   is implemented, but the first real download must be on the
   user's machine.
5. **No training launched** — by design. Candidate evaluation,
   approval, and promotion are gated workflows, not automatic.

### Audit additions (2026-10-27 review, before commit)

Final audited counts (JUnit, after review fixes): 651 tests,
644 passed, 6 failed, 1 skipped, 0 errors. The +7 tests vs the
first report are the new `ensure_loaded` incomplete-base test
and the 6-test `test_learning_workflow_e2e.py` lifecycle suite;
all 7 pass, and the 6 failures are unchanged (same Sentinel
artifact list). Relevant subset (portability, CyberLLM API,
evidence, feedback, learning, CSP, E2E/security, public routes,
theme): 111 tests, 0 failures.

- `ensure_loaded()` now also fails clearly when a base/adapter
  directory exists but is incomplete (previously only an explicit
  `CYBERLLM_MODEL_ROOT` got the clear error; a present-but-empty
  default base dir fell through to a transformers error). A
  missing base directory still takes the HF-download path, and a
  missing adapter still fails on the SHA check. Tested in
  `tests/test_cyberllm_portability.py`.
- `CYBERLLM_WINDOWS_SETUP.md` now carries a portability header
  pointing to `CYBERLLM_PORTABLE_SETUP.md`; its `D:\` commands
  are legacy examples, not defaults.
- Dependencies audit: `requirements.txt` intentionally does NOT
  contain torch / transformers / peft / accelerate /
  `huggingface_hub` / `kaggle` — the app fails open without
  torch, and the ML installs are documented in
  `CYBERLLM_WINDOWS_SETUP.md` §5 and `cyberLLMv1/README.md`.
  `requirements.txt` alone is therefore NOT sufficient for model
  inference; the Windows checklist in §10 of this report's
  companion doc lists the ML installs explicitly. This was not
  changed, because adding torch to `requirements.txt` would
  change every install's size and break the fail-open design;
  it needs a separate decision.
- `scripts/setup_cyberllm.py --download-adapter` (Kaggle CLI
  single-file download + canonical rename) remains untested
  here (no Kaggle auth in this VM). The Windows checklist
  therefore includes a manual-download fallback and a SHA check
  before any launch, and says to check existing files first
  rather than overwriting them.

### Verdict: PASS WITH LIMITATIONS

The release candidate passes 637/644 tests on Linux, fixes the
one confirmed code defect (CSP), expands evidence, portability,
feedback, and security coverage with tests, and removes only
provably unused files. It is NOT a full PASS because Sentinel
dual inference (6 tests) and live 1.7B inference cannot be
verified without artifacts and a Windows/GPU machine that this
VM is not. Nothing in this report claims a Windows, Kaggle, or
real-model test passed unless it was actually executed there.

### Git status

- Branch: `feature/cyberllmv1-portable-runtime`, base `c542cc7`.
- NOT pushed, NOT merged, remote `main` NOT modified.
- Next step is user review of this branch's diff; staging and
  committing are left to the user (or to an explicit approval),
  with the evaluation files kept separate from that commit.
