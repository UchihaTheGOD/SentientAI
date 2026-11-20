# Architecture audit — Sentinel two-model system vs CyberLLMv1

Branch: `feature/cyberllmv1-portable-runtime`
Commit before this audit: `77f1118332d96086746f74acddfdc87e0fe933be`
Base: `c542cc79a29f3846bbd880dee01ac0f4c7fc6277`
Checkpoint patch (branch vs base, saved outside the repo before any
change in this audit):
`~/workspace/sentientai-checkpoint-branch-20261027.patch`
(SHA-256 `30b029e7c5586e5d1d9ed7d506db2c314fc4de794789c4ece8e19aa8c3dbe502`,
218,201 bytes)
Working tree at audit start: only `evaluation/latest.json` and
`evaluation/moderation_latest.json` modified (preserved timestamp/
latency churn, hashes `7fb612b5…` / `61a10731…`), nothing else.
Remote `main` untouched; nothing pushed or merged.

## Executive summary

The six failing tests are **not** evidence that the Sentinel
architecture is obsolete. They are evidence that a live, still-used
subsystem is running without its deployment artifacts in this VM.

Model A and Model B are two checkpoints of the *same* small custom
transformer (`SentinelModel`, vocab 7053, hidden 768, 12 layers),
loaded CPU-only, and used by live routes, the incident workflow,
content moderation, the security lab, and the demo/bridge pipelines.
CyberLLMv1 does **not** replace them: it replaces only the model-
classification step of log analysis, with a different contract, and
it provides no incident, block, review, moderation, security-lab, or
demo functionality. Deleting Sentinel to make six tests pass would
break those features and their API contracts.

The one genuinely obsolete part found is narrow: **Model B is
optional, not required, for Sentinel core functionality.** The
loader marks `ready` when *at least one* model loads
(`ready = len(models) > 0`), and fusion scores rules-only when a
model is unavailable, never fabricating a model verdict. Model B
is required only for the *agreement* comparison and for the
specific dual-load test that asserts both models. That distinction
— B optional for core, required for agreement — is the correct
framing, and it is now tested explicitly.

Measured effectiveness, from the repo's own documentation
(`Documentation/DETECTION_REPORT.md`, `EVALUATION.md`,
`SENTINEL_DIAGNOSTIC_REPORT.md`), is a separate, honest caveat:
on a 26-case probe, Model A produced 24 empty + 2 garbage outputs
and Model B 26 empty, for a 0% structured-valid rate, so fused
verdicts in practice equal the deterministic rules. That makes the
Sentinel *models* weak, not the Sentinel *system* useless — the
rules, incidents, blocks, reviews, and moderation scaffolding
still function, and CyberLLMv1 is the stronger classifier for the
classification step. It does not justify deleting the system
without a migration design, because no migration contract exists
yet.

## Architecture before this audit

```
User / browser
  ├─ GET /sentinel, /admin/sentinel/incidents
  ├─ POST /api/sentinel/analyze ──► prompt_service.build_analysis_prompt
  │                                  (prompts/prompt.txt, tag-sanitised)
  │                                ► run_dual_inference (A + B, CPU)
  │                                ► sentinel_fusion.fuse / fuse_structured
  │                                  (rules 50% weight; a model counts only
  │                                   if its output is structured-valid)
  │                                ► incident_service.create_incident
  │                                  (review queue, temp blocks)
  ├─ POST /api/security/demo/run/{case}, /api/security/lab/*
  │     ► same dual inference + fusion (bridge, security lab)
  ├─ moderation flags ──► sentinel_moderation.run_moderation_for_text
  │     (single model, A preferred, B fallback; skipped if not ready)
  └─ POST /api/cyberllm/analyze ──► Qwen3-1.7B + LoRA v8 (cyberLLMv1/)
        (JSON schema, evidence checks, deterministic SSRF rules;
         NO incident/block/review/moderation; 503 when unavailable)
Startup: lifespan schedules Sentinel background warm-load
(init_sentinel(background=True), fail-open). CyberLLM is lazy:
it loads only on explicit load/analyze, never at startup.
```

## Model A and Model B — what each does

| Item | Model A | Model B |
|---|---|---|
| File | `local_models/sentinel/sentinel_best_model.pt` (1.1 GB in archive) | `local_models/sentinel/best_autolab_checkpoint.pt` (1.09 GB in docs; alt `best_autolab.pt` deduped by size + 4 MB hash prefix) |
| Definition | `sentinel_model.py: SentinelModel` + root `config.py: SentinelConfig` (vocab 7053, hidden 768, 12 layers, 12 heads, intermediate 3072, max_pos 768, pad 0/unk 1/bos 2/eos 3) | Same class, same config, different weights |
| Tokenizer | Shared `sentinel_tokenizer.json` (vocab 7053; added tokens `<pad> <unk> <bos> <eos> <instruction> </instruction> <input> </input> <output> </output>`, ids 0–9 in that order, verified from the archive file) | Same tokenizer |
| Load | `sentinel_loader._load_single_checkpoint` → `torch.load(..., map_location="cpu", weights_only=True)`, `load_state_dict(strict=False)`, smoke generation asserting logits shape | Same function, same path |
| Inference | `sentinel_inference._generate_for_model` (greedy, CPU, timeout 12 s, semaphore 2, tail-preserving truncation, EOS/PAD/control/repetition stops) | Same function, same prompt — tests assert both calls receive the identical prompt |
| Fusion weight | 0.25 if status ok, else 0.12, and only if structured-valid | Same |
| Agreement | `run_dual_inference` compares A/B verdict keywords when both produce text; fusion itself notes "Models A and B are same family (Sentinel finetune); agreement is not independent confirmation" | — |

**Coupled or independent?** Independent at load (each checkpoint
loads or fails on its own; `ready` needs only one) and coupled
only at the agreement feature (which needs both texts). Model A
does not depend on Model B, and vice versa. Removing B alone
removes agreement and the dual-load test, but not Sentinel
analysis, incidents, or moderation (moderation already prefers A
and falls back to B only if A is absent).

**GPU cost:** None. Sentinel checkpoints load CPU-only and
inference runs on the model device, which is CPU. The old models
consume RAM only when loaded (~1.9 GB noted in `main.py` for the
background load) and zero when absent. They do not compete with
CyberLLMv1 for VRAM.

**CyberLLM dependence:** Zero. No `cyberllm_*` module and no
`app/api/cyberllm.py` imports any sentinel module (tested in
`tests/test_sentinel_architecture_audit.py`). The two loaders
resolve different roots (`local_models/sentinel/` vs
`cyberLLMv1/`).

## The six failing tests — individual investigation

All six were reproduced in this VM before any change in this
audit. None was deleted, skipped, or weakened.

| # | Test | Original failure | Production path | Required assets | Still required? | Action | Final result |
|---|---|---|---|---|---|---|---|
| 1 | `test_prompt_propagation_a::test_3_tokenization_preserves_tags` | `tok` is `None` → `AttributeError` on `tok.encode` | `sentinel_loader._build_tokenizer()` → `tokenizers.Tokenizer.from_file(local_models/sentinel/sentinel_tokenizer.json)`; used by every Sentinel generation (prompt must start with `<instruction>`, end with `<output>`) | Real `sentinel_tokenizer.json` (463 KB in archive, vocab 7053, special tokens verified) | Yes — it verifies the *real* tokenizer preserves the tags the inference code depends on. A synthetic tokenizer would test a different property and would hide a broken real tokenizer. | Kept unchanged. Supplying the file (see §Model requirements) is the valid way to run it; it is not a mock candidate. | Still fails in this VM (file absent here); passes where the tokenizer is supplied. Not a code defect. |
| 2 | `test_prompt_propagation_c::test_7_fits_and_truncation` | Same `None` tokenizer | Same tokenizer + `sentinel_inference` truncation budget (`max_pos 768 − max_new 256 − 4 = 508`, tail-preserving middle-drop) | Same tokenizer | Yes — truncation behaviour is live inference code, not a legacy detail. | Kept unchanged. | Same as #1. |
| 3 | `test_sentinel_api::test_analyze_success_admin` | `assert s.ready` fails (`ready=False, a='not_found', b='not_found', reason='checkpoints_not_found'`) | `sentinel_loader.ensure_loaded()` then `POST /api/sentinel/analyze` | Both checkpoints (test asserts `s.ready` only; the analyze call itself does not require models — see below) | Yes as a readiness test, but its *assertion* is stricter than the API contract: analyze itself returns 200 rules-only when models are missing (proven by the passing `test_incident_review_authz` and by the new architecture test). The test therefore proves loader readiness, not that analyze is broken. | Kept unchanged. Do not relax its `s.ready` assertion to make it pass — that would hide the missing-artifact state. | Still fails in this VM for the documented artifact reason. |
| 4 | `test_sentinel_phase1::test_loader_both_models_load_and_duplicate_deduped` | Same `checkpoints_not_found` | `ensure_loaded()` + `_choose_checkpoint_b()` | A + B (canonical `best_autolab_checkpoint.pt`; test asserts `b.name == "best_autolab_checkpoint.pt"`, so the alt alone does not satisfy it) + tokenizer (vocab 7053) | Yes for the dual/agreement feature, no for core Sentinel. This is the one test whose requirement is genuinely *dual-only*: it asserts `s.a == "loaded" and s.b == "loaded"`. | Kept unchanged. Its failure is the correct signal that B is absent, not a reason to delete B's code path. | Still fails in this VM (B absent here). |
| 5 | `test_sentinel_phase1::test_loader_smoke_both_process_same_sample` | `tok` is `None` / models dict empty | `get_models()` + `get_tokenizer()` + direct `SentinelModel` forward | A + B + tokenizer | Yes for dual-model smoke coverage; single-model smoke is already covered by the loader's own smoke generation per checkpoint. | Kept unchanged. | Still fails in this VM. |
| 6 | `test_sentinel_phase1::test_inference_produces_structure` | `assert s.ready` fails | `ensure_loaded()` + `run_dual_inference()` | A + B + tokenizer (test asserts both `model_a` and `model_b` are not None) | Yes as a dual-inference structure test. | Kept unchanged. | Still fails in this VM. |

**What happens when A/B are unavailable (measured, not assumed):**

- App startup: succeeds. Lifespan schedules a background Sentinel
  load that fails open; no crash.
- `GET /api/sentinel/readiness`: 200, `ready: false`,
  `phase: "phase_0_placeholder"`, `missing_files` listing the
  exact absent files (verified live in this VM).
- `POST /api/sentinel/analyze` (authenticated, models absent):
  200, rules-based verdict, `model_a`/`model_b` status
  `"unavailable"`, incident still created when requested
  (proven by passing tests and by the new architecture test).
  It does **not** fabricate a model verdict and does **not**
  incorrectly report ready.
- Anonymous analyze: 401/403 (auth/CSRF), same as with models.
- Moderation: `skipped_not_ready` when not ready; human review
  is required when moderation JSON is invalid (contract tests).
- CyberLLM: unaffected (separate loader, separate root, lazy).

## Inventory classification

**KEEP (required by current functionality):**

- `sentinel_loader.py` (dual loader, tokenizer, status, missing_files)
- `sentinel_inference.py` (`run_dual_inference`, `_generate_for_model`)
- `sentinel_fusion.py` (deterministic rules + fusion; works model-free)
- `sentinel_schema.py` (structured validation, `fuse_structured`)
- `sentinel_moderation.py` (content moderation via single model)
- `sentinel_bridge.py` (security events / ATTACT findings → incidents)
- `app/api/sentinel.py` (readiness, analyze, incidents, blocks, review, training candidates)
- `app/api/security.py` demo route, `app/api/security_lab_api.py` lab routes
- `sentinel_model.py`, root `config.py`, `prompts/prompt.txt`, `app/services/prompt_service.py`
- `app/templates/sentinel.html`, `admin_sentinel.html`, `app/static/js/sentinel_form.js`, `admin_sentinel_review.js`
- `app/models/sentinel_incident.py`, `app/services/incident_service.py`, `training_pipeline.py` (Sentinel candidates)
- All CyberLLMv1 code (`cyberllm_loader/inference/rules/schema/evidence/feedback/dataset`, `app/api/cyberllm.py`, `scripts/setup_cyberllm.py`, `cyberLLMv1/manifest.json`)

**MIGRATE (proposed, NOT implemented — needs a design decision and user approval):**

- Sentinel analyze's *model classification* step could optionally
  be sourced from CyberLLMv1, but the contracts differ:
  Sentinel returns `model_a/model_b/agreement/fusion/risk_score/
  verdict/incident_id` and creates incidents/blocks; CyberLLM
  returns `classification/confidence/deterministic_findings/
  limitations` and creates nothing. A migration would need a
  contract mapping, an incident-creation decision, and a
  moderation decision (CyberLLM has no moderation prompt), and
  it must not silently change existing clients. No code was
  changed for this in this audit.

**REMOVE (proven obsolete, implemented in this audit):**

- `sentinel_loader._check_ram` — defined, never called anywhere
  in app, tests, scripts, or docs (repository-wide grep).
- `sentinel_loader.is_ready` — same, no callers (callers use
  `get_status().ready`).
- `sentinel_loader.has_any_model` — same, no callers.
  Regression proof: full suite after removal (see §Test results).
  These are dead helpers, not architecture; removing them does
  not change any behaviour.

**INVESTIGATE (insufficient evidence to remove — left intact):**

- Model B checkpoint file itself: optional for core, required
  for agreement. Whether to *stop shipping* B is a data decision
  for the user, not a code deletion: the loader already handles
  its absence gracefully, and deleting the file from the user's
  archive would be destructive and irreversible here. Left intact;
  no file was deleted.
- Local base-revision trust: CyberLLM's loader verifies the
  adapter SHA but trusts a local `cyberLLMv1/base/` directory
  without verifying its revision (the pinned revision is enforced
  only by `setup_cyberllm.py --download-base`). A manually placed
  wrong revision would load silently. This is a documented
  limitation, not a proven defect to fix by guessing a revision
  check (Qwen config carries no revision field).
- Sentinel model effectiveness (0% structured-valid in the
  documented probe): whether to retrain or replace the Sentinel
  checkpoints is out of scope (no retraining in this task) and
  is not a reason to delete the surrounding system.

**Explicitly NOT removed:** Model A, Model B code paths,
Sentinel subsystem, Sentinel APIs, Sentinel tests, `datasets/`,
`TESTv1/`, Documentation, tracked patch, checkpoints, databases,
`.env` files, or any user data. No model file was downloaded in
this audit.

## Model requirements (final application)

| Model | Purpose | Path | Size (verified) | Hash / revision |
|---|---|---|---|---|
| CyberLLMv1 base (PRIMARY) | LLM log/URL/vulnerability analysis via `POST /api/cyberllm/analyze` | `cyberLLMv1/base/` | ~4.06 GB weights (3,441,185,608 + 622,329,984 bytes, index total 4,063,479,808) | Qwen/Qwen3-1.7B @ `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e` (HF API revision match, earlier audit) |
| CyberLLMv1 adapter (PRIMARY, LoRA, NOT merged) | Pilot v8, data-v3.2 | `cyberLLMv1/adapter/` | ~82 MB (69,782,384 bytes weights) | SHA-256 `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1` (verified locally from persist_v14; loader refuses SHA mismatch) |
| Sentinel tokenizer (REQUIRED for Sentinel inference) | Tokenizes Sentinel prompts, special tags | `local_models/sentinel/sentinel_tokenizer.json` | 463 KB (archive) | Vocab 7053, special tokens ids 0–9 as above (verified from archive file, not from a download) |
| Sentinel Model A (REQUIRED for Sentinel inference; single-model core works with A alone) | Sentinel log analysis, moderation (preferred model) | `local_models/sentinel/sentinel_best_model.pt` | 1.1 GB (archive; 1,092,932,897 B in repo docs) | No SHA recorded in code; `weights_only=True` load verified for this file by pickletools (OrderedDict + tensor rebuilds only) |
| Sentinel Model B (OPTIONAL for core, REQUIRED for agreement + dual test) | Second Sentinel checkpoint for agreement comparison | `local_models/sentinel/best_autolab_checkpoint.pt` (or alt `best_autolab.pt`, deduped) | 1.09 GB in repo docs (1,092,935,695 B) | Not found in this workspace; do NOT download it until you decide agreement is required — the app works without it |
| Qwen3-0.6B pilot v3 | Fallback only, not primary | Not in `cyberLLMv1/` by default | — | Not required for this release; manifest warns against substituting `adapter_datav2_*` (v3) for v8 |

## Windows / GPU verification (static checks only — no hardware claim)

This VM: Python 3.12.3, torch 2.14.1+cpu (CUDA False),
transformers 5.16.1, peft 0.20.0, accelerate 1.14.0. Windows
hardware (GTX 1660, 32 GB RAM) is **not** available here, so
nothing below is a verified Windows/GPU result.

- Paths: `Path(__file__).resolve()` + `_resolve_against_root`
  (absolute stays absolute, including drive letters; relative
  resolves against PROJECT_ROOT, not cwd) — Windows-safe by
  construction; spaces-in-path already tested for the project
  copy in the previous audit.
- Base/adapter distinct: `cyberLLMv1/base` vs `cyberLLMv1/adapter`,
  distinct env overrides, manifest fallback for id/revision/SHA.
- Legacy env vars: `CYBERLLM_BASE_DIR`/`ADAPTER_DIR` still
  override, `CYBERLLM_MODEL_ROOT` overrides the root; precedence
  is documented in the loader docstring. A legacy var set in
  `.env` *will* override the portable default — that is by
  design for compatibility, and the Windows checklist tells the
  user to leave them unset.
- Missing artifacts: `setup_cyberllm.py --check` (no download,
  exit 1 with exact missing list), `ensure_loaded` clear errors
  for explicit roots and for present-but-incomplete dirs, and
  `GET /api/cyberllm/readiness` (unauthenticated, honest
  `ready: false` + `model_root` when absent).
- No silent substitution: adapter SHA mismatch refuses load;
  a missing base dir falls back to HF id + pinned revision
  (documented, not silent — the status shows `base@revision`);
  a wrong local base revision is the one trust gap noted above.
- Lazy loading: CyberLLM loads only on explicit load/analyze;
  Sentinel loads in a background thread at startup and fails open.
- GPU/precision (static compatibility only): `CYBERLLM_DEVICE`
  auto/cpu/cuda; CUDA → float16 (Turing has no BF16, so float16
  is the correct choice); 8-bit via `BitsAndBytesConfig` only
  when `CYBERLLM_LOAD_IN_8BIT=1` (Windows CUDA builds exist for
  11.7–12.4 per bitsandbytes v0.43.2, untested on the user's PC).
  Estimated peak ~4.5 GB for 1.7B float16 on a 6 GB card —
  **estimate, not measured**. Sentinel never touches the GPU.
- Missing torch/transformers: CyberLLM `ensure_loaded` raises
  `RuntimeError("PyTorch is not installed...")`, converted by
  the API to HTTP 503 `model_unavailable` with deterministic
  findings; the app itself still starts.
- Real inference on Windows: **NOT VERIFIED** (no Windows, no
  1.7B weights, no CUDA in this VM). Stage E is reported as
  NOT VERIFIED, not passed.

## Test results

Stage A (baseline / integrity): branch `77f1118` + working tree
(evaluation churn only) was the baseline for this audit;
`git diff --check` clean before and after the dead-helper removal.
No unrelated changes overwritten; checkpoint patch saved before
any change.

Stage B (architecture / dependency): new
`tests/test_sentinel_architecture_audit.py` (6 tests, all pass):
single-model ready by design (`ready = len(models) > 0`),
fusion rules-only with no fabricated verdict, CyberLLM imports
no sentinel module, Sentinel CPU-only by construction,
dead helpers removed without breaking the loader surface, and
Sentinel analyze degrades to rules (200, `model_a/b:
unavailable`) when models are missing.

Stage C (API / security): subset rerun (see Stage F) includes
auth, rate limit, CSP, evidence, feedback, and E2E/security
tests — all pass. No security behaviour was weakened; no test
assertion was weakened in this audit (no existing test was
modified at all).

Stage D (model-independent): the architecture tests above use
deterministic fixtures/mocks and are labelled as such; they do
not claim model accuracy.

Stage E (real inference): **NOT VERIFIED** in this VM (no 1.7B
weights, no CUDA, no Windows). Previous live v8 inference
(2026-10-24, earlier code state) is historical evidence only
and is not re-claimed for this branch.

Stage F (full regression): see the commit-time run below; the
only failures are the six documented artifact tests, unchanged
in cause from the baseline.

## Remaining risks

1. Sentinel model quality: documented 0% structured-valid rate
   means Sentinel model outputs currently add nothing beyond
   rules. If you rely on Sentinel analyze for a real decision,
   you are relying on rules + human review, not on the models.
   CyberLLMv1 is the stronger classifier, but it is not yet
   wired into Sentinel's incident workflow.
2. Model B absence: agreement is unavailable wherever B is
   absent, and the dual-load test will keep failing there.
   That is a data-supply decision, not a code bug.
3. Local base-revision trust (see INVESTIGATE above).
4. `evaluation/results_*.json` files generated by test runs are
   git-ignored and were left on disk; they are not part of any
   commit.
5. Windows/GPU/CUDA verification is entirely outstanding and
   must be done on the user's PC with the checklist from the
   previous report (updated in §Next steps).

## Exact next steps (Windows, only genuinely required artifacts)

Do not download Sentinel Model B unless you want the agreement
feature and the dual-load test to pass. If you do, copy (do not
move) `best_autolab_checkpoint.pt` into
`local_models\sentinel\` alongside the tokenizer and Model A
from your archive, then `GET /api/sentinel/readiness` should
show both models. If you do not need agreement, Sentinel works
with Model A + tokenizer alone, and CyberLLMv1 is the primary
analysis model.

```powershell
cd D:\path\to\SentientAI
git branch --show-current
git rev-parse HEAD
# CyberLLMv1 (required, primary)
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --check
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-base
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-adapter
(Get-FileHash cyberLLMv1\adapter\adapter_model.safetensors -Algorithm SHA256).Hash
# Expected: d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1
# Sentinel (required only if you want Sentinel inference; copy from your archive, do not download blindly)
#   local_models\sentinel\sentinel_tokenizer.json
#   local_models\sentinel\sentinel_best_model.pt
#   local_models\sentinel\best_autolab_checkpoint.pt   # optional, agreement only
Copy-Item .env.example .env
run.bat start
Invoke-RestMethod http://127.0.0.1:8000/api/cyberllm/readiness | ConvertTo-Json -Depth 5
Invoke-RestMethod http://127.0.0.1:8000/api/sentinel/readiness | ConvertTo-Json -Depth 5
run.bat test
```

Report back: adapter SHA match, `cuda_available`, readiness
JSONs, one real CyberLLM analyze response, and the exact test
counts. Do not label Windows inference as passed until you have
run it.
