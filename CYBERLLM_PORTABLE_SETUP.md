# CyberLLM portable setup — SentientAI

This is the release-candidate setup document for the portable CyberLLM
installation. It replaces the old `D:\CyberLLM\models\` workflow: no
source file needs to be edited to change a model path, and no
machine-specific folder is a runtime dependency.

## 1. What you need

- A clone/copy of this project (any folder, including a path with spaces).
- Python 3.12, a virtual environment, and the project requirements
  (`requirements.txt`, `requirements-dev.txt` for tests).
- About **4.2 GB** free disk for the model, plus RAM/VRAM:
  - Base: Qwen/Qwen3-1.7B @ `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`
    - `model-00001-of-00002.safetensors` 3,441,185,608 bytes
    - `model-00002-of-00002.safetensors` 622,329,984 bytes
    - `tokenizer.json` 11,422,654 bytes, plus `config.json`,
      `tokenizer_config.json`, `model.safetensors.index.json`
    - Total weight size 4,063,479,808 bytes (from the HF index).
  - Adapter: pilot v8, LoRA r16/alpha 32, data-v3.2, NOT merged
    - `adapter_model.safetensors` 69,782,384 bytes
    - SHA-256 `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`
    - Do NOT substitute `adapter_17b_datav2_*` (pilot v4) or
      `adapter_datav2_*` (pilot v3, 0.6B).
- HF access: Qwen/Qwen3-1.7B is ungated; verified 2026-10-27 as
  `granted` for account `Uchiha80971` (config resolve 302).
- Kaggle access for the private adapter dataset
  `uchihamadarum/cyber-llm-artifacts` (v14 files
  `adapter_17b_datav32_*`). Kaggle credentials stay in
  `~/.kaggle/kaggle.json` (Linux) / `%USERPROFILE%\.kaggle\kaggle.json`
  (Windows); no credential is stored in this repo.

## 2. Layout

```
SentientAI/
  cyberLLMv1/
    base/                 # full Qwen3-1.7B files at the pinned revision
    adapter/              # adapter_config.json, adapter_model.safetensors, tokenizer files
    manifest.json         # tracked in Git: model, revision, adapter SHA, layout
    README.md             # tracked in Git: download + verify commands
```

`cyberLLMv1/` is the default model root, resolved from the loader
file's location (`app/services/cyberllm_loader.py`), not from the
current working directory. Moving the project or launching from
another folder does not change it. Weights under `cyberLLMv1/` are
ignored by `.gitignore`; only `manifest.json` and `README.md` are
tracked.

Precedence (highest first):
1. `CYBERLLM_BASE_DIR` / `CYBERLLM_ADAPTER_DIR` (legacy, kept compatible)
2. `CYBERLLM_MODEL_ROOT/{base,adapter}` (+ its `manifest.json`)
3. `<project>/cyberLLMv1/{base,adapter}` (+ its `manifest.json`)
4. Legacy adapter only: `<project>/local_models/cyberllm/v8`, when the
   `cyberLLMv1` adapter is absent. Base still falls back to the HF id.

An explicitly set `CYBERLLM_MODEL_ROOT` that is incomplete is a hard
error (`model root incomplete … refusing to fall back to a download`),
never a silent multi-GB download.

## 3. Windows commands (exact)

Run these from the project folder (PowerShell). `run.bat` already
does `cd /d "%~dp0"`, so its `venv\` path is relative to the batch
file, not to the caller's folder.

```powershell
# 1. Clone / copy the project, then enter it
cd SentientAI

# 2. Python venv + dependencies
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt

# torch is deliberately not in requirements.txt: it is a large,
# platform-specific install. The CUDA 12.1 wheel supports Turing
# (compute 7.5), e.g. the GTX 1660 SUPER.
.\venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu121

# 3. Check what is missing (no download, no credentials needed)
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --check

# 4. Download the base model (~4.1 GB, resumable via huggingface_hub)
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-base

# 5. Download the adapter (~82 MB, Kaggle CLI, then canonical renames)
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-adapter
#    -- or manually, per cyberLLMv1/README.md, then verify:
#    Get-FileHash cyberLLMv1\adapter\adapter_model.safetensors -Algorithm SHA256
#    must equal d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1

# 6. Configure (copy the example, never commit a real .env)
Copy-Item .env.example .env
#    Edit .env: set SECRET_KEY to a long random value, keep
#    CYBERLLM_DEVICE=auto (float16 on CUDA, float32 on CPU;
#    CYBERLLM_LOAD_IN_8BIT=1 only if float16 does not fit).
#    Do NOT set CYBERLLM_BASE_DIR / CYBERLLM_ADAPTER_DIR to D:\ paths
#    unless you intentionally override the portable default.

# 7. Start (unchanged interface)
run.bat start
#    App: http://127.0.0.1:8000

# 8. Test the CyberLLM page (login first, then open /cyberllm)
#    Readiness: GET /api/cyberllm/readiness
#    Load (admin): POST /api/cyberllm/readiness/load
#    Analyse: POST /api/cyberllm/analyze with log_text + kind
#    Run the suite: run.bat test
```

Hardware note (user's PC, unverified in this release): GTX 1660 OC
6 GB VRAM, 32 GB RAM, i5-12600K. The 1.7B base in float16 is ~3.4 GB
of weights, ~4.5 GB peak estimated; Turing has no BF16, so the loader
uses float16 on CUDA. GPU fit and latency on that card are still
BLOCKED — they can only be measured on that machine.

## 4. Obsolete Sentinel models — REMOVED (2026-10-27 migration)

The old Sentinel Model A / Model B checkpoints, tokenizer, prompt
file, loader, dual inference, and model-agreement logic were removed
from this branch. **Do not download `sentinel_best_model.pt`,
`best_autolab_checkpoint.pt`, `best_autolab.pt`, or
`sentinel_tokenizer.json` — nothing in the application requires them
any more, and the application starts without them.**

What replaced them:
- Classification: CyberLLMv1 via `app/services/classifier.py`
  (`classify_log` + `fuse_classification`), used by
  `POST /api/sentinel/analyze`, the bridge, demo, and security lab.
- Deterministic rules: `app/services/security_rules.py` (unchanged
  thresholds, scores, and verdicts from the old fusion rules).
- Incidents, blocks, review queue, and human-review workflows:
  unchanged, now fed by CyberLLMv1 + rules.
- Moderation: human-only. CyberLLMv1 is a security-log classifier,
  not a content-moderation classifier, so it is not forced into
  that role; moderation candidates are born from a moderator's
  decision and are never auto-approved.

`GET /api/sentinel/readiness` now reports the CyberLLMv1 classifier
status (`classifier: "cyberllm"`, `legacy_models: "removed"`,
`rules_available: true`) instead of Sentinel checkpoint files.

## 5. Continuous learning (no training in this release)

The existing reviewed-feedback pipeline is reused, not duplicated:

1. **Collect:** `app/services/cyberllm_feedback.py`
   `collect_cyberllm_feedback()` records a reviewed CyberLLM analysis
   as a `TrainingExample` with `source="cyberllm_feedback"`,
   status `CANDIDATE`, `safe_to_train=False`, redacted input/output,
   and checkpoint provenance (base + adapter SHA). A CANDIDATE is
   user feedback, NOT ground truth.
2. **Review:** `app/services/training.py` `review_example` /
   `approve_example` — only an explicit admin approval moves a row
   to `APPROVED` + `safe_to_train=True`, with duplicate detection.
3. **Prepare:** `python scripts/prepare_cyberllm_feedback.py --out
   data/cyberllm_feedback [--eval-inputs frozen_eval.jsonl]`
   - Contradictory labels for the same input are all excluded.
   - Duplicates keep only the first row.
   - Deterministic split: 80 train / 10 eval / 10 held-out by hash.
   - Without `--eval-inputs` the script exits 2 with a leakage warning;
     do not train until that check has run.
4. **Evaluate a candidate:** on Kaggle (or another training host),
   against the frozen benchmarks, with acceptance criteria recorded
   in an approval file. Training itself is NOT launched by this repo.
5. **Promote (gated):**
   `python scripts/promote_cyberllm_candidate.py --candidate-dir DIR
   --approval approval.json` — check mode only, changes nothing.
   Add `--apply --backup-dir DIR --confirm "I APPROVE"` to back up
   the current `cyberLLMv1/adapter`, copy the candidate in, verify
   its SHA, and write `<backup-dir>/promotion.json`.
   Rollback: `--rollback --backup-dir DIR` restores the previous
   adapter and verifies its SHA. The previous production adapter is
   preserved until an approved replacement exists.

## 6. What is NOT in this release

- No live 1.7B inference in the Linux VM (no base weights, CPU-only,
  low free RAM) — see the validation report for exact reasons.
- No Windows launch test in the Linux VM — `run.bat start` is
  preserved byte-for-byte, but only a Windows run can prove it.
- No Kaggle training job, no retraining, no model replacement.
- No MITRE ATT&CK technique IDs in any API response (by design).
