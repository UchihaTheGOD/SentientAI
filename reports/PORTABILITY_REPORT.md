# SentientAI Portability Report

Branch: `feature/cyberllm-desktop-portable` (code commit `8a5aee9`).
Goal: the project runs on another user's machine from environment
configuration alone — no hard-coded paths, no bundled weights, no
secrets in Git.

## 1. Configuration (environment variables, not machine paths)

| Variable | Purpose | Default |
|---|---|---|
| `CYBERLLM_MODEL_ROOT` | Whole model tree (base + adapter + manifest) | project `cyberLLMv1/` |
| `CYBERLLM_BASE_DIR` | Base model directory override | `<root>/base` |
| `CYBERLLM_ADAPTER_DIR` | Adapter directory override | `<root>/adapter` (else legacy `local_models/cyberllm/v8`) |
| `CYBERLLM_BASE_MODEL` | Base model id (download path) | `Qwen/Qwen3-1.7B` |
| `CYBERLLM_BASE_REVISION` | Base revision (download path) | `70d244cc…` (full value in CYBERLLM_INTEGRATION_REPORT) |
| `CYBERLLM_ADAPTER_SHA256` | Expected adapter hash (load refused on mismatch) | `d624ed79…5a5b1` |
| `CYBERLLM_DEVICE` | `auto` / `cpu` / `cuda` | `auto` |
| `CYBERLLM_LOAD_IN_8BIT` | `1` = 8-bit quantization on CUDA | unset (off) |
| `SECRET_KEY` | JWT/CSRF signing key (see `.env.example`) | must be set by the operator |

`.env.example` documents these with examples. The development paths
`D:\CyberLLM\models\Qwen3-1.7B` and `D:\CyberLLM\models\cyberllm-v8`
are examples only and appear nowhere in the shipped code or config —
verified by grep: the only `D:`-style assertion left in the tree was
the portability test's, which this branch removed (see TEST_RESULTS).

## 2. Path handling

- All shared code uses `pathlib`; no Linux-only or Windows-only path
  assumptions in the loader, inference service, or GUI settings.
- Defaults are project-relative (derived from the loader file's
  location, never from the process working directory — covered by
  `test_default_root_is_project_local_not_cwd`).
- Startup scripts quote every path, so project paths containing spaces
  (e.g. `D:\AI TEST\SentientAI`) work: `run.bat` quotes `%PY%` and
  changes drive+directory with `cd /d "%~dp0"`; `run.sh` quotes
  `"$PY"` and `cd "$(dirname "$0")"`.
- GUI user data (settings, logs, reports, history) lives outside the
  executable: `%APPDATA%\CyberLLMv1 Security Lab` on Windows,
  `~/.local/share/cyberllm-security-lab` elsewhere. The GUI never writes
  into its own install folder.

## 3. Startup scripts (fixed on this branch)

- `run.bat` (Windows): tries `.venv\Scripts\python.exe` first, then
  `venv\Scripts\python.exe`. The previous script accepted only `venv`,
  while the actual dev environment is `.venv` — this was a real,
  user-facing break, now fixed. Tasks: `start`, `test`, `status`,
  `export`, `export-eval`, `backfill`, `help`. CRLF line endings
  preserved.
- `run.sh` (Linux/macOS, new): tries `.venv/bin/python`, then
  `venv/bin/python`. Tasks: `start`, `test`, `status`, `help`.
  Syntax-checked (`bash -n`) and error-path-checked on this VM; a
  full boot through `run.sh` was not possible here because no
  repo-local venv exists in this VM (see TEST_RESULTS §8).
- The GUI launches the backend via `python -m uvicorn app.main:app`
  (not `run.py`, which enables reload) and stops only backends it
  started itself.

## 4. Model acquisition and verification (no weights in the repo)

Weights are never committed and never bundled into the exe. Procedure
(documented in `CYBERLLM_PORTABLE_SETUP.md` and the GUI build guide):

1. Base (~4.06 GB, ungated, resumable):
   `huggingface-cli download Qwen/Qwen3-1.7B --revision
   70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`
   into `cyberLLMv1/base/` (or a configured directory).
2. Adapter (~82 MB, private Kaggle dataset
   `uchihamadarum/cyber-llm-artifacts` v14): download the
   `adapter_17b_datav32_*` parts, rename to the canonical
   `adapter_config.json` / `adapter_model.safetensors`, place in
   `cyberLLMv1/adapter/`.
3. Verify before first run:
   `scripts/setup_cyberllm.py --check` (file presence + adapter SHA-256
   against `d624ed79…5a5b1`), or the GUI Control Center's SHA check.
   The loader re-verifies the hash on load and refuses on mismatch.
4. `scripts/setup_cyberllm.py --download-base` / `--download-adapter`
   automate steps 1–2 where supported.

## 5. Device and memory ladder (measured where possible)

1. CUDA fp16 (GTX 1660 SUPER 6 GB): expected path; peak VRAM estimate
   ~4.5 GB is **unverified** — measure on first Windows run.
2. `CYBERLLM_LOAD_IN_8BIT=1` (official bitsandbytes CUDA builds) if
   fp16 does not fit. Untested on the target PC.
3. `CYBERLLM_DEVICE=cpu` (fp32) if no usable GPU: works, but slow —
   measured 2026-10-24 on 2 CPUs at ~1.5–1.9 tok/s with 4.53 GB RSS for
   the 1.7B + adapter. Do not assume acceptable interactive performance
   without measuring on the target machine.
4. No weights / no torch / SHA mismatch → readiness reports the exact
   reason; the website keeps working with rules-only analysis and an
   honest `unavailable` model status.

## 6. Windows verification commands (for the operator's PC)

From the repo root, in PowerShell, after cloning and checking out this
branch:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe scripts\setup_cyberllm.py --check
# expect: adapter SHA d624ed79…5a5b1, no missing files
Copy-Item .env.example .env   # then set SECRET_KEY; keep CYBERLLM_DEVICE=auto
.\run.bat start
.\run.bat test
```

Then, in a browser: register, log in, open Sentinel (Log Analyzer),
submit the benign sudo log and the SSRF log, and confirm the page shows
the CyberLLMv1 classification with its source/status (not
`model_status: unavailable` with no model contribution). For the GUI:
`security_lab\packaging\build_windows.bat`, then double-click the
produced exe and run the Control Center checks (project root, venv
Python, adapter SHA, backend start, first real inference) and record
GPU fit/latency.

## 7. Platform matrix (honest)

| Platform | Tested here | Not tested here |
|---|---|---|
| Linux (this VM, no GPU) | Full suites, GUI offscreen build, backend start/stop, `run.sh` syntax + error path, all six targeted fix areas | `run.sh` full boot (no repo venv), real inference (no weights/torch) |
| Windows | Nothing (this VM is Linux) | `run.bat` tasks, exe build + double-click, GPU fit/latency, 8-bit path, browser click-through, Windows test run (the confirming step for the three fixes) |

No Windows result is claimed. The Windows items above are the release
blockers listed in RELEASE_READINESS.md.
