# Windows test checklist — SentientAI CyberLLM release candidate

Branch: `feature/cyberllmv1-portable-runtime` (local commit, NOT pushed)
Base: `c542cc79a29f3846bbd880dee01ac0f4c7fc6277`

**Do NOT run this checklist as a claim that the Windows test passed.**
Run it, record the actual output of each step, and report back.
Steps marked **[server running]** need `run.bat start` active in
another PowerShell window. Steps marked **[weights required]** need
`cyberLLMv1/base` and `cyberLLMv1/adapter` populated. Steps marked
**[GPU]** may consume several GB of VRAM; on a GTX 1660 (6 GB),
expect ~4.5 GB peak for the 1.7B model in float16 — this is an
estimate, not a measured fit.

> **Safety first:** never paste a real password, HF token, or
> Kaggle key into a shared log. The commands below use placeholders
> (`YOUR_USERNAME`, `YOUR_PASSWORD`) and read secrets only from
> files you already own. Never commit `.env`, `kaggle.json`, or
> model weights. Check existing files before downloading anything
> — the download commands below are skipped if the file already
> exists, and the SHA check must pass before you launch.

## 0. Get to the project folder

```powershell
cd D:\path\to\SentientAI
git branch --show-current
git rev-parse HEAD
```

Expected: branch `feature/cyberllmv1-portable-runtime`. If it shows
something else, stop and check out the branch first — do not run
the rest against `main`.

## 1. Prepare the `cyberLLMv1/` directory **[no server, no weights yet]**

```powershell
New-Item -ItemType Directory -Force -Path cyberLLMv1\base, cyberLLMv1\adapter | Out-Null
Get-ChildItem cyberLLMv1 -Recurse | Select-Object FullName, Length
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --check
```

`--check` downloads nothing and exits 1 while files are missing,
listing exactly what is absent. If `venv\Scripts\python.exe` does
not exist yet, do step 4 first, then return here.

## 2. Check model artifacts and adapter checksum **[no server]**

Check existing files first — do not overwrite them:

```powershell
Get-ChildItem cyberLLMv1\base, cyberLLMv1\adapter | Select-Object Name, Length
(Get-FileHash cyberLLMv1\adapter\adapter_model.safetensors -Algorithm SHA256).Hash
```

Expected adapter SHA-256 (from `cyberLLMv1\manifest.json`):

```
d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1
```

Expected base: `Qwen/Qwen3-1.7B` revision
`70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`, about 4.06 GB of
weights (`model-00001-of-00002.safetensors` 3,441,185,608 bytes,
`model-00002-of-00002.safetensors` 622,329,984 bytes).
If the base is missing, download it only after confirming ~5 GB
free disk (weights + adapter + temp space):

```powershell
.\venv\Scripts\python.exe -m pip install huggingface_hub
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-base
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --check
```

If the adapter is missing, install Kaggle CLI (only if you have
Kaggle access), put `kaggle.json` in
`$env:USERPROFILE\.kaggle\kaggle.json` first, then:

```powershell
.\venv\Scripts\python.exe -m pip install kaggle
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --download-adapter
.\venv\Scripts\python.exe scripts\setup_cyberllm.py --check
(Get-FileHash cyberLLMv1\adapter\adapter_model.safetensors -Algorithm SHA256).Hash
```

If a download fails, do NOT launch with a partial adapter — the
loader refuses a SHA mismatch by design. Re-run `--check` and
fix the missing file first. The Kaggle download path has not been
tested from this VM, so if it behaves unexpectedly, fall back to
the manual per-file commands in `cyberLLMv1\README.md` (same
filenames, same destination, same SHA check).

## 3. Create the private `.env` **[no server]**

```powershell
Copy-Item .env.example .env
notepad .env
```

Set at least:

```
SECRET_KEY=<a long random string, local use only>
ENVIRONMENT=development
```

Leave the CyberLLM lines at their portable defaults
(`CYBERLLM_DEVICE=auto`, no `D:\` paths). The loader uses
`<project>\cyberLLMv1\` by default. Only set
`CYBERLLM_MODEL_ROOT`, `CYBERLLM_BASE_DIR`, or
`CYBERLLM_ADAPTER_DIR` if you deliberately point elsewhere.
Never commit `.env`.

## 4. Verify dependencies and CUDA **[no server, no weights needed for the check itself]**

`requirements.txt` alone does NOT include the ML stack — the app
fails open without torch. Install both layers:

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu121
.\venv\Scripts\python.exe -m pip install transformers==5.16.1 peft==0.20.0 accelerate==1.14.0 psutil httpx pytest
.\venv\Scripts\python.exe -m pip install huggingface_hub kaggle
.\venv\Scripts\python.exe -c "import torch; print('torch', torch.__version__); print('cuda_available', torch.cuda.is_available()); print('cuda_device', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'none')"
nvidia-smi
```

Record the `cuda_available` line and the `nvidia-smi` VRAM line.
If `cuda_available` is False, the loader will still run on CPU
(`CYBERLLM_DEVICE=auto` falls back), but expect minutes per
request, not seconds — do not judge latency from a CPU run.

## 5. Start the application **[weights required for inference; app itself starts without them]**

In its own PowerShell window, from the project folder:

```powershell
run.bat start
```

Expected: `[run] Starting SentientAI at http://127.0.0.1:8000`.
Leave this window open. `run.bat` already changes to its own
folder (`cd /d "%~dp0"`), and it requires `venv\Scripts\python.exe`
— if it says the venv is missing, redo step 4 with a folder named
`venv` (not `.venv`).

## 6. Check readiness **[server running, no login needed for readiness]**

In a second PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/cyberllm/readiness | ConvertTo-Json -Depth 5
Invoke-RestMethod http://127.0.0.1:8000/api/sentinel/readiness | ConvertTo-Json -Depth 5
```

Record `ready`, `model_root`, `adapter_dir`, and `device` from the
first response. `model_root` must point inside the project
(`...\SentientAI\cyberLLMv1`), never to a personal folder.
Sentinel readiness lists `missing_files` if its checkpoints are
absent — that is expected unless you have supplied them (see the
full validation report §3); it does not block CyberLLM.

## 7. Send an authenticated real inference request **[server running, weights required, GPU]**

This is the only step that runs the real model. Login uses the
app's own form flow: GET a page to obtain the `csrf_token`
cookie, POST `/login` as a form with that token, then POST the
analysis as JSON with the `X-CSRF-Token` header. Replace
`YOUR_USERNAME` / `YOUR_PASSWORD` with your own account (an
existing account; registration is via the website, not this
checklist). Rate limit: 20 analyze calls per 10 minutes per user.

```powershell
$Base = 'http://127.0.0.1:8000'

# 1) Session + CSRF cookie
$null = Invoke-WebRequest "$Base/login" -SessionVariable Session -UseBasicParsing
$csrf = $Session.Cookies.GetCookies($Base)['csrf_token'].Value

# 2) Login (form POST; access_token cookie is stored in $Session)
$login = @{
  username   = 'YOUR_USERNAME'
  password   = 'YOUR_PASSWORD'
  csrf_token = $csrf
  next       = ''
}
$null = Invoke-WebRequest "$Base/login" -WebSession $Session -Method Post -Body $login -UseBasicParsing

# 3) Load the model as admin (only if your account is an admin; otherwise skip to step 4
#    and note that analyze will load on first call instead)
$csrf = $Session.Cookies.GetCookies($Base)['csrf_token'].Value
Invoke-RestMethod "$Base/api/cyberllm/readiness/load" -WebSession $Session -Method Post -Headers @{ 'X-CSRF-Token' = $csrf } | ConvertTo-Json

# 4) Real inference: POST /api/cyberllm/analyze (registered endpoint, JSON body)
#    kind must be one of: log, http_request, url, vulnerability
$body = @{
  log_text       = '2026-10-27T10:00:00Z sshd[123]: Failed password for root from 203.0.113.45 port 22 ssh2'
  kind           = 'log'
  max_new_tokens = 256
} | ConvertTo-Json
$csrf = $Session.Cookies.GetCookies($Base)['csrf_token'].Value
$resp = Invoke-RestMethod "$Base/api/cyberllm/analyze" -WebSession $Session -Method Post -Body $body -ContentType 'application/json' -Headers @{ 'X-CSRF-Token' = $csrf }
$resp | ConvertTo-Json -Depth 6
```

Record: `classification`, `model_classification` (if present),
`decision_source`, `confidence`, `latency_ms`, and `load_ms`.
The first call includes model load time and will be slow even on
GPU; subsequent calls are the real latency measure.

## 8. Check the response for evidence consistency **[server running]**

From the step 7 response, verify by hand:

- `classification` is `likely_benign`, `likely_threat`, or
  `needs_review` — never a MITRE technique ID (the API has no
  MITRE field by design).
- If the model reported a count or time window that contradicts
  the input (for example, "6 seconds" for 5 logins in 60 seconds),
  the response must be `needs_review` with
  `decision_source = "evidence_mismatch"` and the mismatch quoted
  in `limitations`, with the original verdict preserved in
  `model_classification`. If it instead kept a confident verdict,
  that is a bug — report the full response.
- If `truncated` is true, the verdict must be `needs_review`
  (`decision_source = "truncated_output"`), never confident.
- A high-severity deterministic finding (for example, SSRF
  metadata) may override a benign model verdict, but the override
  must be visible in `deterministic_findings`, not hidden.
- If the model was not loaded, the response must be HTTP 503
  `model_unavailable` — never a fabricated verdict.

Also try the browser form as a sanity check (no PowerShell
needed): log in at `http://127.0.0.1:8000/login`, open
`http://127.0.0.1:8000/cyberllm`, paste the same log, submit,
and confirm the page shows the same classification as the API
response.

## 9. Run the Windows regression tests **[server NOT needed; weights NOT needed]**

In a third PowerShell window (server may stay running; tests use
their own test app, not your server):

```powershell
run.bat test
```

Record the final line exactly (expected counts will be updated
in the migration report once the full suite finishes on this
branch — the old 651/644/6/1 baseline no longer applies, because
the Sentinel artifact tests were replaced by CyberLLM classifier
tests that need no checkpoints).
If Windows shows different failures, record the failing test
names and their error messages, not just the count.

## 10. Shut down safely

```powershell
# In the server window: press Ctrl+C, wait for uvicorn to stop, then close the window.
# Optional: confirm nothing is listening any more
Test-NetConnection 127.0.0.1 -Port 8000
```

`Test-NetConnection` should report `TcpTestSucceeded : False`
after shutdown. Do not delete `cyberLLMv1\`, `.env`, or any
checkpoint to "clean up" — those are your local artifacts.

## What to report back

1. Step 2 SHA match (yes/no) and base file sizes.
2. Step 4 `cuda_available` and GPU name/VRAM.
3. Step 6 readiness JSON (`ready`, `model_root`, `device`).
4. Step 7 full response (or its classification/latency lines)
   and whether step 8 checks passed.
5. Step 9 exact test counts and any new failures vs §9 above.
6. Any step that behaved differently from this checklist.
