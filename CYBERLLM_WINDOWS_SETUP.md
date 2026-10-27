# CyberLLM on Windows — download, configure, run, test

Goal: run the already-trained CyberLLM model locally on a Windows PC
through the existing SentientAI website. No retraining, no new website,
no Docker/Kubernetes, no paid services, no publishing.

## 1. Which model was selected, and why

**Selected: pilot v8** — Qwen3-1.7B base + data-v3.2 LoRA adapter.
It is the leading development candidate: it resolved the threat
assertiveness / benign calibration / abstention trade-off seen at 0.6B
scale, with frozen T5 perfect, T3b abstention 1.00, T2 0.95 and
val_v3_log accuracy 0.9583. It is NOT fully promoted, because frozen
T1 is 0.9583 (one SSRF miss) and T4 schema is 0.80 (one CVE truncation)
— see the honest caveats in section 8. Do not present it as
production-ready solely because it loads.

**Fallback: pilot v3** — Qwen3-0.6B + data-v2 adapter, the overall
reference checkpoint. Use it if v8 fails to load or behaves badly
(section 7). Never overwrite either checkpoint.

**Adapter, not merged model.** The trained artifact is a LoRA/PEFT
adapter (`peft_type: LORA`, r16, alpha 32, trained on Qwen3-1.7B).
It does NOT contain the base weights, so you must download BOTH the
exact base model revision AND the adapter. The loader merges the
adapter onto the base in memory at load time; nothing is written back
to disk.

## 2. Your hardware, and the loading configuration

- GPU: NVIDIA GTX 1660 OC — **6 GB VRAM** (confirm with
  `nvidia-smi --query-gpu=name,memory.total --format=csv`).
- RAM: 32 GB. CPU: Intel i5-12600K. OS: Windows.

Why float16 on this GPU: Turing cards (GTX 16 series) have no
bfloat16 tensor-core support, while float16 works. The loader already
does this automatically: CUDA → float16, CPU → bfloat16. Do not force
bfloat16 on this card.

VRAM math for pilot v8 in float16: weights ~3.4 GB + CUDA context,
KV cache and activations ~1 GB → roughly **4.5 GB peak**, which fits
6 GB but is tight if the desktop/browser also hold VRAM. Plan:
1. Try `CYBERLLM_DEVICE=cuda` (or unset = auto) first.
2. If you get a CUDA out-of-memory failure (readiness state `failed`,
   or a 503 with an OOM reason), retry with
   `CYBERLLM_LOAD_IN_8BIT=1` after `pip install bitsandbytes`.
   Official bitsandbytes ships Windows CUDA builds (11.7–12.4 per its
   v0.43.2 installation docs), and CUDA 12.1 is inside that range, so
   the install is worth trying — but the 8-bit load path itself is
   still UNTESTED on this PC (the author has no GPU), so if the
   install or the load fails, skip straight to step 3. Do not
   substitute the unofficial `bitsandbytes-windows` fork.
3. If that also fails, `CYBERLLM_DEVICE=cpu`. 32 GB RAM is plenty
   (CPU peak was ~4.5 GB in testing); it is just slower.

Speed: on a 2-CPU Linux VM without a GPU, v8 took 116–241 s per
request. On your GTX 1660 expect much faster responses, but no exact
figure is promised here — measure it with the latency shown on the
`/cyberllm` results card and treat the CPU numbers as the ceiling.

## 3. What changes in the SentientAI repo

Nothing in this setup touches GitHub settings, and nothing was pushed
to `https://github.com/UchihaTheGOD/SentientAI` by the author. You
apply the `cyberllm-integration` branch changes to your own clone:

- NEW `app/services/cyberllm_loader.py` — lazy base+adapter loader,
  adapter sha256 verification, fail-open without torch.
- NEW `app/services/cyberllm_inference.py` — greedy generation with
  the frozen eval prompt templates verbatim, `enable_thinking=False`.
- NEW `app/services/cyberllm_rules.py` — deterministic SSRF /
  credential-probe / repeated-probe rules with cited evidence.
- NEW `app/services/cyberllm_schema.py` — JSON extraction/validation.
  Deliberately NO MITRE ATT&CK field: exact technique-ID prediction
  measured 0.000–0.025, so IDs must never be presented as findings.
- NEW `app/api/cyberllm.py` — `GET /api/cyberllm/readiness`,
  `POST /api/cyberllm/readiness/load` (admin),
  `POST /api/cyberllm/screen`, `POST /api/cyberllm/analyze`
  (login required), plus the `GET /cyberllm` website form page.
- NEW `app/templates/cyberllm.html` — the analyze form, reusing the
  existing base layout and the existing CSRF double-submit pattern
  (same `X-CSRF-Token` header mechanism as the `/sentinel` page).
- EDIT `app/main.py` — two lines: register `cyberllm.router`.
- NEW `tests/test_cyberllm_api.py` — 11 endpoint/page tests.
- NEW `scripts/cyberllm_live_test.py` — scripted live battery.
- NEW `CYBERLLM_INTEGRATION.md`, `CYBERLLM_INTEGRATION_REPORT.md`,
  and this file.

Apply with the supplied patch file (see section 4), or merge the
`cyberllm-integration` branch if you have it. Auth, authorization
and CSRF protections are unchanged: analyze/screen require login,
the load endpoint requires admin, and the form page redirects
anonymous visitors to `/login`.

## 4. Apply the code changes to your clone (PowerShell)

```powershell
git clone https://github.com/UchihaTheGOD/SentientAI
cd SentientAI
git apply sentientai-cyberllm-windows.patch
git status --short
```

If `git apply` fails because upstream `main` has moved since the
patch was made, apply the files listed in section 3 by hand — the
patch is only a delivery vehicle, and every file above is new except
the two-line change in `app/main.py`.

## 5. Install Python dependencies (PowerShell)

Python 3.12 is recommended. From the `SentientAI` directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cu121
pip install transformers==5.16.1 peft==0.20.0 accelerate==1.14.0 psutil httpx pytest
```

Notes: the CUDA 12.1 torch wheel supports Turing (compute 7.5).
`psutil` is only for RSS reporting; the loader works without it.
If you ever see a `torchao` ImportError from peft, run
`pip uninstall -y torchao` — that conflict was observed in Kaggle
kernels, not in a fresh install, but the fix is the same.

Create a `.env` file next to `run.py` with a private secret (local
use only; never commit it):

```powershell
@"
SECRET_KEY=replace-this-with-a-long-random-string
ENVIRONMENT=development
"@ | Out-File -Encoding utf8 .env
```

## 6. Download the model files

### 6a. Base model — Qwen/Qwen3-1.7B, revision pinned (Hugging Face)

Qwen3-1.7B is Apache-2.0 and ungated: no license approval, no token
needed. The revision below is the exact one the pilots trained and
evaluated against. Do not substitute `main` or another revision —
weights can change under a moving branch.

```powershell
pip install huggingface_hub
huggingface-cli download Qwen/Qwen3-1.7B `
  --revision 70d244cc86ccca08cf5af4e1e306ecf908b1ad5e `
  --local-dir D:\CyberLLM\models\Qwen3-1.7B `
  --local-dir-use-symlinks False
```

Files you should end up with (~4.1 GB total):

| File | Size (bytes) |
|---|---|
| `model-00001-of-00002.safetensors` | 3,441,185,608 |
| `model-00002-of-00002.safetensors` | 622,329,984 |
| `model.safetensors.index.json` | 25,605 |
| `config.json`, `generation_config.json` | small |
| `tokenizer.json`, `tokenizer_config.json`, `vocab.json`, `merges.txt` | ~15 MB |

Hugging Face downloads resume automatically after an interruption —
just re-run the same command. It also verifies file hashes itself.

### 6b. Trained adapter — pilot v8, from your private Kaggle dataset

Authoritative source: your private Kaggle dataset
`uchihamadarum/cyber-llm-artifacts` (version 14). Only the six
`adapter_17b_datav32_*` files are pilot v8. **Warning: do NOT pick
`adapter_17b_datav2_*` — that is pilot v4 (1.7B, data-v2), a different
checkpoint with the same file size.** `adapter_datav2_*` is the 0.6B
pilot v3 fallback, not v8.

```powershell
pip install kaggle
# Put your kaggle.json at $env:USERPROFILE\.kaggle\kaggle.json first
# (Kaggle account page -> API -> Create New Token). Never share it.
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_adapter_config.json   -p D:\CyberLLM\models\cyberllm-v8
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_adapter_model.safetensors -p D:\CyberLLM\models\cyberllm-v8
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_chat_template.jinja    -p D:\CyberLLM\models\cyberllm-v8
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_tokenizer.json         -p D:\CyberLLM\models\cyberllm-v8
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_tokenizer_config.json  -p D:\CyberLLM\models\cyberllm-v8
```

The Kaggle CLI does not resume interrupted downloads, but these
files total only ~82 MB, so re-running a failed download is cheap.
Rename the downloads to the canonical adapter filenames the loader
expects:

```powershell
cd D:\CyberLLM\models\cyberllm-v8
Rename-Item adapter_17b_datav32_adapter_config.json   adapter_config.json
Rename-Item adapter_17b_datav32_adapter_model.safetensors adapter_model.safetensors
Rename-Item adapter_17b_datav32_chat_template.jinja    chat_template.jinja
Rename-Item adapter_17b_datav32_tokenizer.json         tokenizer.json
Rename-Item adapter_17b_datav32_tokenizer_config.json  tokenizer_config.json
```

Verify the weights — the loader refuses to load on a mismatch, and
this hash was re-verified against the Kaggle bundle copy:

```powershell
(Get-FileHash D:\CyberLLM\models\cyberllm-v8\adapter_model.safetensors -Algorithm SHA256).Hash
# must equal: D624ED793A45A64CB541577441C87C7D2FEB83C37A84DA057D1C15E58E45A5B1
```

Adapter total: ~82 MB (weights 69,782,384 bytes + tokenizer
11,422,650 bytes + small files). **Combined download: ~4.2 GB.**

## 7. Launch SentientAI with CyberLLM enabled (PowerShell)

Environment variables only — no Linux paths are hard-coded anywhere
in the code; the defaults are repo-relative and every path below is
an override. These last for the PowerShell session; use `setx` only
if you want them persistent (a new terminal is then required).

```powershell
cd SentientAI
.\.venv\Scripts\Activate.ps1
$env:CYBERLLM_BASE_DIR = "D:\CyberLLM\models\Qwen3-1.7B"
$env:CYBERLLM_ADAPTER_DIR = "D:\CyberLLM\models\cyberllm-v8"
$env:CYBERLLM_ADAPTER_SHA256 = "d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1"
$env:CYBERLLM_DEVICE = "cuda"
python run.py
```

Then open http://127.0.0.1:8000 and check readiness (no login
needed for this one):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/cyberllm/readiness
```

Before any analysis it reports `state: not_loaded` — that is the
lazy-load design, not an error. The model loads on the first
analysis, or explicitly via the admin endpoint
`POST /api/cyberllm/readiness/load`. After loading, readiness shows
`ready: true`, `device: cuda`, `quantization: none`, and `load_ms`.

If readiness reports `failed`, read `reason` — it is the real error
(missing file, hash mismatch, OOM). Missing files and load failures
return 503 from `/api/cyberllm/analyze` with that reason and any
deterministic findings, never a fabricated verdict.

## 8. Test it through the existing website

Register or log in, then open **http://127.0.0.1:8000/cyberllm**.
Run each case (kind selector + text), and compare:

| # | Kind | Input | Expected (live v8 behavior) |
|---|---|---|---|
| 1 | log | `Oct 24 07:12:01 web-1 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx` | likely_benign |
| 2 | log | `Oct 24 07:10:22 proxy-9 sshd[310]: Failed password for ruth from 203.0.113.124 port 22 ssh2` | needs_review (single failure is not enough evidence — the `needs_review` banner must show) |
| 3 | log | Three lines from `203.0.113.153`: `GET /wp-login.php`, `GET /.env`, `GET /.git/config` (404s) | likely_threat (deterministic credential-probe findings must appear) |
| 4 | http_request | `GET /fetch?u=http://169.254.169.254/latest/meta-data/ HTTP/1.1` | likely_threat. Note: the frozen eval recorded v8 calling this likely_benign; the deterministic metadata rule must override it transparently (`decision_source: deterministic_override`, model verdict preserved). If you see likely_benign here, the rules layer is broken. |
| 5 | vulnerability | The SMBv1 / CVE-2017-0142 description (Windows Vista SP2 … Server 2016, remote code execution via crafted packets) | Valid JSON needs_review, OR needs_review with `parse_ok: false` if output truncates at 512 tokens (v8 truncated this item in frozen eval). Either is a safe degradation; a confident fabricated verdict is not. |
| 6 | any | Empty text, or text over 8000 chars | 422 validation error, no analysis |
| 7 | — | With the model directory temporarily renamed, submit any analysis | 503 `model_unavailable` with the real reason — proves failures stay honest |

Also run the automated integration tests (these use recorded
generations, not live weights — they verify the endpoint contract,
not the model):

```powershell
python -m pytest tests/test_cyberllm_api.py -q
```

And the scripted live battery (real inference, same six cases):

```powershell
$env:CYBERLLM_BASE_DIR = "D:\CyberLLM\models\Qwen3-1.7B"
$env:CYBERLLM_ADAPTER_DIR = "D:\CyberLLM\models\cyberllm-v8"
$env:CYBERLLM_ADAPTER_SHA256 = "d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1"
python scripts/cyberllm_live_test.py
```

## 9. Fallback: pilot v3 (0.6B, data-v2)

If v8 fails to load or misbehaves, switch to the overall reference
checkpoint. Download the 0.6B base and the `adapter_datav2_*` files
(the same Kaggle dataset, different filenames), rename them the same
way, and launch with:

```powershell
huggingface-cli download Qwen/Qwen3-0.6B `
  --revision c1899de289a04d12100db370d81485cdf75e47ca `
  --local-dir D:\CyberLLM\models\Qwen3-0.6B `
  --local-dir-use-symlinks False
# Kaggle files: adapter_datav2_adapter_config.json, adapter_datav2_adapter_model.safetensors,
# adapter_datav2_chat_template.jinja, adapter_datav2_tokenizer.json, adapter_datav2_tokenizer_config.json
# -> rename to adapter_config.json, adapter_model.safetensors, chat_template.jinja, tokenizer.json, tokenizer_config.json
$env:CYBERLLM_BASE_DIR = "D:\CyberLLM\models\Qwen3-0.6B"
$env:CYBERLLM_ADAPTER_DIR = "D:\CyberLLM\models\cyberllm-v3"
$env:CYBERLLM_ADAPTER_SHA256 = "384d296a4ad5afb7b1523a8f2f3b8e0c07ad7a1ac7faf1b27d36436084bd8967"
```

v3 is lighter (0.6B weights ~1.2 GB, adapter 40,422,168 bytes) and
was verified live as well, but its frozen T5 threat recall is only
0.50 versus v8's perfect score — it is a fallback, not an upgrade.

## 10. Remaining limitations — read before trusting any verdict

- **GPU path not verified by the author.** This environment has no
  GPU, so CUDA loading, the 6 GB fit estimate and the 8-bit fallback
  are reasoned from the model size, not measured. The CPU path and
  the endpoint contract are verified; the GPU numbers on your PC are
  yours to measure. (One correction from re-checking: official
  bitsandbytes does distribute Windows CUDA builds, so the 8-bit
  fallback is installable in principle — it is still untested here.)
- **v8 is not deployable-grade.** Frozen T1 0.9583 (SSRF miss, covered
  by the deterministic rule) and T4 0.80 (CVE truncation). Treat every
  `needs_review` as genuinely uncertain.
- **No MITRE ATT&CK output, by design.** Exact technique-ID accuracy
  was 0.000–0.025; the API has no such field.
- **Log text is data, never instructions.** Commands inside a
  submitted log are never executed; the analyzer only reads them.
- **First load is slow and single-use.** The model loads once per
  server process and stays resident; restarting `run.py` reloads it.
  `run.py` uses `reload=True`, so editing files under `app/` while
  the server runs restarts the process and drops the loaded model.
- **The branch is not on GitHub.** The author did not push anything
  to your repository; the patch file is how these changes reach your
  clone. Pushing the branch yourself is your decision.
