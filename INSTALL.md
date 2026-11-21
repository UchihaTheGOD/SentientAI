# Install SentientAI + CyberLLM — complete beginner guide

> **Version:** `1.0.0-rc.2` (release candidate). This guide installs the project
> from scratch so anyone can get it running. If you only want the short
> version, the same steps are in the README, section **8. Installation**.
> Follow the steps in order — each one builds on the last.

**Contents**

- [1. What is SentientAI + CyberLLM?](#1-what-is-sentientai--cyberllm)
- [2. Before you start](#2-before-you-start)
- [3. Step 1 — Get the code](#3-step-1--get-the-code)
- [4. Step 2 — Install Python dependencies](#4-step-2--install-python-dependencies)
- [5. Step 3 — Download the model](#5-step-3--download-the-model)
- [6. Step 4 — Configure the app](#6-step-4--configure-the-app)
- [7. Step 5 — Start the server](#7-step-5--start-the-server)
- [8. Step 6 — Create the admin account](#8-step-6--create-the-admin-account)
- [9. Step 7 — Build and check the desktop .exe (Windows, optional)](#9-step-7--build-and-check-the-desktop-exe-windows-optional)
- [10. What each part of the project does](#10-what-each-part-of-the-project-does)
- [11. Check it works](#11-check-it-works)
- [12. If something goes wrong](#12-if-something-goes-wrong)

---

## 1. What is SentientAI + CyberLLM?

**SentientAI** is a self-hosted website you run on your own computer: a
community blogging site (posts, comments, likes, follows, messages) with
login, an admin panel, and a human-reviewed moderation queue. **CyberLLM**
is an AI security assistant built into it: a small language model
(Qwen3-1.7B + a trained LoRA adapter called "pilot v8") that reads a
security log, URL, or vulnerability description and gives a structured
verdict — `likely_benign`, `needs_review`, or `likely_threat` — combined
with deterministic security rules. A native desktop app, the **Security
Lab**, sits on top of the same backend for scanning, model testing, and
user management. Everything runs locally; no external AI service is
needed. Model outputs are provisional and a human reviews consequential
decisions.

## 2. Before you start

| Need | Details |
|---|---|
| **Operating system** | Windows 10/11, Linux, or macOS. Windows is the reference platform (Python 3.12, GTX 1660 SUPER). |
| **Python** | **3.11 or 3.12** (3.12 recommended). Check with `python --version` (Windows) or `python3 --version` (Linux/macOS). |
| **Git** | Needed to download the code. Check with `git --version`. |
| **Disk space** | About **5 GB free**: ~4.2 GB for the AI model + ~500 MB for Python packages and the project. |
| **Memory** | The website alone runs on little RAM. Loading the model needs about **4.5 GB** free RAM (CPU) or about **4.5 GB VRAM** (GPU, float16). |
| **GPU (optional)** | Not required. The site works without the model (rules-only mode). With an NVIDIA GPU (CUDA), the model answers much faster. A 6 GB card (e.g. GTX 1660) fits the model in float16; the exact fit is still unverified on that card, so see the fallback in Step 3 if loading fails. |
| **Internet** | Needed once, to download the code, Python packages, and the model (~4.2 GB). After that the app runs fully offline. |

> **No GPU? No problem.** Skip the CUDA torch install in Step 2 and the
> model still works on CPU — it is just slower (minutes per analysis on a
> weak machine). The website, login, admin panel, and deterministic
> security rules all work with no model at all.

---

## 3. Step 1 — Get the code

Open a terminal (Windows: **PowerShell**; Linux/macOS: your terminal) and run:

```bash
git clone https://github.com/UchihaTheGOD/SentientAI.git
cd SentientAI
```

This downloads the `main` branch. Stay inside this `SentientAI` folder for
every command below.

---

## 4. Step 2 — Install Python dependencies

### 4a. Create a virtual environment

A virtual environment keeps the project's Python packages separate from
the rest of your computer. From inside the `SentientAI` folder:

```bash
python -m venv venv
```

(`.venv` works too — `run.bat` / `run.sh` look for `.venv` first, then
`venv`. If a `venv` folder already exists, reuse it; do not recreate it.)

### 4b. Activate it

**Windows (PowerShell):**

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this once for the current window
only, then try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

Your prompt should now start with `(venv)`. Keep this terminal open —
every command below runs in it.

### 4c. Install the website dependencies

```bash
pip install -r requirements.txt -r requirements-dev.txt
```

This installs FastAPI, Uvicorn, SQLAlchemy, Jinja2, Argon2 password
hashing, and the test tools (pytest, httpx). It does **not** install
`torch` — that is a large, platform-specific install, handled next.

### 4d. Install torch (needed only for the AI model)

**With an NVIDIA GPU (CUDA 12.1 wheel — supports Turing cards like the
GTX 1660):**

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

**CPU only (no GPU):**

```bash
pip install torch
```

> If you do not want the AI model at all, you can skip torch entirely —
> the website starts and works in rules-only mode without it.

### 4e. Install the model runtime libraries

These are needed only to load and run the CyberLLM model:

```bash
pip install transformers==5.16.1 peft==0.20.0 accelerate==1.14.0 huggingface_hub
```

`huggingface_hub` is also what downloads the base model in the next step.
If you ever see a `torchao` import error, run `pip uninstall -y torchao`.

---

## 5. Step 3 — Download the model

The model has **two parts**, and you need both. They go into the
project-local folders `cyberLLMv1/base/` and `cyberLLMv1/adapter/`
(weights are never committed to Git). Total download: **about 4.2 GB**.

| Part | What it is | Size | Source |
|---|---|---|---|
| **Base model** | Qwen/Qwen3-1.7B, pinned revision `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`, Apache-2.0 | ~4.1 GB | Hugging Face (free, no login, no token) |
| **Adapter** | CyberLLM pilot v8 LoRA adapter (rank 16, trained on data-v3.2). **Not** a merged model — it is layered onto the base at load time. | ~82 MB | Public Hugging Face repo `Uchiha80971/CyberLLM-v8` (free, no login) **or** private Kaggle dataset (needs Kaggle login) |

### 5a. Check what is missing (no download, no credentials)

```bash
python scripts/setup_cyberllm.py --check
```

It prints the model folders it expects and lists anything missing.

### 5b. Download the base model (~4.1 GB, resumable)

```bash
python scripts/setup_cyberllm.py --download-base
```

This downloads `Qwen/Qwen3-1.7B` at the exact pinned revision into
`cyberLLMv1/base/`. Downloads resume if interrupted — just re-run the
same command. (Manual equivalent:
`hf download Qwen/Qwen3-1.7B --revision 70d244cc86ccca08cf5af4e1e306ecf908b1ad5e --local-dir cyberLLMv1/base`.
Do not substitute `main` or another revision — weights can change under
a moving branch.)

You should end up with these files in `cyberLLMv1/base/`:

| File | Size |
|---|---|
| `model-00001-of-00002.safetensors` | 3,441,185,608 bytes (~3.4 GB) |
| `model-00002-of-00002.safetensors` | 622,329,984 bytes (~622 MB) |
| `model.safetensors.index.json` | 25,605 bytes |
| `config.json`, `generation_config.json` | small |
| `tokenizer.json`, `tokenizer_config.json`, `vocab.json`, `merges.txt` | ~15 MB |

### 5c. Download the adapter (~82 MB)

**Easiest — public Hugging Face repo (no account, no token):**

```bash
hf download Uchiha80971/CyberLLM-v8 --local-dir cyberLLMv1/adapter
```

The repo hosts the adapter files under their canonical names, so they
land exactly where the loader expects them. You need these files in
`cyberLLMv1/adapter/`: `adapter_config.json`,
`adapter_model.safetensors` (69,782,384 bytes), `chat_template.jinja`,
`tokenizer.json`, `tokenizer_config.json`.

**Alternative — Kaggle CLI (needs a Kaggle account):**

```bash
pip install kaggle
python scripts/setup_cyberllm.py --download-adapter
```

This downloads the six `adapter_17b_datav32_*` files from the private
Kaggle dataset `uchihamadarum/cyber-llm-artifacts` and renames them to
the canonical names above. It needs your Kaggle API token at
`~/.kaggle/kaggle.json` (Linux/macOS) or
`%USERPROFILE%\.kaggle\kaggle.json` (Windows) — create it from your
Kaggle account page → API → Create New Token. Never share or commit
that file. **Do not** pick `adapter_17b_datav2_*` (pilot v4) or
`adapter_datav2_*` (pilot v3, 0.6B) — those are different checkpoints.

> The desktop Security Lab app has the same download built in: its
> Model Management page downloads the base from Hugging Face and the
> adapter from the public `Uchiha80971/CyberLLM-v8` repo by default, with
> progress, resume, and SHA verification (see
> `security_lab/model_download.py`).

### 5d. Verify the download (important)

Run the checker — it verifies the adapter's SHA-256 hash and refuses on
any mismatch:

```bash
python scripts/setup_cyberllm.py --check
```

You should see: `OK: base + adapter present; adapter SHA-256 matches (d624ed79…).`

Or check the hash yourself. It **must** equal
`d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`:

**Windows (PowerShell):**

```powershell
(Get-FileHash cyberLLMv1\adapter\adapter_model.safetensors -Algorithm SHA256).Hash
```

**Linux / macOS:**

```bash
sha256sum cyberLLMv1/adapter/adapter_model.safetensors
```

If the hash does not match, delete `cyberLLMv1/adapter/` and download
again — the loader will refuse to load a mismatched adapter, and that
refusal is by design.

---

## 6. Step 4 — Configure the app

### 6a. Create your `.env` file

```bash
# Windows (PowerShell):
Copy-Item .env.example .env

# Linux / macOS:
cp .env.example .env
```

`.env` holds your private settings. **Never commit it** — it is already
in `.gitignore`.

### 6b. Set a SECRET_KEY

Open `.env` in a text editor and set `SECRET_KEY` to a long random
string. Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy the output into `.env`:

```ini
SECRET_KEY=paste-your-long-random-string-here
ENVIRONMENT=development
```

Why this matters: `SECRET_KEY` signs login sessions. In development the
app falls back to an insecure built-in key if it is unset, but in
production (`ENVIRONMENT=production`) the app **refuses to start**
without a real one.

### 6c. The settings you normally leave alone

These already have working defaults in `.env.example` — change them only
if you know why:

| Setting | Default | What it does |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./app.db` | Where the database lives. SQLite needs no server; the file `app.db` is created in the project folder on first run. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | How long a login session lasts. |
| `CYBERLLM_DEVICE` | `auto` | `auto` = use CUDA if a GPU is found, else CPU. Set `cpu` to force CPU, `cuda` to force GPU. |
| `CYBERLLM_LOAD_IN_8BIT` | (unset) | Set to `1` only if the model does not fit in VRAM (needs `bitsandbytes`; untested on Windows — if it fails, remove the line and use `CYBERLLM_DEVICE=cpu`). |
| `CYBERLLM_MODEL_ROOT` | (unset) | Leave unset — the loader uses `cyberLLMv1/` inside the project. Set it only to point at a model stored elsewhere. |
| `CYBERLLM_BASE_DIR` / `CYBERLLM_ADAPTER_DIR` | (unset) | Legacy per-folder overrides for the base/adapter. Leave unset unless you keep the model outside the project. |
| `SENTIENTAI_HOST` / `SENTIENTAI_PORT` | `127.0.0.1` / `8000` | The address and port the server listens on. |

SMTP settings (`SMTP_HOST`, `SMTP_PORT`, …) are only for password-reset
emails. Leave `SMTP_HOST` blank in development — the reset link is then
printed to the console instead of emailed.

---

## 7. Step 5 — Start the server

From the project folder, in your activated virtual environment:

```bash
python run.py
```

Or use the task runner:

```bash
# Windows:
run.bat start

# Linux / macOS:
./run.sh start
```

Then open **http://127.0.0.1:8000** in your browser. You should see the
SentientAI homepage.

- **Stop the server:** press `Ctrl+C` in the terminal.
- **API docs:** http://127.0.0.1:8000/api/docs
- **Health check:** http://127.0.0.1:8000/api/health
- **Change the port:** set `SENTIENTAI_PORT` in `.env` (for example
  `SENTIENTAI_PORT=8001`), or run with `SENTIENTAI_PORT=8001 python run.py`.

> The database is created automatically on first start: `init_db()`
> creates the tables in `app.db` and adds any missing columns. The
> model is **not** loaded at startup — it loads lazily on the first
> analysis, so the site starts and works even without the model.

---

## 8. Step 6 — Create the admin account

The first admin is created from the command line. **There is no default
password** — a fixed password shipped in a public repo would be a
publicly known admin login, so the command generates a fresh random one
and prints it exactly once.

In a **second** terminal (keep the server running in the first), from
the project folder with the venv activated:

```bash
python manage.py seed-admin
```

You will see something like:

```text
[OK] Initial admin created: admin (admin@12345)
[IMPORTANT] Generated admin password (shown once — save it now):
    <a random 22-character password>
```

**Save that password now** — there is no other copy. The admin username
is `admin` and the email is `admin@12345`.

Prefer to choose your own password? Use:

```bash
python manage.py seed-admin --password "YourStrongPasswordHere"
```

Other useful admin commands (all from the project folder):

| Command | What it does |
|---|---|
| `python manage.py seed-admin [--password ...]` | Create the first admin. Safe to re-run — if `admin` already exists it just says `[SKIP]` and changes nothing. |
| `python manage.py create-admin --username X --email Y --password Z` | Create another admin. |
| `python manage.py set-role --username X --role admin` | Make an existing user an admin (or `--role user` to demote). |
| `python manage.py list-users` | List every user with role and status. |
| `python manage.py seed-blog` | Add 3 example blog posts by 2 example authors. |
| `python manage.py reset-db --yes [--password ...]` | **Destructive:** deletes all data, recreates the database, and seeds exactly one admin. Only for starting over. |

### Log in

1. Open **http://127.0.0.1:8000/login** and sign in as `admin` with the
   password from `seed-admin` (or your `--password`).
2. The **admin panel** is at **http://127.0.0.1:8000/admin** — user
   management, the moderation queue, the training review queue, and
   the audit log live there.
3. Regular users can register themselves at
   http://127.0.0.1:8000/register.
4. **Change the admin password right after first login** (profile /
   password change on the site) — especially if you used the generated
   one.

---

## 9. Step 7 — Build and check the desktop .exe (Windows, optional)

The desktop Security Lab is a native Windows GUI app (PySide6) that talks
HTTP to the backend at http://127.0.0.1:8000. **It is not the website** —
the website runs in a browser; the exe is the desktop app. It does **not**
bundle the backend or any model weights; those stay on the machine.

> **Honest status:** the exe build + double-click run has **not** been done
> on a Windows PC yet. The steps below come from the build script
> (`security_lab/packaging/build_windows.bat`), the PyInstaller spec, and
> `security_lab/packaging/BUILD_GUIDE.md`, and every feature listed was
> confirmed in the GUI code. This Linux environment cannot build or run a
> Windows GUI exe, so the real build and visual check are a Windows-PC
> step.

### 9a. Compile it (Windows 10/11)

Do Steps 1–6 first. Then, from the project root:

```bat
security_lab\packaging\build_windows.bat
```

The script creates a build venv in `%TEMP%\seclab-build-venv`, installs
PySide6 + `requests` + `reportlab` + PyInstaller, and runs PyInstaller on
`security_lab\packaging\security-lab.spec`. It takes a few minutes.
Output: `dist\CyberLLMv1-Security-Lab.exe` — double-click it, no console
or browser needed. If SmartScreen flags the unsigned exe, unblock it in
the file properties (expected for a locally built PyInstaller app).

### 9b. Set it up (first run)

1. On first run it asks for (or auto-detects) the **project root** and
   the **backend Python** (the project venv's `python.exe`).
2. In the **Control Center**, confirm: Project root, Backend Python, API
   host `127.0.0.1`, API port `8000`.
3. Click **"Verify adapter SHA + artifacts"** — it must report OK.
4. Click **"Start backend"** — status shows running; **"Refresh
   status"** shows readiness `not_loaded` until the first analysis.
5. User Management needs a real admin — create one from the project
   folder (`manage.py create-admin ...` then `manage.py set-role
   --username <name> --role admin`) and sign in on that page.

### 9c. Check it works (feature checklist)

Every item below was confirmed in the code — if one is missing, the build
is wrong, not the guide.

- [ ] **Control Center** opens with Start/Stop/Restart backend,
      Refresh status, readiness, and the project/Python/host/port
      fields.
- [ ] **Tunnel Manager** (Control Center): Provider dropdown shows all
      four — **cloudflared, ngrok, pinggy, zrok**. Pinggy free needs no
      token (60-minute tunnels); Pinggy Pro uses the token field (never
      saved); ngrok needs an authtoken once; zrok needs `zrok enable`
      once; cloudflared quick tunnel needs no account.
- [ ] **Download manager** (Model Testing page): **"Download
      CyberLLM"**, **"Cancel download"**, **"Verify (SHA-256)"** with a
      progress bar (MB, speed, ETA). Base comes from Hugging Face
      (resumable); the adapter from the public repo
      `Uchiha80971/CyberLLM-v8` by default. A SHA mismatch fails the
      check and the loader refuses the adapter; a cancelled download
      resumes.
- [ ] **Prompt Test Lab:** run a prompt against the real model —
      generation is **greedy/deterministic**. History is saved;
      **"Compare selected (2 runs)"** compares two runs; **"Clear
      history"** wipes it.
- [ ] **Model Testing:** example dropdown, **"Run Inference"**,
      **"Run batch evaluation"**.
- [ ] **Scanner:** target + authorization checkbox, allowlist,
      **"Stop scan"** button. Detection-only.
- [ ] **Other pages open:** User Management, Reports & History, Case
      Management, Classroom Demo, Diagnostics, Settings.

### 9d. If the exe does not work

- **SmartScreen blocks it:** unblock in file properties, or rebuild as
  a one-folder build.
- **Cannot connect:** check the Control Center's project root, backend
  Python, host, and port — or start the backend yourself with
  `python run.py` and confirm http://127.0.0.1:8000 loads.
- **Model not loaded:** `python scripts/setup_cyberllm.py --check`, or
  use the Model Testing page's download + verify buttons.
- **Slow first inference:** normal on CPU (minutes). Use CUDA or the
  8-bit / CPU fallback on the 6 GB card.

Full EXE guide: README section **9. Desktop Security Lab .exe
(Windows)**. Full build guide:
`security_lab/packaging/BUILD_GUIDE.md`.

## 10. What each part of the project does

A short map so a new person can find their way around. (The README
sections 4 and 6 have the full version.)

| Part | What it does |
|---|---|
| `run.py` | Starts the website: Uvicorn on `127.0.0.1:8000` with reload on `app/`. Host/port come from `SENTIENTAI_HOST` / `SENTIENTAI_PORT`. |
| `manage.py` | Command-line admin tool: `seed-admin`, `create-admin`, `set-role`, `list-users`, `seed-blog`, `reset-db`. |
| `app/main.py` | Builds the FastAPI app (`create_app()`), wires up middleware (security events → security headers → CSRF) and all routers. |
| `app/api/` | The web routes, one file per area: `auth` (register/login), `blog` (posts/comments), `community`, `social`, `feed`, `messages`, `moderation`, `admin`, `admin_users`, `sentinel`, `cyberllm` (the AI analyze page + API), `security_*`, `lab`, `theme`. |
| `app/services/` | The business logic: `auth_service` (login, Argon2 passwords, JWT), `csrf`, `sanitize`, `ratelimit`, `security_events`, `classifier` (CyberLLM + rules fusion), `security_rules` (deterministic brute-force / port-scan / XSS / SQLi / traversal / SSRF rules), `cyberllm_loader` (finds + verifies + loads the model), `cyberllm_inference` (asks the model, greedy, JSON-validated), `cyberllm_schema` / `cyberllm_evidence` / `cyberllm_rules`, `training` + `collection` (human review queue), `incident_service`, `attact_runner`. |
| `app/models/` | The database tables (SQLAlchemy): `User`, `BlogPost`, `Comment`, `Social`, `Message`, `Moderation`, `TrainingExample`, `SentinelIncident` / `TempBlock`, `SecurityEvent` / `AttactAssessment`, `Audit`, `Activity`, `Learning`. |
| `app/templates/` + `app/static/` | The website pages (Jinja2 templates) and CSS/JS. |
| `app/config.py` | Reads `.env` and exposes settings (`SECRET_KEY`, `DATABASE_URL`, …). Production refuses to start without `SECRET_KEY`. |
| `app/database.py` | Database connection + `init_db()` (creates tables, migrates missing columns). |
| `cyberLLMv1/` | The model files: `base/` (Qwen3-1.7B), `adapter/` (pilot v8 LoRA), `manifest.json` (model id, pinned revision, adapter SHA). |
| `security_lab/` | The desktop Security Lab (PySide6): Control Center (start/stop backend, model status), authorized website scanner, model testing & evaluation, user management, reports, cases, classroom demo, diagnostics, settings. Run from source with `pip install -r security_lab/packaging/requirements-gui.txt` then `python -m security_lab`. Build the Windows exe with `security_lab\packaging\build_windows.bat` → `dist\CyberLLMv1-Security-Lab.exe` (bundles the GUI only — backend, torch, and model files stay on the machine). |
| `ATTACT/` | Authorized assessment toolkit: 12 read-only checks (headers, TLS, info disclosure, …). Requires explicit authorization; localhost/private/metadata targets are blocked by default. |
| `scripts/` | Helper scripts: `setup_cyberllm.py` (model check/download), `cyberllm_live_test.py` (scripted live battery), `prepare_cyberllm_feedback.py` / `promote_cyberllm_candidate.py` (reviewed-feedback pipeline). |
| `evaluation_matrix.py` / `evaluation_moderation.py` | Evaluation harnesses (26-case security matrix, 13-case moderation split). Results go to `evaluation/`. |
| `tests/` + `security_lab/tests/` | The pytest suites. Run with `python -m pytest tests/ -q` and `python -m pytest security_lab/tests/ -q`. |
| `run.bat` / `run.sh` | Task runners: `start`, `test`, `status`, `export`, `export-eval`, `backfill`. |

**How a request flows:** browser → rate limit / auth → router →
service → SQLite database (and, for AI analysis, the CyberLLM loader)
→ Jinja2 page back. Model outputs are JSON-validated; anything
unparseable, truncated, or lacking evidence downgrades to
`needs_review` for a human.

---

## 11. Check it works

Run through this list after installing:

- [ ] **Site loads:** http://127.0.0.1:8000 shows the homepage.
- [ ] **Model files present:** `python scripts/setup_cyberllm.py --check`
      prints `OK: base + adapter present; adapter SHA-256 matches (d624ed79…).`
- [ ] **Admin login works:** sign in at `/login` as `admin`, open `/admin`.
- [ ] **Readiness:** open http://127.0.0.1:8000/api/cyberllm/readiness
      (no login needed). Before any analysis it says `state: not_loaded`
      — that is the lazy-load design, not an error. After loading it
      reports `ready: true` with the device and load time.
- [ ] **One analysis:** log in, open http://127.0.0.1:8000/cyberllm,
      pick kind `log`, paste a log line (for example a single
      `Failed password for root from 203.0.113.124 port 22 ssh2` line),
      and submit. A single failed login should come back
      `needs_review` — one line is not enough evidence for a verdict,
      and that honest uncertainty is the system working correctly.
- [ ] **Tests pass (optional):** `python -m pytest tests/ -q`
      (website suite) and `python -m pytest security_lab/tests/ -q`
      (lab suite). Baseline on this branch: website 666 passed +
      1 skipped; lab 100 passed (non-GUI).

## 12. If something goes wrong

- **PowerShell blocks venv activation:** run
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`
  in that PowerShell window, then activate again.
- **"No module named app" / import errors:** you are not in the
  project folder, or the venv is not activated. `cd` into `SentientAI`
  and activate the venv first.
- **Missing packages:** re-run
  `pip install -r requirements.txt -r requirements-dev.txt` in the
  activated venv.
- **App will not start in production:** set a real `SECRET_KEY` in
  `.env` — production refuses to start without one.
- **Database error (`no such column`):** restart the app (migrations
  run at startup); if an old database still fails, start over with
  `python manage.py reset-db --yes` (destroys all data).
- **Model not ready / 503 `model_unavailable`:** check
  `cyberLLMv1/base/` and `cyberLLMv1/adapter/` exist, re-run
  `python scripts/setup_cyberllm.py --check`, and confirm `torch` /
  `transformers` / `peft` are installed. The site still works
  rules-only without the model — the analyze endpoint honestly returns
  503 instead of a fabricated verdict.
- **CUDA out of memory:** try `CYBERLLM_LOAD_IN_8BIT=1` in `.env`
  (needs `pip install bitsandbytes`; untested on Windows), or fall back
  to `CYBERLLM_DEVICE=cpu`.
- **Forgot the generated admin password:** if no other admin exists,
  `seed-admin` will not reset it (it skips when `admin` exists). Use
  `python manage.py reset-db --yes` to start over, or create a second
  admin first and use it to reset the first one.

Full troubleshooting list: README section **18. Troubleshooting**.
Full Windows setup (GPU detail, live test battery, v3 fallback):
`CYBERLLM_WINDOWS_SETUP.md`. Portable setup:
`CYBERLLM_PORTABLE_SETUP.md`. Model card: `cyberLLMv1/MODEL_CARD.md`.
