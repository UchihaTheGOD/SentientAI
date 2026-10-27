# CyberLLMv1 Security Lab — Build & Run Guide (Windows)

## What the exe is (and is not)

The exe is the **GUI shell**: the Control Center, Scanner, Model
Testing, User Management, Reports, Cases, Demo, Diagnostics, and
Settings pages. It bundles PySide6, requests, and reportlab.

It does **not** bundle:

- the SentientAI backend or its dependencies (FastAPI, SQLAlchemy, …),
- any model weights (the 1.7B base is ~4 GB; the adapter ~82 MB),
- your settings, logs, or reports (those live in your user data dir).

That is deliberate: the backend is your own project, and weights are
too large to freeze into an exe. On first run the GUI asks for (or
auto-detects) the project root and the backend Python; everything
else runs from there.

## Prerequisites (Windows 10/11)

1. Python 3.11 or 3.12 (python.org, "Add python to PATH" checked).
2. The SentientAI project, e.g. `D:\SentientAI`, with its venv:
   ```
   python -m venv venv
   .\venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
   ```
3. Model files (pilot v8, the leading development candidate):
   ```
   python scripts\setup_cyberllm.py --check
   python scripts\setup_cyberllm.py --download-base
   python scripts\setup_cyberllm.py --download-adapter
   ```
   Verify the adapter SHA-256 is
   `d624ed79…5a5b1` (full value in the Control Center and in
   `CYBERLLM_PORTABLE_SETUP.md`). The GUI re-verifies it before load
   and the backend loader refuses a mismatch.
4. A `.env` next to the project (copy `.env.example`; set
   `SECRET_KEY`; keep `CYBERLLM_DEVICE=auto`).

## Building the exe

From the project root:

```
security_lab\packaging\build_windows.bat
```

Output: `dist\CyberLLMv1-Security-Lab.exe`. Double-click it; no
console, PowerShell, VS Code, or browser is needed.

If Windows Defender / SmartScreen flags the unsigned exe, that is
expected for a locally built PyInstaller app: unblock it in the file
properties, or sign it with your own certificate. A one-folder build
(`COLLECT` in the spec instead of a single-file `EXE`) is the usual
fallback if one-file packaging trips antivirus tooling.

## First run checklist

1. Control Center → confirm Project root, Backend Python (the
   project venv's `python.exe`), and API host/port.
2. "Verify adapter SHA + artifacts" → must report OK.
3. "Start backend" → status shows running; "Refresh status" shows
   readiness `not_loaded` until the first analysis.
4. Model Testing → sign in (lab account from Settings, or your own
   login) → run an example case. First inference on CPU is slow
   (minutes); on the GTX 1660 SUPER it uses the CUDA path when
   available, else falls back to CPU or 8-bit (see the setup doc).
5. User Management → sign in as an administrator (see below).

## Administrator access (User Management page)

The lab account is a normal user, so User Management needs a real
admin session. Create or promote one from the project folder:

```
.\venv\Scripts\python.exe manage.py create-admin --username <name> --email <mail> --password <pass>
.\venv\Scripts\python.exe manage.py set-role --username <name> --role admin
```

Then sign in on the User Management page with those credentials
(kept in memory only, never saved). The backend enforces every
guard: no self role-change/deactivation/suspension, and no removing
the last active administrator. Deletion stays in the website admin
panel (username confirmation); the GUI offers reversible
deactivation instead.

## Scanner safety rules (summary)

- A scan needs an allowlisted target **and** the authorization
  checkbox. The engine enforces both independently of the GUI.
- Localhost/private/link-local/cloud-metadata addresses are refused
  by default; loopback targets work only with local-lab mode on.
- GET-only, rate-limited, request-capped, deadline-bounded, with a
  stop button. Redirects that escape the authorized host are refused.
- Markers are inert alphanumeric tokens. A reflected marker, an
  error string, or a version banner is a **suspected** indicator,
  never a confirmed vulnerability. Reports never contain
  credentials, cookies, or tokens (redacted at collection).

## Known limitations (honest list)

- The Windows exe has **not** been built or tested in this Linux
  environment: the spec and build script are provided and the GUI
  code is verified offscreen (see below), but the actual Windows
  build + double-click run must be done on a Windows PC.
- GPU fit on the GTX 1660 SUPER (6 GB) is an **unverified
  estimate** (~4.5 GB peak); measure it on the real machine and use
  the 8-bit or CPU fallback if it does not fit.
- Real 1.7B inference was not verified in this environment (no
  weights here): the backend honestly reports `not_loaded`, and the
  real-model smoke test skips unless weights and
  `CYBERLLM_REAL_MODEL=1` are present.
- The scanner is detection-only: it never proves exploitation, and
  its DNS-rebinding TOCTOU limitation is documented in
  `security_lab/ARCHITECTURE.md`.
- MITRE ATT&CK technique IDs are never shown unless a future backend
  API actually returns them; the current API has no MITRE field.

## Tests (run from the project root)

```
# GUI + scanner + reports + evaluation tests (PySide6 offscreen):
python -m pytest security_lab/tests -q
# Website tests (needs the project venv):
python -m pytest tests -q
# Real-model smoke (only with weights + backend ready):
CYBERLLM_REAL_MODEL=1 python -m pytest security_lab/tests/test_real_model_smoke.py -q
```

## Files changed (this branch)

- `security_lab/` — the whole desktop app (config, backend manager,
  API client, scanner, lab server, model/evaluation/cases/timeline/
  reports, diagnostics, PySide6 GUI, tests, packaging).
- `app/api/admin_users.py` — admin-only JSON user-management API.
- `app/main.py` — registers that router.
- `app/models/audit.py` — seven new `admin.*` audit event types.
- `tests/test_admin_users_api.py` — 19 API tests.
