# CyberLLMv1 Security Lab

A standalone Windows desktop app around the existing CyberLLMv1
integration in SentientAI. Double-click the exe; no console,
PowerShell, VS Code, or browser needed.

## The four tools (sidebar)

1. **Website & Model Control Center** — start/stop/restart the
   existing SentientAI backend, health/readiness/GPU/system status,
   model-path configuration, adapter SHA verification, backend logs.
2. **Authorized Website Security Scanner** — detection-only scans
   (14 categories) against a target you are authorized to test.
   Allowlist + authorization confirmation enforced; localhost and
   private/metadata addresses blocked by default (local lab only via
   explicit local-lab mode). Findings are `suspected` / `verified` /
   `inconclusive` — a missing header or version string never counts
   as a confirmed vulnerability. Exports: HTML, JSON, CSV, PDF.
3. **Model Testing & Evaluation** — real inference through the
   backend API (never mocked): single analysis with raw + parsed
   output, example cases, abstention, batch evaluation from
   JSONL/CSV with confusion matrix, precision/recall/F1, threat
   recall, false-positive rate, baseline save/compare. Without
   ground-truth labels the result says "not evaluated" — never a
   fabricated score. Confidence and MITRE mappings appear only when
   the API actually returns them.
4. **User Management** — administrators only, via a new admin-only
   JSON API (`app/api/admin_users.py`). Dashboard counts, searchable
   table, detail view, role change, activate/deactivate,
   suspend/unsuspend, admin creation, existing password-reset flow,
   audit-event review. The backend enforces authorization, the
   last-admin guard, and self-lockout guards; the GUI never touches
   the database directly and never shows hashes or tokens.

Secondary pages: Reports & History, Case Management, Classroom Demo
(+ attack-vs-detection simulator, all events labelled SIMULATED),
Diagnostics (one-click self-test), Settings.

## Run from source (any OS with Python 3.11/3.12)

```
pip install -r security_lab/packaging/requirements-gui.txt
python -m security_lab
```

The GUI needs the SentientAI project (this repo) and its venv for
the backend. Set the project root and backend Python on the Control
Center page if they are not auto-detected.

## Build the Windows exe

See `security_lab/packaging/BUILD_GUIDE.md`. In short:

```
security_lab\packaging\build_windows.bat
```

then double-click `dist\CyberLLMv1-Security-Lab.exe`.

## Model setup

Pilot v8 is the leading development candidate (Qwen3-1.7B base +
LoRA adapter). From the project root:

```
python scripts\setup_cyberllm.py --check
python scripts\setup_cyberllm.py --download-base
python scripts\setup_cyberllm.py --download-adapter
```

Verify the adapter SHA-256 (`d624ed79…5a5b1`, full value in
`CYBERLLM_PORTABLE_SETUP.md` and the Control Center). The GUI
checks artifacts before load; the backend loader refuses a SHA
mismatch. Weights are never bundled into the exe.

## Signing in

- **Model testing / scanner / cases**: sign in with the lab account
  (configure it in Settings — a throwaway local credential, never
  exported) or with your own SentientAI login (kept in memory only).
- **User Management**: sign in as an administrator. The lab account
  is a normal user, so create/promote an admin with
  `manage.py create-admin` / `manage.py set-role` first (details in
  the build guide).

## Safety contract (scanner)

Authorization confirmation + allowlist required; GET-only read-only
checks; inert markers; rate limits, request cap, deadline, stop
button; manual redirect handling that refuses host escapes;
evidence redaction at collection (no credentials, cookies, or tokens
in findings or reports). Full contract:
`security_lab/ARCHITECTURE.md`.

## Known limitations

- The Windows exe is specified and scripted here but must be built
  and double-click-tested on a Windows PC (this environment is
  Linux; the GUI itself is verified offscreen).
- GPU fit on a 6 GB card is an unverified estimate; CPU and 8-bit
  fallbacks exist.
- Real 1.7B inference was not verified in this environment (no
  weights here); the backend honestly reports `not_loaded` and the
  real-model smoke test skips without weights.
- MITRE technique IDs are never displayed unless a future backend
  API returns them.

## Tests

```
python -m pytest security_lab/tests -q
CYBERLLM_REAL_MODEL=1 python -m pytest security_lab/tests/test_real_model_smoke.py -q
```
