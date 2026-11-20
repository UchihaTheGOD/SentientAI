# CyberLLMv1 Security Lab — architecture

Standalone Windows desktop companion for the existing SentientAI /
CyberLLMv1 integration. It does **not** replace the website, retrain the
model, or build a second model loader. It manages the existing backend
and talks to its existing API.

## Reuse points (existing SentientAI code, never duplicated)

- Backend: `app.main:app` launched with uvicorn from the project root
  (the GUI uses uvicorn directly, not `run.py`, because `run.py` enables
  reload mode, which is wrong for a managed backend process).
- Model: `app/services/cyberllm_loader.py` (env-driven paths, SHA-gated
  load, `auto`/`cpu`/`cuda` device, 8-bit fallback) via the HTTP API:
  `GET /api/cyberllm/readiness`, `POST /api/cyberllm/readiness/load`
  (admin-only), `POST /api/cyberllm/analyze` (auth + rate limit).
  `generate()` calls `ensure_loaded()`, so a first analysis lazily
  loads the model for any authenticated user; explicit load stays
  admin-only and the GUI says so when it gets a 403.
- Auth: the website's own register/login forms + signed double-submit
  CSRF cookie. The GUI client reads the `csrf_token` cookie from its
  own cookie jar (browsers cannot, a requests client can) and sends it
  as `X-CSRF-Token`.
- Model identity (pinned, never guessed):
  base `Qwen/Qwen3-1.7B` @ `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`,
  pilot v8 LoRA adapter, SHA-256
  `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`.

## Layout

```
security_lab/
  config.py      settings + user data dir (no secrets except the local
                 lab credential, documented in config.py)
  backend.py     BackendManager: start/stop/restart, readiness polling,
                 log capture, GPU info (torch / nvidia-smi when present)
  client.py      BackendClient: register/login, CSRF, readiness, analyze,
                 screen; honest errors (503/429/422/401 surfaced, never
                 replaced with a fabricated verdict)
  scanner/       detection-only website assessment (see below)
  lab_server.py  stdlib mock lab on 127.0.0.1 (ephemeral port) for safe
                 scans and classroom demos; fake content is labelled FAKE
  model.py       example cases + analysis result shaping
  evaluation.py  batch eval, confusion matrix, precision/recall/F1,
                 threat recall, FPR, baseline save/compare
  cases.py       case management (New/Investigating/Accepted Risk/Resolved)
  timeline.py    chronological event log (JSONL in the data dir)
  reports.py     HTML / JSON / CSV exporters; PDF via reportlab if present
  gui/           PySide6 UI (offscreen-testable, workers never block UI)
  tests/         pytest suite (run: pytest security_lab/tests)
  packaging/     PyInstaller spec + Windows build script + build guide
```

## Scanner safety contract (enforced in code, not just in the UI)

- Only `GET` requests. No POST/PUT/DELETE, no login attempts, no data
  extraction, no brute force, no DoS, no persistence, no malware.
- Every scan requires `authorized=True` in `ScanConfig` **and**
  allowlist membership for the target host. The GUI additionally
  requires the authorization checkbox. Local-lab targets are loopback
  only and only when local-lab mode is explicitly enabled.
- Before any request, the host is resolved and **every** resolved IP
  is classified. Private, loopback (unless local-lab), link-local
  (including 169.254.169.254 cloud metadata), reserved, multicast and
  unspecified addresses are rejected. Every redirect target is
  re-validated and re-resolved the same way; redirects escaping the
  authorized host are refused.
- Rate limiter (min interval between requests), request cap, timeouts,
  overall deadline, and a stop event checked between requests.
- Markers are inert alphanumeric tokens. Reflected-input and SQL-error
  checks are non-destructive detection only; nothing is executed and
  no data is extracted. SSRF is reported only as a suspected sink
  (a parameter that accepts a URL); the scanner never asks a server
  to fetch an internal address.
- Findings distinguish observation from claim: `status` is
  `suspected`, `verified` (the observation itself is confirmed, e.g. a
  header is absent — not that exploitation is confirmed), or
  `inconclusive`. Missing headers and version strings are never
  presented as confirmed vulnerabilities.
- Evidence is redacted before storage: cookie values, tokens, keys,
  passwords and authorization material are masked. Sensitive-path
  probes store status/length only, never bodies.
- Known limitation (stated in reports): DNS is resolved once per host
  per scan and cached; a hostile DNS change between the check and the
  connect (rebinding) is not fully eliminated. Scans connect directly
  (no proxy) so local/lab targets behave predictably.

## Model testing honesty contract

- The app never invents a verdict. If the backend is down, the model
  is unloaded and fails, or output is unparseable, the UI shows the
  real error/reason and the deterministic findings, if any.
- Confidence is shown only when the model (via the API) returns it.
  The API has no MITRE field by design, so the UI shows MITRE mapping
  only if a future API response actually contains one — otherwise it
  shows "not provided by the model".
- Batch metrics are computed only when ground-truth labels exist;
  otherwise the UI shows "not evaluated". Baselines are saved JSON
  snapshots; regression comparison diffs them, it never rewrites
  history.

## User Management (fourth sidebar section)

Reuses the existing SentientAI auth system, database, roles and
checks. No separate user database, no independent auth, no direct
database writes from the GUI.

Inspection result (2026-10-28): the website admin panel is HTML-only
and has list/detail/delete (non-admin only, self-delete refused,
username confirmation) plus remove-all; role promotion exists only
as `manage.py` CLI. There is **no** role-change, suspend/activate,
admin-create, or JSON admin endpoint. So this module adds one small
admin-only JSON router, `app/api/admin_users.py`, reusing
`require_admin`, the `User` model, `hash_password`,
`_validate_registration`, `audit.record`, and
`password_reset.initiate_reset`:

- `GET /api/admin/users` — counts (total/active/suspended/admins),
  recent accounts, searchable/sortable/paginated safe user objects
  (id, username, email, role, is_active, is_suspended, created_at,
  display_name). Never password hashes, token versions, or sessions.
- `GET /api/admin/users/{id}` — detail + recent account audit events.
- `PATCH /api/admin/users/{id}/role` — role user|admin.
- `PATCH /api/admin/users/{id}/active` — is_active toggle.
- `PATCH /api/admin/users/{id}/suspend` — is_suspended + reason.
- `POST /api/admin/users` — admin creation (validation + duplicate
  checks reused; 409 on duplicate; password never logged).
- `POST /api/admin/users/{id}/password-reset` — initiates the
  existing emailed reset flow (generic, no-enumeration response).
- `GET /api/admin/audit-events` — filtered recent audit events
  (ip hashes omitted).

Backend-enforced guards on every route: `require_admin` (403 for
ordinary users); no self role-change, deactivation, or suspension;
demoting/deactivating/suspending an admin requires at least two
active admins to remain; role/activation/suspension changes bump
`token_version` so sessions die immediately, matching the model's
invalidation policy. Every success and failure is audit-recorded
without secrets. No delete endpoint is added: deactivation is the
reversible control, and deletion stays in the website panel under
its existing username-confirmation guard.

GUI: the User Management page needs an admin session. The lab
account is a normal user, so the page offers an admin sign-in
(username/password kept in memory only, never saved) and documents
the `manage.py` promotion path. All destructive/role actions use
confirmation dialogs. A 403 is shown as "administrative access
denied", never as a simulated success.

## Packaging

The GUI is the PyInstaller product. The multi-gigabyte model weights
are never bundled. The distribution folder contains the GUI exe plus
the SentientAI sources it manages; the backend runs from the user's
own project Python (venv) so torch/CUDA come from their environment.
`run.bat test` (the root suite, `tests/`) is untouched: this package
has its own suite under `security_lab/tests/`.
