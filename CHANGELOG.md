# Changelog

All notable changes on the `feature/cyberllm-desktop-portable` branch.
Versioning follows semantic versioning. A `-rc.N` suffix marks a
release candidate: feature-complete for that release, but not yet
promoted to stable.

## [1.0.0-rc.1] — 2026-10-28

Release candidate for the desktop-portable release. Verified on Linux
only (see "Not verified" below). Stable `v1.0.0` requires the Windows
battery: exe build + double-click, GPU fit/latency, real 1.7B
inference, Windows test run.

Baseline tests (2026-10-28, Linux VM): website suite 635 passed +
1 skipped (636 total; skip = pre-existing template skip); Security
Lab suite 47 passed + 1 skipped (48 total; skip = real-model smoke,
needs weights + `CYBERLLM_REAL_MODEL=1`). 0 failed in either suite.

### Added
- Native desktop Security Lab GUI (`security_lab/`, PySide6, 9 pages):
  Control Center, Authorized Scanner (14 detection-only categories),
  Model Testing & Evaluation, User Management, Reports & History,
  Cases, Demo/simulator (SIMULATED-labelled), Diagnostics, Settings.
- Admin users JSON API (`app/api/admin_users.py`): list/detail/role/
  activate/suspend/create/password-reset/audit-events, with
  backend-enforced guards (require_admin, no self role-change/
  deactivation/suspension, last-admin guard, token_version session
  invalidation). No delete endpoint; deactivation is the control.
- Portable runtime: `run.bat` (tries `.venv` then `venv`) and `run.sh`
  (Linux/macOS counterpart); project-local model layout
  `cyberLLMv1/{base,adapter}` + `scripts/setup_cyberllm.py --check`
  / `--download-base` / `--download-adapter` with adapter SHA
  verification.
- CyberLLMv1 as the single classifier (`app/services/classifier.py`):
  rules 50% + confident model 50%, SSRF/metadata deterministic
  override, unavailable/unparseable/truncated/mismatch/
  unjustified-threat → `needs_review`; moderation is human-only.
- Versioning: `VERSION`, this changelog, `DEVELOPMENT_LOG.md`,
  annotated tag `v1.0.0-rc.1`, and the rollback procedure below.
- Release reports: `reports/ARCHITECTURE_AUDIT.md`,
  `CLEANUP_REPORT.md`, `CYBERLLM_INTEGRATION_REPORT.md`,
  `TEST_RESULTS.md`, `PORTABILITY_REPORT.md`, `RELEASE_READINESS.md`.

### Changed
- `/api/sentinel/analyze` no longer returns `model_a`/`model_b`/
  `agreement`/`prompt` and no longer accepts `extra_prompt`;
  readiness reports classifier `cyberllm`; prompt status/reload
  routes removed (404).
- Reports list/detail UI migrated to single-CyberLLMv1 presentation
  (API storage-mirror `model_a_*`/`model_b_*` fields kept for
  historical rows).
- Loader diagnostics: artifact validation now runs before the
  missing-torch check, so an incomplete model dir reports its own
  error even in a torch-less venv.
- Promotion/rollback subprocess tests inherit the parent env and
  override only `CYBERLLM_MODEL_ROOT` (fixes a Windows
  WinError-10106-class failure); portability `D:` assertion replaced
  with a project-tree check; test file reads use UTF-8 explicitly
  (fixes Windows CP1252 failures).
- GUI backend venv resolution: `.venv` tried before `venv`
  (was `venv`-only; a frozen exe with a `.venv`-only project
  returned `None`).
- README refreshed for the current branch (removed stale Sentinel
  claims and a duplicated section, corrected routers, stack,
  install, environment, and evaluation status).

### Removed
- Obsolete Sentinel model code: `sentinel_loader`,
  `sentinel_inference`, `sentinel_moderation`, `sentinel_schema`,
  `sentinel_fusion`, `prompt_service`, `sentinel_model.py`, root
  `config.py`, `prompts/prompt.txt`, old-model tests.
- Dead lab-runner duplicates and root scratch scripts; stale
  duplicate README section 12 (dual-model fusion text).

### Fixed
- `restart_server.ps1` stale hard-coded dev-machine path →
  `-ProjectPath` parameter (defaults to the script folder),
  `.venv` then `venv`.
- Torch install step added to `CYBERLLM_PORTABLE_SETUP.md` and
  `security_lab/packaging/BUILD_GUIDE.md` (torch deliberately not in
  `requirements.txt`).
- Stale `requirements-dev.txt` comment referencing deleted
  `cyberllm_client.py` → accurate Starlette TestClient explanation.
- Bootstrap admin password literal removed from the README (the
  default remains in `manage.py` code; change it after first login).

### Security
- Scanner: authorization confirmation + allowlist required; localhost,
  private-network, and cloud-metadata destinations blocked by default;
  GET-only read-only checks; evidence redaction (credentials, cookies,
  tokens never stored); findings distinguish suspected / verified /
  inconclusive — a missing header, error, or version string alone
  never confirms a vulnerability.
- Admin actions enforced on the backend, not merely hidden in the GUI.
- No secrets, weights, local databases, or `.env` contents are
  committed (see `.gitignore`).

### Not verified (Windows / hardware only)
- Windows test run, exe build + double-click, GPU fit/latency on the
  reference GTX 1660 SUPER, real 1.7B inference.
- The user's `unparseable` case diagnosis (awaiting raw output +
  truncated flag + token count).

## Rollback

- In any clone containing the tag: `git checkout v1.0.0-rc.1` to
  inspect or run the release-candidate tree. Return with
  `git checkout feature/cyberllm-desktop-portable`. Stash or commit
  working-tree changes first; never check out over uncommitted files
  you need — back them up first. The two evaluation files
  (`evaluation/latest.json`, `evaluation/moderation_latest.json`)
  are uncommitted working-tree churn, not part of any release.
- On a Windows PC without the tag: apply the patch chain in order —
  desktop-portable patches (`c542cc7..0a5d052`), audit-fixes patch
  (`1fad93b`), milestone-2 patch (`bd19855`), then the release
  patch — or fetch the branch/tag from origin once pushed.
- Code rollback does NOT touch model weights (outside the repo),
  the SQLite database (gitignored), or `.env`. Back those up
  separately before destructive actions (`manage.py reset-db --yes`
  destroys the database).
- Never move the `v1.0.0-rc.1` tag. To supersede it, create a new
  version (e.g. `1.0.0-rc.2`).

## [Unreleased]

- (none yet)
