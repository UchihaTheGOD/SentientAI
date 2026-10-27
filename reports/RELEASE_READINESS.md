# SentientAI Release Readiness

- **Branch:** `feature/cyberllm-desktop-portable`
- **Base:** user-pushed `main` commit `c542cc7`
- **Code commit:** `8a5aee9` (Windows fixes, `run.bat`/`run.sh`,
  A/B UI migration)
- **Reports commit:** the commit that adds these six reports (see
  `git log` on the branch; this file was written before that commit
  was created, so it names the code commit, not itself)
- **Pushed to GitHub:** NO — see §3. Nothing on the remote was changed.

## 1. Acceptance criteria (mission Phase 10 + final standard)

| Criterion | Status | Evidence |
|---|---|---|
| Obsolete AI-model architecture removed or safely retired | DONE | CLEANUP_REPORT manifest; no live importer of any deleted module; full suite green |
| Only CyberLLMv1 performs AI inference | DONE | Single loader + inference service; GUI reuses the backend; no model A/B code path remains |
| Model loaded through a single shared service | DONE | `cyberllm_loader.ensure_loaded()` (global bundle + lock); lazy load for any authenticated user via inference service |
| Log Analyzer no longer exposes obsolete model A/B output | DONE | `/api/sentinel/analyze` returns classification/rules/fusion only; list + detail UI migrated to a single CyberLLMv1 presentation |
| Deterministic rules remain functional | DONE | Rules engine + fusion covered by the suite (635 passed); rules-only screen endpoint intact |
| Website works (auth, admin, incidents, reports, lab) | DONE | Full suite green; backend start/stop smoke; admin API 19 tests green |
| Authentication and user management remain secure | DONE | Backend-enforced guards (require_admin, no self-change, last-admin guard, token_version invalidation, audit); no second user DB; GUI uses authenticated API only |
| Project configurable without machine-specific paths | DONE | Env-based config; project-relative defaults; `run.bat` .venv/venv; `run.sh` added; no `D:` paths in shipped code |
| Tests pass, or remaining failures documented | DONE | Root 635 passed / 0 failed / 1 skipped; GUI suite 40 passed / 0 failed / 1 skipped (honest real-model skip); Qt teardown segfault documented, not hidden |
| Real inference verified or clearly marked blocked | BLOCKED (honest) | Not verified in this VM (no weights, no torch); last real runs 2026-10-24 CPU (see INTEGRATION §6); Windows verification commands in PORTABILITY §6 |
| Reproducible portable release process exists | PARTIAL | Model setup + SHA verification documented; PyInstaller spec + `build_windows.bat` + `BUILD_GUIDE.md` exist; exe itself NOT built/tested (Linux VM) |
| Git changes committed and accurately reported | DONE | Logical commits on the new branch; patch fallback prepared and replay-verified (see §3); evaluation files excluded from all commits/patches |

## 2. Remaining limitations and blockers (in priority order)

1. **Branch not pushed** — GitHub auth from this VM is unavailable
   (HTTPS: no credentials; SSH: proxy resets). The user pushes from
   their authenticated PC using the patch set in §3. Remote content
   verification is pending that push.
2. **Windows exe not built or tested** — requires a Windows PC.
   One-file PyInstaller spec is the default; a one-folder distribution
   is acceptable if it proves more reliable during the Windows build.
3. **Real 1.7B inference not re-verified on this branch** — requires
   weights + torch on the operator's PC (or a GPU environment).
   Pilot v8 is not deployable-grade (frozen T1 0.9583, T4 0.80); pilot
   v3 remains the reference fallback.
4. **GPU fit/latency on GTX 1660 SUPER 6 GB unmeasured** — ~4.5 GB peak
   is an unverified estimate; the 8-bit and CPU fallbacks are the
   documented ladder.
5. **Windows test run not performed** — the three Windows fixes are
   correct by construction and pass on Linux, but `run.bat test` on
   Windows is the confirming step.
6. **Evaluation files left modified-unstaged** (`evaluation/latest.json`,
   `evaluation/moderation_latest.json`) — pre-existing working-tree
   churn, deliberately excluded from commits and patches. Do not commit
   them without reviewing what changed them.
7. **API storage-mirror fields** (`model_a_*` / `model_b_*` in
   `security_lab_api.py`) retained for backward compatibility and
   historical rows; presentation migrated. A future rename is a
   breaking change requiring a migration, not a cleanup.

## 3. Release process (what the operator does next)

1. On an authenticated PC, clone the repo and fetch `main` at `c542cc7`.
2. Create the branch and apply the patch set (in order):
   `git checkout -b feature/cyberllm-desktop-portable c542cc7`
   then `git am` each patch in `sentientai-desktop-portable-patches/`
   (the set is replay-verified: applying it to pristine `c542cc7`
   reproduces this branch's tree exactly; commit hashes will differ,
   content will not).
3. `git push -u origin feature/cyberllm-desktop-portable` and report
   back; the assistant will then verify remote content against the
   local branch.
4. On Windows, follow PORTABILITY §6 (venv, setup check, `run.bat
   start`, `run.bat test`, browser battery), then build the GUI with
   `security_lab\packaging\build_windows.bat` and double-click test it,
   recording GPU fit/latency and the first real inference.
5. Do NOT merge into `main` without explicit approval, and do NOT
   force-push at any point.

## 4. What is ready to use now

- The website on this branch (checkout + venv + model files + `.env`)
  is a complete, single-model, portable SentientAI application.
- The desktop GUI source + build script are complete and
  offscreen-verified; only the Windows exe artifact itself awaits a
  Windows build.
- Every report in `reports/` states what was measured, what was not,
  and what remains — no result in this release is claimed without a
  run behind it.
