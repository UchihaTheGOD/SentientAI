# Verification Report — Sentient

**Date:** 2026-09-04
**Branch:** `redesign/public-site-and-security-foundation`
**Purpose:** An independent verification pass over the finished application —
run the real test suite, boot the real app, and exercise the important user and
security flows against the running application. This is **not** a development
phase: no working code was rebuilt, refactored, or changed to make a test pass.

This document complements the other three:

- [README.md](README.md) — how to install and run it.
- [DOCUMENTATION.md](DOCUMENTATION.md) — how it is built (architecture, data
  model, security model, limitations).
- [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) — what was built and why,
  with a per-control security review.
- **This file** — evidence that what is described actually behaves that way,
  gathered from a fresh run.

---

## 1. Method

Verification was done at two levels:

1. **Automated suite** — the committed `pytest` suite, run in-process against a
   throwaway SQLite database. This is the reproducible backbone: anyone who
   clones the repo can re-run it and get the same result.
2. **Live application checks** — the real app object (`create_app()`) was booted
   with its lifespan (`init_db()`) and driven through the important flows over
   Starlette's ASGI `TestClient`, against an **isolated temporary database** so
   the local `app.db` was never touched. This exercised the same middleware
   stack (security headers → CSRF → routes) and error handlers a browser would
   hit. The live harness was an out-of-band script (not committed); the results
   it produced are recorded per category in §5.

Only **safe** verification inputs were used (e.g. an escaped `<script>` string,
a quoted SQL fragment in a search box). No destructive action was taken against
any external system, and no real email was sent.

---

## 2. Repository state at verification

```
On branch redesign/public-site-and-security-foundation
nothing to commit, working tree clean
```

- **Secrets and data are not tracked.** `.gitignore` excludes `venv/`, `.env`,
  and `*.db`; `git ls-files` confirms none of them are in the repository. Only
  `.env.example` (a template with no real values) is committed.
- No application source file was modified during verification.

---

## 3. Automated test suite (fresh run)

Command (Windows):

```bash
./venv/Scripts/python.exe -m pytest -p no:warnings -rs
```

Output:

```
........................................................................ [ 34%]
........................................................................ [ 52%]
........................................................................ [ 69%]
........................................................................ [ 86%]
..................s...................................                   [100%]
=========================== short test summary info ===========================
SKIPPED [1] tests\test_templates.py:59: partials/nav.html is not part of this layout
413 passed, 1 skipped in 35.51s
EXIT=0
```

- **413 passed, 0 failed, 0 errors, 1 skipped. Exit code 0.**
- The single skip is intentional, not a failure: the test guards a template
  partial (`partials/nav.html`) that the current layout does not use, and skips
  itself when the file is absent rather than asserting on a component that was
  deliberately not built.

The suite covers authentication and sessions, CSRF, the blog lifecycle and
ownership/IDOR, social actions, messaging, moderation, the admin panel
(including authorisation), password reset, sanitisation, scoring, the training
pipeline, the CLIs, templates, and public-route smoke tests — including a check
that banned security-testing vocabulary never appears on public pages.

---

## 4. Application boot

```bash
./venv/Scripts/python.exe -c "from app.main import create_app; a=create_app(); print(a.title, a.version, len(a.routes))"
# Sentient 0.3.0 87
```

The factory builds cleanly, the lifespan runs `init_db()` without error, and no
import, template, or static-asset error occurs. Health (`/api/health`) and the
homepage (`/`) return `200`.

---

## 5. Live functional and security verification

Each category below was exercised against the running app. "PASS" means the
observed behaviour matched the documented, secure contract.

| Area | Result | What was observed |
| --- | --- | --- |
| **Public website** | PASS | Homepage, explore, category/tag listings, search, post read, public profiles, register/login/logout, authoring (draft→publish→archive→delete of one's own posts), likes, bookmarks, comments, follow, direct messages, notifications, feed, contact, profile edit, password change — all returned correct statuses and content. The site reads as a normal blog/social platform. |
| **Public cleanliness** | PASS | Zero security-testing vocabulary (hack/exploit/payload/sqli/xss/pentest/attack/etc.) across all templates **and** static assets. Internal terms (dataset/candidate) appear only in admin-only templates. No `/testing`, `/labs`, or `/attacks` routes exist. |
| **Authentication** | PASS | Argon2id hashes stored (`$argon2id$…`), no plaintext anywhere. Session cookie is `HttpOnly` + `SameSite=Lax`. Logout bumps `token_version`, so a replayed post-logout token is rejected (bounced to `/login`). After a password change the old password is refused (400) and the new one works. |
| **Authorisation / IDOR** | PASS | A user cannot edit or delete another user's post (403) or delete another user's comment (403). A normal user is blocked from every admin GET **and** POST (403). Anonymous access to a protected route is denied via `303 → /login?next=…` (see §6). |
| **CSRF** | PASS | A state-changing POST with a missing or wrong token returns 403 before the handler runs; a valid signed double-submit token is accepted. |
| **XSS** | PASS | A `<script>` payload is rendered escaped, never raw; a comment `onerror=` handler is not emitted as live markup; a `javascript:` profile URL is not rendered as an `href`. No `\| safe` is applied to user content; CSP `script-src 'self'` blocks inline execution as defence-in-depth. |
| **SQL injection** | PASS | Injection strings in search, login, and post content produced no 500 and no database error; the `users` table was intact afterwards (SQLAlchemy parameterised queries; usernames additionally regex-restricted). |
| **Admin panel** | PASS | Every panel page loads for an admin and returns 403 for a normal user. Moderation hide/restore/approve/reject work; the JSONL export works; every admin action writes an `AuditEvent`. Settings shows secrets only as configured/not-configured flags, never values. |
| **Password reset / SMTP** | PASS | SMTP config is read from the environment (blank in this run); credentials are never logged. The forgot-password response is identical for a known and an unknown email (no enumeration) and never contains the token. The token is stored only as a SHA-256 hash, carries an expiry, is single-use (reuse and expiry both fail to verify), and the flow ends at the login page (no auto-login). |
| **Internal Sentinel pipeline** | PASS | A moderator hiding reported content produces exactly one `TrainingExample` in state `CANDIDATE` with `safe_to_train=False` and `is_trainable=False`; nothing is trainable before review. Approval flips it to `APPROVED` / `safe_to_train=True` / `is_trainable=True`; rejection keeps the row and it stays non-trainable. The export contains the approved example. No auto-training path exists. |
| **Database** | PASS | Users, audit events, training examples, moderation actions, reports, messages, and notifications all persisted. Every password hash is Argon2id; no plaintext password is stored; reset tokens are stored hashed. Re-running `init_db()` preserved row counts (idempotent `create_all`; the only destructive operation, `manage.py reset-db`, requires `--yes`). |

---

## 6. One finding that looked like a bug but is not

During verification, unauthenticated access to a protected HTML route returned
**`303 → /login?next=<path>`** rather than a raw `401`, and the canonical
profile routes `/me` and `/profile` returned `303` redirects to `/u/{username}`.

These are **correct, intentional behaviours**, not defects:

- The `401` exception handler (`app/services/errors.py`) converts an
  unauthenticated HTML `GET` into a redirect to the login page carrying a `next`
  parameter — a hard denial (the protected page is never served; the login form
  is) with a friendlier UX. API paths (`/api/…`) still receive JSON `401`.
- `/me` and `/profile` are canonical redirects to the signed-in user's public
  profile.

The initial verification harness asserted a bare `401`/`200` for these cases;
those assertions were wrong, and were corrected in the (uncommitted) harness —
**the application was not changed**, because the application was already correct.

---

## 7. Final verdict

| Category | Result |
| --- | --- |
| Application boot | ✅ PASS |
| Public website | ✅ PASS |
| Authentication | ✅ PASS |
| Password reset / SMTP | ✅ PASS |
| CSRF | ✅ PASS |
| XSS | ✅ PASS |
| SQL injection | ✅ PASS |
| IDOR / authorisation | ✅ PASS |
| Admin panel | ✅ PASS |
| Sentinel / internal pipeline | ✅ PASS |
| Training / dataset workflow | ✅ PASS |
| Database | ✅ PASS |
| Public UI cleanliness | ✅ PASS |
| **Automated tests** | **413 passed, 0 failed, 1 skipped — exit 0** |
| **Git status** | **clean** |

- **Issues found:** none. (The one thing that first looked like a failure — the
  `303 → /login` redirect — is correct, secure behaviour; see §6.)
- **Fixes made:** none to application code or to the committed test suite.
- **Final verdict:** ✅ **READY.**

---

## 8. Genuine limitations

These are real, deliberate constraints (the full list is in
[DOCUMENTATION.md §22](DOCUMENTATION.md#22-known-limitations)):

- **SQLite / single process** — foreign keys are not DB-enforced (cascades are
  handled in application code); portable to Postgres via `DATABASE_URL`.
- **In-memory rate limiting** — per-process, resets on restart; a shared store
  (e.g. Redis) would be needed for a global limit behind multiple workers.
- **Seed admin email `admin@12345` is non-routable** — the reset email cannot be
  delivered to the seed admin (it works for real addresses); change it after the
  first sign-in.
- **Dev-only reset-link logging** — when SMTP is unconfigured and the
  environment is not production, the reset link is logged for local testing;
  never in production.
- **No ML model / no inference** — "Sentinel" is deterministic rule-based
  advisory scoring plus a human review queue and JSONL export; it never trains
  or promotes anything automatically.
- **Verification transport** — the live checks were driven in-process over ASGI
  via `TestClient` (the same app object, middleware, and lifespan that
  `run.py`/uvicorn use), not over a live network socket; this is a functional
  and security verification, not a load or network test.
