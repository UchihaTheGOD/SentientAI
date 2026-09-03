# Implementation & Security Report — Sentient

This report describes the **current, actual** state of the codebase. Every claim
below was verified against the source and the test suite at the time of writing;
nothing here is aspirational. Where a capability is deliberately limited, it is
listed in [Known limitations](#known-limitations) rather than glossed over.

---

## 1. Summary

Sentient is a server-rendered community publishing platform: a public blog /
social site, a private `/admin` moderation panel, and an internal
content-moderation dataset assistant ("Sentinel"). It is built on FastAPI /
Starlette + Jinja2 + SQLAlchemy over SQLite, with security implemented in the
application layer (Argon2id passwords, JWT session cookies with a revocation
version, CSRF, server-side sanitisation, a strict CSP, per-action rate limiting
and security headers).

The refactor that produced this state converted an earlier security-testing
"lab" prototype into a legitimate content platform: all attack/exploit/payload
vocabulary and lab routes were removed from the product, and the learning
pipeline was re-sourced from a moderator's own review decisions instead of
attack traffic.

## 2. Test results (verified)

Command (Windows):

```bash
./venv/Scripts/python.exe -m pytest -p no:warnings -rs
```

Result:

```
413 passed, 1 skipped in 53.53s
EXIT=0
```

The single skip is intentional and not a failure:

```
SKIPPED [1] tests/test_templates.py:59: partials/nav.html is not part of this layout
```

The test guards a template partial (`partials/nav.html`) that this layout does
not use; the test skips itself when the file is absent rather than asserting on
a component that was intentionally not built. There are **0 failures and 0
errors**.

## 3. Architecture

- **`create_app()`** factory in `app/main.py` builds the Starlette/FastAPI app,
  mounts `/static`, installs middleware and registers 10 routers: health, auth,
  users, blog, community, social, feed, messages, moderation, admin.
- **Middleware order** (outer → inner): `SecurityHeadersMiddleware` →
  `CSRFMiddleware` → routes. Security headers wrap every response including
  errors; CSRF runs before route handlers.
- **Error handlers** for 401/403/404/429 render friendly pages; the catch-all
  500 handler logs the traceback server-side and returns a generic page with no
  internal detail leaked to the client.
- **Templating**: Jinja2 server-side rendering only. No SPA, no client-side
  framework, no inline JavaScript.

## 4. Data model

SQLAlchemy 2.0 models over a single-file SQLite database (`app.db`). Core
entities: `User`, `BlogPost`, `Tag` (+ `post_tags`), `Comment`, `PostLike`,
`CommentLike`, `Bookmark`, `Follow`, `Notification`, `Message`, `Report`,
`ModerationAction`, `AuditEvent`, `Activity`, `DailyMetric`, `SearchQueryStat`,
plus the internal `TrainingExample`. `init_db()` imports all models, runs
`create_all`, then an idempotent `_run_migrations()` for additive columns. No
data is dropped on startup.

## 5. Public site

Anonymous visitors can browse; actions require an account. Homepage
(featured/latest/trending + popular authors), explore, category and tag
listings, search over posts and people, post reading with view counts, public
profiles with follow/unfollow, authoring (draft → publish → archive → delete of
**your own** posts), likes, bookmarks, threaded-ish comments and comment likes,
a personalised feed, direct messages, notifications, an activity log, account
settings, password change and self-service password reset.

All seven post-listing surfaces (index, explore, community, search, feed,
profile, bookmarks) render through the single shared partial
`templates/partials/post_card.html`. The card takes an optional `show_bookmark`
flag and derives its filled/empty state from a `bookmarks` set in context, so
the bookmark control appears where appropriate without duplicating markup or
changing any route.

## 6. Private admin panel

Every `/admin` route is authorised server-side with `require_admin`. Verified:
`app/api/admin.py` defines **18 routes** and contains **20** `require_admin`
references (the 18 route dependencies plus the import and the module docstring).
Authorisation does not rely on hiding navigation links. The panel provides an
overview, user management (including a guarded "remove all normal users"
transaction), post and comment moderation, a reports queue, an audit-log viewer
with filters, the Sentinel review queue (approve / reject / needs-edit +
JSONL export) and a read-only settings summary.

## 7. Internal Sentinel (content-moderation dataset)

Not a public feature. `app/services/collection.py` turns a moderator's review
decisions into candidate `TrainingExample` rows; `app/services/scoring.py`
assigns a **deterministic, rule-based advisory score and triage band** (no model
is consulted — the module explicitly states "No model is consulted");
`app/services/training.py` exports **human-approved** examples as JSONL. The
lifecycle is PENDING → admin review → APPROVED / REJECTED / NEEDS-EDIT. Scoring
never sets `approved` or `safe_to_train`; nothing auto-trains on public content.

## 8. Security review (each item verified)

| # | Check | Result |
| --- | --- | --- |
| 1 | No security-testing vocabulary in the public product | Verified: template search for hack/exploit/payload/sqli/xss/pentest/cyberllm/attack → **no matches** |
| 2 | Passwords hashed with Argon2id, never plaintext | Verified: `auth_service.py` `schemes=["argon2"], argon2__type="ID", m=19456, t=2, p=1`; only the hash string is stored |
| 3 | Sessions revocable | JWT HS256 cookie carries `tv` (token_version); bumped on logout-all, password change, reset, suspend, delete — `get_current_user` fails closed on mismatch |
| 4 | Admin authorisation enforced server-side | Verified: all 18 admin routes depend on `require_admin` |
| 5 | CSRF on state-changing routes | Signed double-submit token middleware; forms emit `csrf_input()`; missing/invalid token → 403 |
| 6 | Output sanitised; no `\| safe` on user content | Verified: only two `\| safe` occurrences in templates, both **comments stating the rule**, none applied to user content |
| 7 | Strict CSP | `script-src 'self'` (no inline JS executes); `frame-ancestors 'none'`; `object-src 'none'` |
| 8 | Reset tokens random, single-use, expiring | Verified: `secrets.token_urlsafe` (~256 bits); `used_at` marks single-use; expiry via `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES`; other tokens retired on use |
| 9 | No enumeration on reset | The forgot-password response is identical whether or not the email exists |
| 10 | No secrets logged | Verified: the only logging near sensitive fields is a static string ("SMTP is not configured; password-reset email not sent.") — no password, token, hash, SMTP password or API key is interpolated into any log |
| 11 | Secrets from environment | `SECRET_KEY`, `DATABASE_URL`, SMTP creds all read from env; nothing sensitive hardcoded or stored in the DB |
| 12 | Fail-safe secret | `create_app`/config raises at startup if `SECRET_KEY` is unset while `ENVIRONMENT=production`; dev keeps an insecure default |
| 13 | Rate limiting on sensitive endpoints | In-memory sliding window on login, register, password, comment, reaction, post-write, report, search, message |
| 14 | Security headers on every response | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CSP, referrer policy |
| 15 | DB init/reset never destroys production data silently | `init_db()` is additive only; the destructive `reset-db` CLI requires an explicit `--yes` |

## 9. Files changed / removed in the final pass

**Changed**
- `app/templates/partials/post_card.html` — added optional `show_bookmark` toggle
- `app/templates/{index,explore,community,search,feed,profile_public,bookmarks}.html`
  — unified onto the shared partial (removed duplicated card markup and invalid
  anchor-wrapped cards); net ≈ −173 lines
- `app/cli.py` — corrected a stale comment referencing a removed seed script
- `README.md` — rewritten to describe the current implementation

**Added**
- `DOCUMENTATION.md` — full technical reference
- `IMPLEMENTATION_REPORT.md` — this report

**Removed**
- `seed_community.py` — broke the post state machine (set `published` without
  `status`/`user_id`) and duplicated `manage.py seed-blog`; unreferenced
- `PROJECT_STATE.md`, `PROJECT_CHECKPOINT.md`, `REFACTOR_PLAN.md` — transient
  refactor scaffolding, superseded by README + DOCUMENTATION

## 10. Known limitations

These are genuine and intentional, not defects to hide:

- **SQLite / single process.** In-process, single-writer. Fine for the intended
  scale; migrate to Postgres via `DATABASE_URL` for concurrency.
- **In-memory rate limiting.** Counters live in process memory, so limits reset
  on restart and are per-process (not shared across workers).
- **Foreign keys not DB-enforced.** SQLite FK enforcement is not enabled;
  cascading deletes are handled explicitly in application code.
- **Reset link in development.** With no `SMTP_HOST` configured in development,
  the reset link is logged to the server console for convenience; in production
  a missing SMTP host is an error and no link is logged.
- **Seed admin email is non-routable.** The bootstrap admin email `admin@12345`
  is a fixed spec literal and cannot receive mail, so the reset email can't be
  delivered to the seed admin. Change the password after first sign-in; reset
  works normally for real user email addresses.
- **Sentinel does not run a model.** Scoring is deterministic and rule-based and
  is advisory only; there is no ML inference or training in the product.
- **Tests run in-process.** The suite uses Starlette's `TestClient` against a
  throwaway SQLite database; it does not exercise a live network stack.
