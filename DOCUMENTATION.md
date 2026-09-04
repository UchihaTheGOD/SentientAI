# Sentient — Technical Documentation

This document describes the **current** implementation: what exists in the code
today, how the parts fit together, and where the real limits are. It does not
describe aspirational features. Where a capability is intentionally limited, that
is stated plainly under [Known limitations](#22-known-limitations).

---

## 1. Overview

Sentient is a server-rendered community publishing platform built with FastAPI
and Jinja2 over a SQLite database. It has two audiences:

- **The public site** — a normal blogging / social website. Anyone can read;
  members can write posts, comment, like, bookmark, follow, message each other,
  and manage their own account.
- **The private admin panel** (`/admin`) — for administrators to manage users
  and content, work a reports queue, read the audit log, and curate the internal
  moderation-assistant dataset.

A third component, the **internal Sentinel**, is not user-facing. It converts a
moderator's review decisions into a human-curated training dataset. It performs
no automated action and consults no model (see §15–16).

The public product contains **no** security-testing, exploitation, or
attack-simulation functionality. Application security (auth, CSRF, sanitisation)
is present as protection, not as a feature to interact with.

---

## 2. Architecture and request flow

The app is created by a factory, `create_app()` in `app/main.py`, which returns a
configured `FastAPI` instance (`app = create_app()` at import time).

Middleware is registered so that the outermost layer is added last:

```
request → SecurityHeadersMiddleware → CSRFMiddleware → router/handler → response
```

- **SecurityHeadersMiddleware** wraps everything, so even a CSRF rejection or an
  error page carries security headers (§10).
- **CSRFMiddleware** validates the token on unsafe methods before a handler runs
  and exposes a per-request token for templates (§9).

Routes are grouped into ten routers (§7, §14). Errors are handled centrally:
custom 401/403/404/429 pages and a catch-all 500 that logs the traceback
server-side but never returns exception text to the browser
(`app/services/errors.py`).

Templates are rendered through one shared Jinja environment
(`app/template_env.py`) with a small set of registered globals/filters
(`csrf_input`, `safe_url`, unread badges, etc.).

---

## 3. Technology stack

| Concern | Choice |
| --- | --- |
| Language / framework | Python, FastAPI + Starlette |
| Server | Uvicorn |
| Views | Jinja2 server-side templates |
| ORM / DB | SQLAlchemy 2.0 over SQLite (`app.db`) |
| Password hashing | passlib **Argon2id** |
| Sessions | python-jose JWT (HS256) in an httpOnly cookie |
| Email | stdlib `smtplib` (STARTTLS) |
| Tests | pytest, in-process |

There is no front-end build step, no SPA, and no client-side framework. The
Content-Security-Policy forbids inline scripts (`script-src 'self'`).

---

## 4. Directory layout

```
app/
├── main.py            # factory, middleware, router wiring, error handlers
├── config.py          # Settings from environment variables
├── database.py        # engine, SessionLocal, Base, init_db + migrations
├── template_env.py    # shared Jinja environment + globals/filters
├── cli.py             # internal dataset maintenance CLI (python -m app.cli)
├── api/               # routers (one module per area)
│   ├── health.py auth.py users.py blog.py community.py
│   ├── social.py feed.py messages.py moderation.py admin.py
├── models/            # SQLAlchemy models
│   ├── user.py blog_post.py tag.py social.py message.py
│   ├── moderation.py password_reset.py activity.py audit.py
│   ├── learning.py training_example.py
├── services/          # business logic (no HTTP)
│   ├── auth_service.py csrf.py sanitize.py ratelimit.py errors.py
│   ├── content.py pagination.py tags.py activity_service.py
│   ├── audit.py admin_service.py password_reset.py messaging.py
│   ├── collection.py scoring.py training.py
├── templates/         # Jinja templates (public + admin + partials + errors)
└── static/            # public.css, public.js

manage.py              # user/database admin CLI
run.py                 # uvicorn entrypoint
tests/                 # pytest suite
```

---

## 5. Configuration and environment

All configuration comes from environment variables, loaded from `.env` at import
time (`app/config.py`, `python-dotenv`). Nothing sensitive is hardcoded or stored
in the database.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | `production` enables the SECRET_KEY guard |
| `SECRET_KEY` | dev-only fallback | Signs JWTs; **fatal if missing in production** |
| `DATABASE_URL` | `sqlite:///./app.db` | SQLAlchemy connection URL |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Session cookie lifetime |
| `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | `30` | Reset-link lifetime |
| `SMTP_HOST` | *(blank)* | Blank ⇒ log link in dev / error in prod |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | *(blank)* | SMTP auth (never logged, never in DB) |
| `SMTP_FROM` | *(blank)* | From address (falls back to username) |
| `SMTP_USE_TLS` | `true` | STARTTLS toggle |

**Production fail-safe:** if `ENVIRONMENT=production` and `SECRET_KEY` is unset,
`Settings.__init__` raises at startup rather than mint an insecure default.
In development an insecure default key is used deliberately (and never used in
production).

---

## 6. Data model

All models share the declarative `Base`. `init_db()` imports every model module
(so all tables are registered), runs `create_all`, then applies additive
migrations. The SQLite engine does **not** enable `PRAGMA foreign_keys`, so
cascading deletes are handled explicitly in service code (see `admin_service`,
blog delete).

| Model | Table | Key fields / notes |
| --- | --- | --- |
| `User` | users | `username`, `email`, `password_hash`, `role` (`user`/`admin`), `is_active`, `is_suspended`, `token_version`, `display_name`, `bio`, `avatar_url` |
| `BlogPost` | blog_posts | `slug`, `title`, `author` (string), `user_id`, `category`, `summary`, `content`, `status` (draft/published/archived), `is_hidden`, `views`, `reading_time`, timestamps |
| `Tag` / `post_tags` | tags / assoc | many-to-many tags on posts |
| `PostLike`, `CommentLike` | *_likes | one row per (user, target) |
| `Comment` | comments | `user_id`, `post_id`, `body` |
| `Bookmark` | bookmarks | one row per (user, post) |
| `Follow` | follows | follower → following |
| `Notification` | notifications | `user_id`, `type`, `message`, `target_url`, `is_read` |
| `Message` | messages | `sender_id`, `recipient_id`, `pair_key`, `body`, `is_read` |
| `Report` | reports | reporter, target (post/comment/profile), status |
| `ModerationAction` | moderation_actions | audit trail of moderator decisions |
| `Activity` | activities | per-user activity feed entries |
| `AuditEvent` | audit_events | admin/security-relevant events |
| `PasswordResetToken` | password_reset_tokens | hashed token, expiry, `used_at` |
| `TrainingExample` | training_examples | curated Sentinel dataset + review lifecycle |

---

## 7. Public site routes and features

Grouped by router. Anonymous visitors can read; actions that change state require
sign-in and pass CSRF.

**`users.py` (public shell)** — `/` homepage (featured/latest/trending/authors),
`/about`, `/contact` (GET + POST acknowledge), `/profile` (legacy redirect to the
user's public profile).

**`blog.py`** — `/blog` list, `/blog/{slug}` read (increments views for
non-authors), `/write` + `/blog/{slug}/edit` (owner only), `/blog/{slug}/state`
(publish/draft/archive, owner only), `/blog/{slug}/delete` (owner only, cascades
children), `/category/{category}`, `/tag/{slug}`, `/my/posts`.

**`community.py`** — `/community` recent posts, `/u/{username}` public profile.

**`social.py`** — like / unlike, comment create/delete, comment like, bookmark
toggle, follow / unfollow, `/bookmarks`, `/notifications`.

**`feed.py`** — `/feed` (people you follow + recommendations), `/explore`
(with category filter), `/search` (posts and people).

**`messages.py`** — `/messages` inbox, `/messages/{username}` thread (marks read),
POST to send. Server-rendered, no websockets.

**`auth.py`** — `/register`, `/login`, `/logout`, `/logout-all`, account settings,
`/account/password` (change), `/forgot-password`, `/reset-password` (§13).

**`activity.py` routes** (in users/social area) — `/activity`, `/dashboard`,
`/me`.

The shared post-card partial (`templates/partials/post_card.html`) renders every
post listing across the site, so cards look and behave identically everywhere;
listings that offer a bookmark control pass `show_bookmark`.

---

## 8. Authentication and sessions

- **Hashing:** Argon2id via passlib
  (`schemes=["argon2"], argon2__type="ID", m=19456, t=2, p=1`). Only the hash is
  stored, in `User.password_hash`. Plaintext passwords are never persisted or
  logged.
- **Session token:** a HS256 JWT in an httpOnly cookie (`access_token`). Claims
  include `sub` (user id) and `tv` (token version).
- **`token_version` invalidation:** `get_current_user` compares the token's `tv`
  to the user's current `token_version` and fails closed on mismatch. Bumping
  `token_version` therefore invalidates *all* existing sessions at once. It is
  bumped on: logout-all, password change (the current session is re-issued),
  password reset, account suspend, and account delete.
- **Dependencies:** `get_current_user` (401/403 as appropriate),
  `get_current_user_optional` (None for anonymous), `require_admin` (403 for
  non-admins).

---

## 9. CSRF protection

`app/services/csrf.py` implements a signed **double-submit** token as
middleware. On unsafe methods (POST/PUT/PATCH/DELETE) the submitted token is
verified against the signed cookie; failure returns **403** before any handler
runs. Templates embed the token with the `csrf_input()` global inside every form.
The test client supplies the header automatically; tests that pass `csrf=False`
assert the 403.

---

## 10. Security headers and CSP

`SecurityHeadersMiddleware` sets on every response:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Content-Security-Policy`: `default-src 'self'`; `script-src 'self'`
  (no inline scripts execute); `style-src 'self' 'unsafe-inline'` +
  Google Fonts; `img-src 'self' data: https:`; `frame-ancestors 'none'`;
  `object-src 'none'`; `base-uri 'self'`; `form-action 'self'`.

`'unsafe-inline'` is present only for **style** attributes used throughout the
templates, not for scripts.

---

## 11. Input sanitisation and output safety

`app/services/sanitize.py` provides `strip_formatting`, `clean_text`, and
`render_content` (produces safe HTML from post content). Templates never mark
user content with `|safe`; the escaping default of Jinja plus these helpers means
user input is rendered as text/known-safe markup. Message and comment bodies are
stored as cleaned plain text and rendered escaped. The CSP is a second line of
defence if any markup ever slipped through.

---

## 12. Rate limiting

`app/services/ratelimit.py` is an in-process sliding-window limiter keyed per
client + bucket. Buckets currently enforced (limit / window):

| Bucket | Limit | Window |
| --- | --- | --- |
| login | 12 | 5 min |
| register | 6 | 15 min |
| password (reset + change) | 6 | 15 min |
| comment | 20 | 5 min |
| reaction (likes) | 80 | 1 min |
| post_write | 15 | 10 min |
| report | 10 | 60 min |
| search | 45 | 1 min |
| message | 30 | 5 min |

Exceeding a bucket returns **429** with a `Retry-After`. The store is in-memory
(see limitations for multi-process deployments).

---

## 13. Password reset

Implemented in `app/services/password_reset.py` + `auth.py` routes:

1. **Request** (`/forgot-password`): always responds the same way whether or not
   the email exists — **no account enumeration**.
2. **Token:** a random token is generated; only its hash is stored with an expiry
   (`PASSWORD_RESET_TOKEN_EXPIRE_MINUTES`, default 30). Any prior outstanding
   tokens for the user are retired.
3. **Delivery:** `send_reset_email` sends the link over SMTP (STARTTLS). With no
   `SMTP_HOST`, in production it logs an error and sends nothing; in development
   it logs the link for local testing (see limitations).
4. **Reset** (`/reset-password`): validates token + expiry, sets the new Argon2id
   hash, marks the token `used_at` (**single-use**), retires other tokens, and
   **bumps `token_version`** so existing sessions die. It does **not** auto-login;
   the user signs in with the new password.

---

## 14. Admin panel

`app/api/admin.py`, prefix `/admin`. Every one of its routes declares
`Depends(require_admin)`, so authorisation is enforced server-side per endpoint —
a normal user who guesses a URL gets 403, not a page. Areas:

- **Overview** — counts and recent activity.
- **Users** (`/admin/users`, `/admin/users/{id}`) — inspect, change role,
  suspend/reactivate, delete; **remove-all-normal-users** behind an explicit
  confirmation and a single transaction (admins preserved).
- **Content** — posts (`/admin/posts`) and comments (`/admin/comments`) with
  hide/unhide and delete.
- **Reports** — the moderation queue (`Report` / `ModerationAction`).
- **Logs** (`/admin/logs`) — filterable audit-event viewer.
- **Sentinel review** (`/admin/training`, `/admin/rejected`) — the dataset
  review queue (§15).
- **Settings** (`/admin/settings`) — read-only environment summary (never prints
  secret values).

Admin moderation of reported content is also where the Sentinel producer is
triggered (§15).

---

## 15. Internal Sentinel — moderation to dataset

The Sentinel is an **internal, human-in-the-loop** content-moderation dataset
pipeline. It is not exposed on the public site.

- **Producer** (`app/services/collection.py`): when a moderator acts on reported
  content in the admin flow (`app/api/moderation.py`), that decision can produce
  a `TrainingExample` **candidate** (instruction / input / output derived from
  the moderated content and the decision). This is the only producer today.
- **Review lifecycle** (`TrainingExample` + `app/services/training.py`): every
  candidate starts **pending**. A human moderator can **approve**, **reject**
  (with a reason), or mark **needs-edit**. Only a human-approved row becomes
  eligible for export.
- **Export** (`training.py`, `app/cli.py`): approved rows can be exported as
  JSONL (train / eval splits). Nothing is auto-promoted and no model is trained
  in this codebase.

Public content is never silently harvested into a trainable dataset: a candidate
only appears as a result of a moderator's own review action, and it never counts
until a human approves it.

---

## 16. Advisory scoring

`app/services/scoring.py` assigns each candidate a 0–100 **score** and a triage
**band** (`useful` / `review` / `noisy`). It is:

- **Deterministic and rule-based** — *no model is consulted*, so a given
  candidate's score never drifts between runs. Signals are a coarse moderation
  strength plus cheap, content-agnostic text checks (length, non-printable ratio,
  padding, presence of a concrete recommendation, duplication).
- **Advisory only** — it decides ordering/triage in the review queue. It never
  sets `approved` or `safe_to_train`; the only path to a trainable row is a human
  via `TrainingExample.apply_review`.

`score-backfill` (`python -m app.cli`) can band legacy scored-but-unbanded rows;
it never touches approval state.

---

## 17. Logging and auditing

- **Application logging** never records passwords, password hashes, JWTs, SMTP
  credentials, the `SECRET_KEY`, CSRF secrets, or reset tokens. The one
  development-only exception is the reset-link log described in §13/§22.
- **Audit events** (`AuditEvent` via `app/services/audit.py`) record
  security-relevant admin/account actions for the `/admin/logs` viewer.
- The catch-all error handler logs 5xx tracebacks server-side but returns a
  generic page — no exception text reaches the browser.

---

## 18. Notifications, activity, and messaging

- **Notifications** — created for likes, comments, follows and new messages;
  surfaced with an unread badge and at `/notifications`.
- **Activity** — a per-user activity log (`/activity`).
- **Messaging** — direct messages between members. `pair_key` (order-independent
  `"min:max"` of the two user ids) groups a conversation; `list_conversations`,
  `get_thread`, `mark_thread_read` and `unread_count` back the inbox and thread
  views. Sending a message also creates a notification. Server-rendered; no
  websockets.

---

## 19. Database initialisation, migrations, seeding

- `init_db()` (`app/database.py`) imports all models, `create_all`, then runs
  small additive migrations (`_run_migrations`). It is idempotent and never drops
  data, so it is safe to call on every startup and from each standalone
  entrypoint.
- Seeding is explicit and lives in `manage.py` (§20). The initial admin is
  `admin` / `admin@12345` / `admin@12345` (role admin, active).
- `reset-db --yes` is the only destructive operation and refuses to run without
  the flag.

---

## 20. Management CLIs

**`manage.py`** — accounts and database: `create-admin`, `set-role`,
`list-users`, `seed-admin`, `seed-blog`, `remove-all-users`,
`reset-db --yes`.

**`python -m app.cli`** — internal dataset chores: `training-status`,
`export-training [--out]`, `export-eval [--out]`, `score-backfill [--apply]`.
These are thin wrappers over `training.py` / `scoring.py`; none promotes a
candidate or trains a model.

---

## 21. Testing

The pytest suite runs **in-process** against a throwaway SQLite database. An
autouse fixture cleans the database and resets rate-limit state between tests.
Fixtures provide `db` plus `user` / `other_user` / `admin` and matching test
clients (`client`, `auth_client`, `other_client`, `admin_client`); the test
client injects the CSRF header automatically. Coverage spans auth, sessions,
CSRF, blog lifecycle and ownership/IDOR, social actions, messaging, moderation,
the admin panel (including authorisation), password reset, sanitisation,
scoring, the training pipeline, the CLI, templates, and public-route smoke tests
(including a check that banned security-testing vocabulary never appears on
public pages).

Run:

```bash
./venv/Scripts/python.exe -m pytest        # Windows
./venv/bin/python -m pytest                 # Linux/macOS
```

Current result: **413 passed, 1 skipped** (see the implementation report and
the [verification report](VERIFICATION_REPORT.md) for an independent run).

---

## 22. Known limitations

These are real, deliberate constraints — not TODOs hidden as features.

1. **SQLite / single process.** Storage is a single SQLite file. Suitable for
   development and small single-node deployments; it is not configured for
   distributed replication. `DATABASE_URL` can point at another SQLAlchemy
   backend, but that is untested here.
2. **In-memory rate limiting.** The limiter lives in process memory, so limits
   are per-process and reset on restart. Behind multiple workers each worker has
   its own counters; a shared store (e.g. Redis) would be needed for a global
   limit.
3. **Foreign keys not enforced by the DB.** `PRAGMA foreign_keys` is off;
   cascading deletes are done in application code. Direct DB manipulation outside
   the app could orphan rows.
4. **Dev-only reset-link logging.** When `SMTP_HOST` is unset **and**
   `ENVIRONMENT` is not `production`, the reset link (which contains the one-time
   token) is written to the log so the flow can be tested locally. In production
   the token is never logged. Configure SMTP to disable this path.
5. **Seed admin email is not routable.** The mandated initial admin email
   `admin@12345` is not a real address, so a password-reset email to the seed
   admin cannot be delivered. Reset works normally for real user email
   addresses; change the admin's email/password after first sign-in.
6. **No model inference.** The Sentinel is deterministic rule-based scoring plus
   a human review queue. There is no machine-learning model, no external model
   API, and no automated classification — by design.
7. **In-process tests.** The suite uses FastAPI's in-process `TestClient`; it
   exercises server behaviour and rendered HTML but does not run a browser, so
   client-side behaviour and real network/TLS are out of scope.

---

## 23. Security checklist (summary)

| Control | State |
| --- | --- |
| Passwords hashed (Argon2id), never plaintext, never logged | ✅ |
| Session invalidation via `token_version` | ✅ |
| CSRF on all state-changing routes | ✅ |
| Admin authorisation server-side on every `/admin` route | ✅ |
| Output sanitised; strict CSP; no inline scripts | ✅ |
| Per-action rate limiting | ✅ |
| Security headers on every response | ✅ |
| Secrets from env only; none in DB or logs | ✅ |
| Reset tokens hashed, single-use, expiring; no enumeration; no auto-login | ✅ |
| SECRET_KEY required in production (fail-safe startup) | ✅ |
| Destructive DB reset gated behind `--yes` | ✅ |
| No public security-testing / attack functionality | ✅ |

See [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) for the full report with
test evidence, and [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) for an
independent verification pass (fresh test run + live-app checks).
