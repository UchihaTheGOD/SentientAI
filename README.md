# Sentient — Community Publishing Platform

Sentient is a server-rendered blogging and social platform: a public site anyone
can read, and members can write on, plus a private administration panel for the
people who run it. It is a normal content site — posts, tags, comments, likes,
bookmarks, follows, direct messages, notifications, search — with security built
into the application itself (authentication, CSRF, sanitisation, rate limiting).

There is also a small **internal** content-moderation assistant ("Sentinel").
It is not a public feature: it turns a moderator's own review decisions into a
human-curated dataset and lives entirely behind the admin panel.

## What it does

### Public site (browsable anonymously, actions require an account)
- Homepage with featured / latest / trending posts and popular authors
- Explore, category (`/category/{name}`) and tag (`/tag/{slug}`) listings
- Full-text-ish search over posts and people (`/search`)
- Read posts (`/blog/{slug}`); view counts for non-authors
- Public profiles (`/u/{username}`) with follow / unfollow
- Write, edit, publish, archive and delete **your own** posts (draft by default)
- Likes, bookmarks, threaded-ish comments and comment likes
- A personalised feed of people you follow + recommendations (`/feed`)
- Direct messages between members (`/messages`)
- Notifications and an activity log
- Account settings, change password, and a self-service password reset by email
- Register, log in, log out; about and contact pages

### Private admin panel (`/admin`, administrators only)
- Overview, user management (including a guarded "remove all normal users")
- Content moderation: posts and comments, reports queue, hide/unhide
- Audit log viewer with filters
- The Sentinel review queue: approve / reject / needs-edit candidates and
  export the approved dataset as JSONL
- Read-only settings summary

Every `/admin` route is authorised on the server with `require_admin`; hiding a
link is never the only thing standing between a normal user and admin data.

## Tech stack

- **Python** + **FastAPI** / Starlette, served by **Uvicorn**
- **Jinja2** server-side templates (no SPA; `script-src 'self'`, no inline JS)
- **SQLAlchemy 2.0** over **SQLite** (single-file `app.db`; portable to Postgres)
- **passlib[argon2]** — Argon2id password hashing
- **python-jose** — HS256 JWT session cookie
- **pytest** — full in-process test suite

## Quick start

```bash
python -m venv venv
```

Activate it — `source venv/bin/activate` (Linux/macOS) or
`.\venv\Scripts\Activate.ps1` (Windows PowerShell) — then:

```bash
pip install -r requirements.txt
```

Create your environment file from the template and set a strong secret:

```bash
cp .env.example .env
```

At minimum set `SECRET_KEY` (any long random string in development; **required**
in production — the app refuses to start without it when `ENVIRONMENT=production`).

Create the initial administrator and start the server:

```bash
python manage.py seed-admin
```

```bash
python run.py
```

The site runs at **http://127.0.0.1:8000**. Interactive API docs (route list)
are at `/api/docs`.

### Windows launch shortcuts

On Windows you can use the batch helpers instead of typing the commands:

- `run.bat start` — task-runner shortcut (also `run.bat test`, `run.bat status`,
  `run.bat export`, …); calls the venv's Python directly.
- Double-click **`it old didn't work.bat`** — a fallback launcher to use *if
  `run.bat` didn't work*: it activates the virtualenv and runs `python run.py`
  (after a tongue-in-cheek banner).

Both expect the `venv` to already exist with dependencies installed (see above).

### Initial administrator

`seed-admin` (and `reset-db`) create exactly one administrator:

| Field | Value |
| --- | --- |
| username | `admin` |
| email | `admin@12345` |
| password | `admin@12345` |
| role | `admin` |

These are fixed bootstrap credentials — **change the password after first
sign-in** in any real deployment. (`admin@12345` is not a routable email
address, so the password-reset email cannot actually be delivered to the seed
admin; reset works normally for real user email addresses.)

### Optional: example content

```bash
python manage.py seed-blog
```

creates three published example posts authored by two example users (`maya`,
`devon`).

## Management CLI

```bash
python manage.py <command>
```

| Command | What it does |
| --- | --- |
| `seed-admin` | Create the initial admin (idempotent) |
| `seed-blog` | Create a few example published posts |
| `create-admin --username U --email E --password P` | Create another admin |
| `set-role --username U --role admin\|user` | Change a user's role |
| `list-users` | List accounts |
| `remove-all-users` | Delete every non-admin account and its data |
| `reset-db --yes` | **Destructive**: drop, recreate, seed one admin |

Internal dataset chores (admin/operator use) live in `python -m app.cli`
(`training-status`, `export-training`, `export-eval`, `score-backfill`).

## Testing

```bash
./venv/Scripts/python.exe -m pytest        # Windows
```
```bash
./venv/bin/python -m pytest                 # Linux/macOS
```

The suite runs in-process against a throwaway SQLite database with a fresh state
per test. See [DOCUMENTATION.md](DOCUMENTATION.md) for the full architecture,
data model, security model and known limitations, and
[VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) for an independent verification
pass (fresh test run + live-app checks of the important flows).

## Configuration

All configuration is read from environment variables (loaded from `.env`); see
[`.env.example`](.env.example). Nothing sensitive is hardcoded or stored in the
database. Key variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `SECRET_KEY` | *(dev-only fallback)* | JWT signing key; **required in production** |
| `ENVIRONMENT` | `development` | `production` enables the SECRET_KEY guard |
| `DATABASE_URL` | `sqlite:///./app.db` | Any SQLAlchemy URL |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Session cookie lifetime |
| `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | `30` | Reset link lifetime |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_USE_TLS` | *(blank)* | Outbound email for password reset; blank host = log the link in dev, error in production |

## Security at a glance

- Passwords hashed with **Argon2id** (OWASP parameters); only the hash is stored
- Sessions are HS256 JWTs in an httpOnly cookie, carrying a `token_version` that
  is bumped to invalidate every existing session on logout-all, password change,
  reset, suspend or delete
- **CSRF** protection (signed double-submit token) on every state-changing route
- Output is **sanitised** server-side; a strict Content-Security-Policy is a
  second line of defence (no inline scripts execute)
- Per-action **rate limiting** on sensitive endpoints (login, register, reset,
  messages, comments, …)
- Security headers on every response (`X-Frame-Options: DENY`, `nosniff`, …)
- No passwords, hashes, tokens, secrets or API keys are ever written to logs
