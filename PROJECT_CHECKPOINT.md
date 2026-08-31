# PROJECT_CHECKPOINT.md — SentientAI

*Last updated: 2026-08-31 — public/testing split, community layer, security hardening, in-process test suite.*
*Branch: `redesign/public-site-and-security-foundation` (not merged, no PR).*

---

## 1. WHAT THIS PROJECT IS

Two separated experiences on one FastAPI app:

- **Public website** — a normal writing/community site: home + discovery feed,
  blog/articles, categories/tags, search, likes/dislikes, threaded comments,
  user profiles, follow/unfollow, user-authored posts, activity log,
  notifications, bookmarks, auth. It reads as an ordinary blogging community.
  It does **not** advertise or expose the testing area's mechanics or
  vocabulary.
- **Authenticated `/testing` area** — the existing sandboxed cybersecurity labs,
  per-session telemetry, detection results, and the CyberLLM analysis/education
  layer. Reachable only by authenticated accounts (`require_lab_access`).

The two surfaces use two stylesheets: `app/static/css/public.css`
(`base_public.html`) and `app/static/css/style.css` (`base.html`,
`base_testing.html`). A public-side template referencing `style.css` class
names is a bug.

---

## 2. STACK

- Python 3.11/3.12 · FastAPI 0.115.6 · Starlette 0.41.3 · Uvicorn 0.34.0
- SQLAlchemy 2.0.36 → SQLite · Jinja2 3.1.5 (server-side, one shared env in
  `app/template_env.py`)
- Passlib 1.7.4 + bcrypt 4.2.1 · python-jose 3.3.0 (JWT in httpOnly cookie)
- Vanilla CSS + JS, no frontend framework
- Run tests with the repo venv: `./venv/Scripts/python.exe -m pytest`

---

## 3. SECURITY MODEL (load-bearing — do not regress)

- **Authorization is server-side only**, via `Depends()` in
  `app/services/auth_service.py`: `get_current_user`,
  `get_current_user_optional`, `require_lab_access` (any active, non-suspended
  account), `require_tester` (role ∈ tester/admin), `require_admin`. Hiding UI
  is never the control.
- **CSRF**: signed double-submit (`app/services/csrf.py`) — cookie
  `csrf_token` + form field or `X-CSRF-Token`. Middleware order
  SecurityHeaders → CSRF → routes.
- **Output sanitization**: escape-first `app/services/sanitize.py`
  (`render_content`, `clean_text`, `strip_formatting`, `safe_url`). No template
  uses `| safe` on user text. All user-generated content — article bodies,
  comments, usernames, profile fields, tags, search params — is untrusted.
- **Visibility** flows through one module, `app/services/content.py`
  (`public_posts_query` = published & not hidden, `visible_comments_query`,
  ownership checks `can_view_post`/`can_edit_post`). IDOR is prevented by
  scoping every lookup to `user_id`, not by filtering after the fetch.
- **Rate limiting**: in-process sliding window (`app/services/rate_limit.py`):
  `limit_login/register/password/comment/reaction/post_write/report/search/
  analysis/feedback`. `limit_feedback` is defined but not yet applied.
- **Detection engine is the enforcement layer** (`app/services/detection.py`):
  `SEVERITY_ORDER`, never-downgrade, `command_injection` always critical,
  `should_block=True` only on critical. **CyberLLM can explain but can NEVER
  override a block.**
- **Labs stay sandboxed** (`app/labs/`): in-memory fake data only, no real DB
  queries with user input, no shell/filesystem/network. `sql_injection.py`'s
  tautology returns five fake `@example.com` rows and nothing real.
- **Model never self-trains on raw input**: candidates are sanitized, scored,
  human-reviewed, and only promoted to `safe_to_train` via
  `TrainingExample.apply_review()`. Rejected examples are retained separately.
  Never overwrite the only working checkpoint.

---

## 4. SHIPPED FEATURES

- **Auth**: register/login/logout, JWT httpOnly cookie, password change
  (`/account/password`), account fields kept private (email never rendered).
- **Public content**: `/` home, `/explore`, `/blog` + `/blog/{slug}`, `/search`,
  `/feed`, `/community`, categories & tags, likes/dislikes, threaded comments
  with replies, reports.
- **User-authored posts**: `/write` create/edit, draft/publish/archive
  lifecycle, `/my/posts`, `/dashboard`, `/bookmarks`.
- **Profiles & social**: `/u/{username}` public profile, `/profile/edit`,
  follow/unfollow, `/me` (→ profile), `/activity` (own log, public + private,
  filterable by type).
- **Notifications**: `/notifications` with unread badge.
- **Pagination**: `app/services/pagination.py` (`Page`, `paginate`,
  `clamp_page`, `clamp_per_page`) + `partials/pagination.html`.
- **Testing area**: `/testing` labs (`sqli`, `xss_stored`, `xss_reflected`),
  per-session lifecycle (active → completed/terminated/expired), critical
  payload terminates + redirects to `/testing/session-ended/{id}`, events
  timeline, all telemetry scoped per user.
- **Learning lifecycle** (`app/models/learning.py`): CANDIDATE / NEEDS_EDIT /
  APPROVED / REJECTED / DUPLICATE, `DatasetVersion`, `ModelCheckpoint`,
  `EvaluationRun`, `AnalysisFeedback`; services in `app/services/training.py`
  (dedup, review, approve/reject, JSONL export with train/eval split).
- **CyberLLM** (`app/services/cyberllm_client.py`): `MockCyberLLMClient`
  (deterministic) + `RealSentinelClient` (HTTP adapter, lazy `import httpx`,
  falls back to mock). **No local model artifacts exist in the repo** — there is
  no checkpoint, tokenizer, training script or dataset committed. CyberLLM is an
  HTTP adapter plus a deterministic mock; nothing here trains or serves a model.
- **Moderation/admin**: `/admin`, `/admin/moderation` (auditable actions),
  training approve/reject, JSONL export.

---

## 5. TESTS

- **In-process pytest suite** in `tests/` (no running server needed; conftest
  builds a throwaway SQLite DB and sets `DATABASE_URL` before `app.database`
  imports). `pytest.ini` sets `testpaths = tests`.
- **Run**: `./venv/Scripts/python.exe -m pytest`
- **Last result: 331 passed, 1 skipped, 415 warnings (~88s).** The 415 warnings
  are Starlette `TemplateResponse(name, {...})` deprecations, deliberately not
  suppressed.
- Modules: auth, public_routes, blog_lifecycle, social, sanitization,
  moderation, training_pipeline, cyberllm, testing_area, lab_sessions,
  templates (compiles every template + checks nav links resolve), activity.
- `requirements-dev.txt` pins `pytest` + `httpx` (TestClient only).
- The old root `test_phase2.py` (live-server script) and `_verify_tmp.py` were
  ported into the suite and deleted.

---

## 6. REMAINING WORK (exactly what is left)

**Batch B — account:** avatar management (route `avatar_url` through `safe_url`
on save, as the website field already is).

**Batch E — admin depth:** admin users/posts/comments/tags/activity/
system-health pages; surface the retained *rejected*-example view.

**Batch F — CyberLLM + learning UI:** quality-scoring service that writes scored
candidates from `analysis.py`; human-review UI; dataset versioning/export UI
with train/eval split + contamination check; wire the placeholder sidebar
routes `/testing/sentinel|knowledge|training`; analysis-feedback UI backed by
`AnalysisFeedback` (apply `limit_feedback`).

**Consistency:** route `explore.html`, `search.html`, `feed.html`,
`profile_public.html` onto `partials/post_card.html` +
`content.post_card_context` (queries were unified; rendering was not).

**Housekeeping:** `RESEARCH_CATEGORIES` is referenced by nothing except the test
asserting its absence from the public form — remove if truly dead. 415
`TemplateResponse` deprecations remain app-wide. `limit_feedback` unapplied.

**Legacy dead code:** `app/api/attacks.py` and `app/api/labs.py` are not mounted;
their `base.html` templates (`attacks.html`, `blocked.html`, `dashboard.html`
legacy, `labs.html`, …) are candidates for removal.

---

## 7. RULES FOR THE NEXT AGENT

- Keep everything on `redesign/public-site-and-security-foundation`. **Do not
  merge into `main`. Do not open the PR.** Commit coherent phases; re-run the
  full suite before each commit.
- Do not rebuild from scratch, do not rewrite the labs, do not turn the public
  site into a security/hacker UI.
- New public template → extend `base_public.html`, use `public.css` classes,
  pass `current_user` in context. New testing/admin template → `base_testing.html`.
- Enforce auth with the `Depends()` chain in §3; never rely on template checks.
- Do not fabricate model capabilities. Do not claim "implemented" without the
  code, or "tests passed" without running them.
- New model → add to `app/models/__init__.py` `__all__`, import in
  `database.py init_db()`, add idempotent migration in `_run_migrations()` if
  altering an existing table.

---

## 8. RUN

```bash
./venv/Scripts/python.exe -m pip install -r requirements.txt -r requirements-dev.txt
./venv/Scripts/python.exe run.py            # http://127.0.0.1:8000
./venv/Scripts/python.exe -m pytest         # full suite
```

Env vars: `SECRET_KEY` (required), `DATABASE_URL` (default
`sqlite:///./data/sentientai.db`), `ENVIRONMENT`, `CYBERLLM_API_URL` /
`CYBERLLM_API_KEY` (blank → mock), `SENTINEL_MODEL_NAME`.
