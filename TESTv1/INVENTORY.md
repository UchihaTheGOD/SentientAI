# INVENTORY — SentientAI (2026-10-20)

Grounded in files read 2026-10-20. No assumptions.

## Framework & Entry
- **Framework:** FastAPI 0.115.6 + Uvicorn 0.34.0 (reload, reload_dirs=["app"])
- **App factory:** `app/main.py` → `create_app()` → `app` (title "Sentient", version 0.3.0, docs at `/api/docs`)
- **Entrypoint:** `run.py` (`uvicorn.run("app.main:app", host 127.0.0.1:8000, reload=True)`), also `run.bat` / `restart_server.ps1`
- **Config:** `app/config.py` (Settings: SECRET_KEY, DATABASE_URL, ALGORITHM HS256, ACCESS_TOKEN_EXPIRE 60m, PASSWORD_RESET 30m, SMTP_*, ENVIRONMENT) + root `config.py` (SentinelConfig dataclass) + `.env` / `.env.example`
- **Database:** `app/database.py` — SQLAlchemy 2.0.36, SQLite default `./data/sentientai.db` (file 1.46 MB at check), `check_same_thread=False`, `Base.metadata.create_all` + model-driven `_run_migrations` (non-destructive ALTER ADD COLUMN)
- **Middleware order (outer→inner):** SecurityEvents → SecurityHeaders (X-Content-Type-Options nosniff, X-Frame-Options DENY, X-XSS-Protection, Referrer-Policy, Permissions-Policy, CSP) → CSRF (double-submit signed cookie `csrf_token`, FORM_FIELD `csrf_token`, HEADER `x-csrf-token`, SAFE_METHODS GET/HEAD/OPTIONS/TRACE, EXEMPT_PREFIXES `/api/health`) → routes. CSRF + CSP verified live on `/api/health`.
- **Lifespan:** `init_db()` + `sentinel_loader.init_sentinel(background=True)` (fail-open)

## Routers (app/main.py mounts, real routes from app/api/*.py)
- `health` → `GET /api/health`
- `auth` → `GET/POST /register`, `GET/POST /login`, `POST/GET /logout`, `GET/POST /account/password`, `GET/POST /forgot-password`, `GET/POST /reset-password`
- `users` → `GET /`, `GET /about`, `GET/POST /contact`, `GET /profile` (plus `GET /profile/edit` etc via community)
- `blog` → `GET /blog`, `GET /category/{category}`, `GET /tag/{slug}`, `GET/POST /write`, `GET /my/posts`, `GET/POST /blog/{slug}/edit`, `POST /blog/{slug}/state`, `POST /blog/{slug}/delete`, `GET /blog/{slug}`
- `community` → `GET /community`, `GET /users/{username}`, `GET /u/{username}`, `GET /dashboard`, `GET /me`, `GET /activity`, `GET/POST /profile/edit`
- `social` → `POST /blog/{slug}/like`, `POST /comment/{comment_id}/like`, `POST /blog/{slug}/comment`, `POST /blog/{slug}/comment/{comment_id}/delete`, `POST /blog/{slug}/comment/{comment_id}/edit`, `POST /blog/{slug}/bookmark`, `GET /bookmarks`, `POST /users/{username}/follow`, `GET /notifications`, `POST /notifications/read-all`, `POST /notifications/{id}/read`
- `feed` → `GET /explore`, `GET /feed`, `GET /search`
- `messages` → `GET /messages`, `GET /messages/{username}`, `POST /messages/{username}` (rate-limited)
- `moderation` → `GET/POST /report`, `GET /admin/moderation`, `POST /admin/moderation/{report_id}/resolve|dismiss`, `POST .../post/{id}/hide|restore`, `POST .../comment/{id}/hide|restore`, `POST .../user/{id}/suspend|reinstate`
- `admin` → `GET /admin`, `GET /admin/users`, `GET/POST /admin/users/remove-all`, `GET /admin/users/{user_id}`, `POST /admin/users/{user_id}/delete`, `GET /admin/posts`, `POST /admin/posts/{post_id}/delete`, `GET /admin/comments`, `POST /admin/comments/{comment_id}/delete`, `GET /admin/logs`, `GET /admin/settings`, `GET /admin/training`, `GET /admin/training/rejected`, `POST /admin/training/{id}/approve|reject|needs-edit`, `GET /admin/export`
- `sentinel` → `GET /api/sentinel/readiness`, `POST /api/sentinel/readiness/load` (admin), `GET /api/sentinel/prompt/status`, `POST /api/sentinel/prompt/reload` (admin), `POST /api/sentinel/analyze`, `GET /api/sentinel/incidents`, `POST /api/sentinel/incidents/{id}/review`, `POST /api/sentinel/blocks`, `POST /api/sentinel/blocks/{id}/revoke`, `GET /api/sentinel/blocks`, `GET /api/sentinel/training/candidates`, `POST .../training/build|approve|rollback`, `GET /sentinel`, `GET /admin/sentinel/incidents`
- `security` (`app/api/security.py`) → `POST /attact/run`, `GET /assessments`, `GET /assessments/{aid}/export`, `GET /events`, `GET /events/export`, `POST /findings/{fid}/triage`, `POST /demo/run/{case_id}`
- `lab_router` (`security_lab_api.py`) → `POST /run`, `GET /runs`, `GET /runs/{rid}`, `POST /analyze`, `POST /log-analyze`, `DELETE /runs/{rid}`
- `admin_security` → `GET /admin/security` (HTML), `GET /admin/reports/security`, `GET /admin/reports/security/{rid}`, `GET /admin/assessments/{aid}`, `POST /admin/analyze/event`, `POST /admin/analyze/finding`
- `theme` → `GET/POST /theme`, `GET /theme-resolve`
- Static mount → `/static` → `app/static`

## Templates (app/templates)
`403.html, 404.html, 429.html, 500.html, about.html, account_password.html, activity.html, admin.html, admin_comments.html, admin_logs.html, admin_posts.html, admin_rejected.html, admin_remove_all.html, admin_reports_security.html, admin_reports_security_detail.html, admin_security.html, admin_security_detail.html, admin_sentinel.html, admin_settings.html, admin_training.html, admin_users.html, admin_user_detail.html, base_public.html, bookmarks.html, community.html, contact.html, dashboard_user.html, explore.html, feed.html, forgot_password.html, index.html, login.html, messages_inbox.html, messages_thread.html, notifications.html, profile_edit.html, profile_public.html, register.html, report.html, reset_password.html, search.html, sentinel.html, admin/moderation.html, blog/index.html, blog/my_posts.html, blog/post.html, blog/write.html, partials/admin_nav.html, partials/comment.html, partials/pagination.html, partials/post_card.html, partials/theme_selector.html`

## Static Assets (app/static)
- `css/theme.css, css/public.css`
- `js/public.js, js/theme.js (system/light/dark, localStorage+server, no FOUC), js/security_lab_analyze.js, js/security_lab_init.js, js/security_lab_part1.js, js/security_reports.js`

## Models (app/models)
`activity.py, attact_assessment.py, audit.py, blog_post.py, learning.py, message.py, moderation.py, password_reset.py, security_lab.py, sentinel_incident.py, social.py, tag.py, training_example.py, user.py`

## Services (app/services)
`activity_service.py, admin_service.py, attact_runner.py, audit.py, auth_service.py, collection.py, content.py, csrf.py, demo_cases.py, errors.py, incident_service.py, messaging.py, pagination.py, password_reset.py, prompt_service.py, ratelimit.py, sanitize.py, scoring.py, security_events.py, security_lab.py, security_lab_run2.py, security_lab_runner.py, security_lab_runner_a.py, sentinel_bridge.py, sentinel_fusion.py, sentinel_inference.py, sentinel_loader.py, sentinel_moderation.py, sentinel_schema.py, tags.py, training.py, training_pipeline.py` + `middleware/security_events.py`

## Key Files Outside app/
- `local_models/sentinel/` — `config.json` (450 B), `sentinel_tokenizer.json` (473700 B), `sentinel_best_model.pt` (~1.09 GB), `best_autolab_checkpoint.pt` (~1.09 GB)
- `prompts/prompt.txt` (2081 B)
- `data/sentientai.db` (1466368 B, SQLite)
- `ATTACT/`, `evaluation/`, `evaluation_matrix.py`, `sentinel_model.py`, `config.py`, `manage.py`, `run.py`
- Requirements: `fastapi 0.115.6, uvicorn[standard] 0.34.0, sqlalchemy 2.0.36, passlib[argon2] 1.7.4, argon2-cffi, python-jose[cryptography] 3.3.0, python-dotenv 1.0.1, python-multipart 0.0.20, jinja2 3.1.5, aiofiles 24.1.0` + dev `pytest 8.3.4, httpx 0.28.1`

## Tests (tests/, per pytest.ini testpaths=tests addopts=-q)
`conftest.py, test_activity.py, test_admin.py, test_attact_checks.py, test_attact_scope.py, test_auth.py, test_blog_lifecycle.py, test_bridge.py, test_bruteforce_regression.py, test_cli.py, test_csrf.py, test_e2e_review_queue_verification.py, test_evaluation_matrix.py, test_messages.py, test_moderation.py, test_password_reset.py, test_prompt_and_readiness.py, test_prompt_path_resolution.py, test_prompt_propagation_a/b/c.py, test_public_routes.py, test_sanitization.py, test_schema_migration.py, test_scoring.py, test_security_center.py, test_security_lab_phase.py, test_security_reports_phase_a/b.py, test_sentinel_api.py, test_sentinel_contract_a/b.py, test_sentinel_moderation_contract.py, test_sentinel_phase1.py, test_social.py, test_templates.py, test_theme.py, test_training_pipeline.py`

## Git (2026-10-20)
- Branch `main`, up-to-date with origin/main
- Staged: `.gitignore`, `app/api/admin_security.py`, `app/api/security.py` (new), `app/api/security_lab_api.py` (new), `app/main.py`, `app/models/security_lab.py`, `app/static/css/theme.css`, `app/static/js/security_reports.js` (new), `app/templates/admin_reports_security*.html` (new), `app/templates/base_public.html`, `app/templates/partials/admin_nav.html`; Deleted staged: `app/api/security_a.py`, `security_b.py`, `security_lab_api_a.py/b.py`, `theme_dark_extras.css`, `it old didn't work.bat`; New tests: `test_security_reports_phase_a/b.py`; Untracked: `.clinerules/`, `Documentation/…`, `TESTv1/` — preserved, not committed.
