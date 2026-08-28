# PROJECT_CHECKPOINT.md — SentientAI

*Last updated: 2026-08-28 — Agent 1 (Foundation + Auth Architecture)*

---

## 1. CURRENT PHASE

**Completed:** Phase 1 (Public/Testing split, RBAC, Session lifecycle)
**Completed:** Agent 1 Foundation (Audit, Checkpoint, Auth Architecture planning, Detection fix)
**Next:** Phase 2 — Community features, User profiles, Dashboard, Bookmarks/Activity

---

## 2. ARCHITECTURE

### Tech Stack
- **Python 3.12** / **FastAPI 0.115.6** / **Uvicorn 0.34.0**
- **SQLAlchemy 2.0.36** (ORM) → **SQLite** (PostgreSQL-ready)
- **Jinja2 3.1.5** (server-side rendering)
- **Passlib 1.7.4** + **bcrypt 4.2.1** (password hashing)
- **python-jose 3.3.0** (JWT)
- **slowapi 0.1.9** (rate limiting — imported but not wired)
- **Vanilla CSS + JS** (no frontend framework)

### Application Structure
```
SentientAI/
├── app/
│   ├── __init__.py               # Package marker
│   ├── config.py                 # Settings from .env (SECRET_KEY, DATABASE_URL, CYBERLLM_*, TEACHER_*)
│   ├── database.py               # SQLAlchemy engine, SessionLocal, Base, init_db(), _run_migrations()
│   ├── main.py                   # create_app() factory, SecurityHeadersMiddleware, router registration, error handlers
│   ├── api/                      # Route handlers (routers)
│   │   ├── __init__.py
│   │   ├── admin.py              # /admin — require_admin — dashboard, events, training CRUD, JSONL export
│   │   ├── attacks.py            # LEGACY — /attacks, /blocked — NOT MOUNTED in main.py
│   │   ├── auth.py               # /login, /register, /logout — JWT cookie auth
│   │   ├── blog.py               # /blog, /blog/{slug} — public, optional user context
│   │   ├── health.py             # /api/health — unauthenticated
│   │   ├── labs.py               # LEGACY — /labs, /api/lab/{id}/submit — NOT MOUNTED in main.py
│   │   ├── testing.py            # /testing/* — require_tester — labs, sessions, events, session-ended, blocked
│   │   └── users.py              # /, /about, /contact, /profile — public+authenticated mix
│   ├── labs/                     # Sandboxed vulnerability simulators
│   │   ├── __init__.py           # Lab registry (register_lab, get_lab, list_labs, init_labs)
│   │   ├── sql_injection.py      # sqli lab — fake in-memory user DB, query string concat
│   │   └── xss.py                # xss_stored + xss_reflected — in-memory guestbook + reflection
│   ├── models/                   # SQLAlchemy models
│   │   ├── __init__.py           # Re-exports: User, SecurityEvent, TrainingExample, BlogPost, LabSession
│   │   ├── blog_post.py          # BlogPost — slug, title, author, category, content, published
│   │   ├── lab_session.py        # LabSession — session_id (uuid hex), user_id, lab_id, status lifecycle, counters
│   │   ├── security_event.py     # SecurityEvent — user_id, lab_id, session_id FK, detection telemetry
│   │   ├── training_example.py   # TrainingExample — instruction/input/output for CyberLLM fine-tuning
│   │   └── user.py               # User — username, email, hashed_password, role (user|tester|admin), is_active
│   ├── services/                 # Business logic
│   │   ├── __init__.py
│   │   ├── analysis.py           # analyze_lab_submission() — ties detection→CyberLLM→DB logging→training gen
│   │   ├── auth_service.py       # hash_password, verify_password, JWT encode/decode, get_current_user deps
│   │   ├── cyberllm_client.py    # CyberLLMClientInterface, MockCyberLLMClient, RealSentinelClient, factory
│   │   ├── detection.py          # Rule-based regex detection engine (SQLi, XSS, Path Traversal, Cmd Injection, Auth Bypass)
│   │   └── training.py           # Training example CRUD — get_pending, approve, reject, export_jsonl
│   ├── static/
│   │   ├── css/style.css         # ~33KB — complete dual-theme stylesheet (public + testing)
│   │   └── js/main.js            # ~1KB — nav toggle, alert dismiss, double-submit prevention
│   └── templates/
│       ├── base.html             # LEGACY base — used by old templates (attacks.html, blocked.html, etc.)
│       ├── base_public.html      # PUBLIC base — nav with user-aware links, footer, body.public-site
│       ├── base_testing.html     # TESTING base — sidebar layout, body.testing-env, model tag
│       ├── blog/                 # Blog templates (extend base_public)
│       ├── testing/              # Testing environment templates (extend base_testing)
│       └── (various pages)       # Auth, profile, error pages, etc.
├── data/
│   └── sentientai.db             # SQLite database (git-ignored)
├── manage.py                     # CLI: create-admin, set-role, list-users, seed-blog
├── requirements.txt              # Python dependencies (12 packages)
├── run.py                        # uvicorn entrypoint (host=127.0.0.1, port=8000, reload=True)
├── test_phase2.py                # 42-test integration suite (Phase 2 session lifecycle)
├── .env / .env.example           # Environment variables
└── .gitignore
```

### Router Registration (in main.py)
```python
# MOUNTED (active):
application.include_router(health.router)    # /api/health
application.include_router(auth.router)      # /login, /register, /logout
application.include_router(users.router)     # /, /about, /contact, /profile
application.include_router(blog.router)      # /blog, /blog/{slug}
application.include_router(testing.router)   # /testing/*
application.include_router(admin.router)     # /admin/*

# NOT MOUNTED (legacy dead code — still exists in repo):
# attacks.py  → /attacks, /attacks/{id}, /blocked
# labs.py     → /labs, /labs/{id}, /api/lab/{id}/submit
```

### Template Hierarchy
```
base_public.html    → Public pages (index, about, blog, contact, login, register, profile, 403, 404)
base_testing.html   → Testing environment (testing/*, admin.html, admin_event.html)
base.html           → LEGACY only — used by unmounted legacy templates (attacks.html, blocked.html, dashboard.html, labs.html)
```

### Template Context Variable Convention
- **Public routes** pass `current_user` → templates alias it: `{% set user = current_user %}`
- **Testing routes** pass `user` directly
- **base_public.html** checks `{% if user %}` for conditional nav
- **base_testing.html** checks `{% if user %}` and `{% if user.is_admin %}`
- This inconsistency means NEW routes should follow the PATTERN of the surface they belong to

---

## 3. EXISTING FEATURES

### Authentication & Authorization
- **Registration:** `/register` — username, email, password + confirm, validates length/uppercase/number
- **Login:** `/login` — JWT in httpOnly cookie, SameSite=lax, 60min expiry
- **Logout:** `/logout` — deletes cookie, redirects to /
- **Role system:** `user` | `tester` | `admin` — stored in User.role column
- **Dependencies:**
  - `get_current_user` — extracts user from JWT cookie, raises 401
  - `get_current_user_optional` — returns None instead of raising
  - `require_tester` — chains get_current_user, checks role ∈ (tester, admin), raises 403
  - `require_admin` — chains get_current_user, checks role == admin, raises 403
- **Error handlers** in main.py:
  - 401 → redirect to /login (browser) or JSON (API)
  - 403 → 403.html page (browser) or JSON (API)
  - 404 → 404.html page
- **Role promotion:** Only via `manage.py set-role` CLI — no self-service role change

### Labs (Sandboxed)
- **SQL Injection (sqli):** Fake in-memory user DB, demonstrates query concat vulnerability
- **Stored XSS (xss_stored):** In-memory guestbook, payload persists across submits (global state, resets on restart)
- **Reflected XSS (xss_reflected):** Simulated parameter reflection
- Lab registry in `app/labs/__init__.py` — register/get/list pattern
- Labs are initialized on startup via `init_labs()`

### Detection Engine
- Regex-based pattern matching in `app/services/detection.py`
- Categories: SQL Injection (high), XSS (medium), Path Traversal (high), Command Injection (critical), Auth Bypass (medium)
- Command injection always checked regardless of lab category
- Critical severity triggers `should_block=True` → session termination
- **FIXED (Agent 1):** Severity overwrite bug — now highest severity always wins via SEVERITY_ORDER

### Session Lifecycle
- `LabSession` model tracks: session_id (UUID hex), user_id, lab_id, status, timestamps, attack/detected/blocked counters
- Status lifecycle: `active` → `completed` | `terminated` | `expired`
- Session created when user opens a lab detail page
- Session terminated on critical payload detection → redirects to `/testing/session-ended/{session_id}`
- Dead-end: resubmit to terminated session → redirected back to session-ended

### CyberLLM Integration
- Abstract `CyberLLMClientInterface` with analyze/classify/explain/generate_training_example
- `MockCyberLLMClient` — deterministic, formats detection results into educational analysis
- `RealSentinelClient` — HTTP adapter for SentinelSmolLM2-360M-V9, falls back to mock on error
- Factory: `get_cyberllm_client()` returns real if CYBERLLM_API_URL set, else mock
- Confidence classification: OBSERVED / INFERRED / UNKNOWN

### Blog
- `BlogPost` model with slug, category filtering, published flag
- Public routes at `/blog` and `/blog/{slug}`
- Categories: Vulnerability Research, Detection Engineering, SOC, Web Security, Incident Response, Security Engineering, Lab Notes
- Seed data via `manage.py seed-blog` (3 placeholder articles)

### Admin Panel
- `/admin` — dashboard with user/attack/training stats
- `/admin/events/{id}` — detailed event inspector
- Training data approval/rejection workflow
- JSONL export of approved training examples

---

## 4. COMPLETED WORK (This Session — Agent 1)

### Detection Engine Fix
- **File:** `app/services/detection.py`
- **What:** Fixed severity overwrite bug where `list({lab_category, "command_injection"})` used non-deterministic set ordering
- **How:** Added `SEVERITY_ORDER` constant, made category list deterministic, inner loop now only overwrites when current match severity ≥ existing
- **Impact:** Critical payloads (command injection) now always correctly trigger blocking regardless of iteration order

---

## 5. FILES CHANGED (This Session)

| File | Change Type | Description |
|---|---|---|
| `app/services/detection.py` | MODIFIED | Added SEVERITY_ORDER, fixed category list determinism, severity-aware overwrite logic |
| `PROJECT_CHECKPOINT.md` | CREATED | This file — cross-session continuity document |

---

## 6. DATABASE CHANGES

### Current Schema
```
users:
  id (PK), username (unique), email (unique), hashed_password, role, is_active, created_at

blog_posts:
  id (PK), slug (unique), title, author, category, summary, content, reading_time, published, created_at, updated_at

security_events:
  id (PK), user_id (FK→users), lab_id, session_id (FK→lab_sessions.session_id, nullable),
  timestamp, method, endpoint, sanitized_payload, detection_result, attack_category,
  severity, success, blocked, explanation, defense_recommendation, raw_analysis_json

lab_sessions:
  id (PK), session_id (unique, uuid hex), user_id (FK→users), lab_id, status, started_at,
  ended_at, termination_reason, attack_count, detected_count, blocked_count, metadata_json

training_examples:
  id (PK), event_id (FK→security_events), instruction, input_text, output_text,
  attack_type, severity, source, approved, reviewed_by (FK→users), created_at
```

### Migration System
- `_run_migrations()` in `database.py` — idempotent ALTER TABLE for adding columns to existing tables
- Currently adds `session_id` to `security_events` if missing

### For Next Agent — Adding New Tables
1. Define model in `app/models/new_model.py`
2. Import in `app/models/__init__.py` and add to `__all__`
3. Import in `database.py init_db()` with `# noqa: F401`
4. If adding columns to existing tables, add idempotent ALTER in `_run_migrations()`

---

## 7. API CHANGES

No API endpoint changes this session. All existing endpoints preserved.

### Current Active Endpoints
```
GET  /api/health                          — unauthenticated
GET  /                                    — public (optional user)
GET  /about                               — public (optional user)
GET  /contact                             — public (optional user)
POST /contact                             — public (optional user)
GET  /blog                                — public (optional user)
GET  /blog/{slug}                         — public (optional user)
GET  /profile                             — authenticated (get_current_user)
GET  /login                               — public
POST /login                               — public
GET  /register                            — public
POST /register                            — public
GET  /logout                              — public
GET  /testing                             — require_tester
GET  /testing/labs                         — require_tester
GET  /testing/labs/{lab_id}               — require_tester
POST /testing/labs/{lab_id}/submit        — require_tester
GET  /testing/sessions                    — require_tester
GET  /testing/sessions/{session_id}       — require_tester
GET  /testing/session-ended/{session_id}  — require_tester
GET  /testing/events                      — require_tester
GET  /testing/events/{event_id}           — require_tester
GET  /testing/blocked                     — require_tester
GET  /admin                               — require_admin
GET  /admin/events/{event_id}             — require_admin
POST /admin/training/{id}/approve         — require_admin
POST /admin/training/{id}/reject          — require_admin
GET  /admin/export                        — require_admin
```

---

## 8. FRONTEND CHANGES

No template changes this session.

---

## 9. TESTS

### Existing Test Suite
- **File:** `test_phase2.py` — 42 integration tests (run against live server)
- **Run:** `python test_phase2.py` (requires server running at http://127.0.0.1:8000)
- **Covers:** Login, overview, labs, sessions, events, session lifecycle, critical payload blocking, RBAC
- **Last result:** 42/42 PASSED

### Running Tests
```powershell
# Start server first:
python run.py

# In another terminal:
python test_phase2.py
```

---

## 10. KNOWN BUGS

1. **bcrypt version warning:** `passlib 1.7.4` can't read `bcrypt 4.2.1` version attribute. Prints traceback on first login but auth still works. Fix: pin `bcrypt==4.0.1` or upgrade passlib.
2. **Deprecated startup hook:** `main.py` uses `@application.on_event("startup")` which is deprecated in FastAPI ≥0.103. Should migrate to `lifespan` context manager. Still works, just emits warning.

---

## 11. KNOWN LIMITATIONS

1. **Legacy dead code:** `app/api/attacks.py` and `app/api/labs.py` exist but are NOT mounted in `main.py`. Their corresponding templates (`attacks.html`, `attack_detail.html`, `attack_result.html`, `blocked.html`, `dashboard.html`, `labs.html`, `lab_detail.html`) use the legacy `base.html`. These should be cleaned up.
2. **Contact form:** `POST /contact` acknowledges but doesn't persist or send email.
3. **Stored XSS global state:** `_stored_comments` in `xss.py` is shared across all users (deliberate for simulation).
4. **Blog is read-only:** No create/edit/delete UI for blog posts. Only seeded via `manage.py seed-blog`.
5. **No pagination:** Events, sessions, blog posts all use simple LIMIT queries.
6. **No rate limiting wired:** `slowapi` is in requirements but not configured in middleware.
7. **Sidebar placeholder links:** `/testing/sentinel`, `/testing/knowledge`, `/testing/training` are in the sidebar but have no routes.

---

## 12. CYBERLLM STATUS

- **Current:** `MockCyberLLMClient` provides deterministic analysis based on detection engine output
- **Real client ready:** `RealSentinelClient` in `cyberllm_client.py` with full HTTP adapter, fallback to mock
- **Activation:** Set `CYBERLLM_API_URL` and `CYBERLLM_API_KEY` in `.env`
- **Model:** SentinelSmolLM2-360M-V9 (inference server expected at API URL)
- **Finding classification:** OBSERVED / INFERRED / UNKNOWN — honest about confidence levels
- **Important:** CyberLLM is INTELLIGENCE/EDUCATION layer. Detection engine is SECURITY ENFORCEMENT layer. Never swap.

---

## 13. TRAINING PIPELINE STATUS

- **Training example generation:** Automatic on every lab submission via `analysis.py`
- **Storage:** `TrainingExample` model with instruction/input/output triples
- **Review:** Admin panel at `/admin` — approve or reject individual examples
- **Export:** `GET /admin/export` → JSONL file download of approved examples
- **Integration:** Designed for CyberLLM/Sentinel fine-tuning pipeline (external)

---

## 14. NEXT TASKS (For Agent 2+)

### Priority 1: User Profile Enhancement
- Add `display_name`, `bio`, `avatar_url`, `website` fields to User model
- Create `/users/{username}` public profile page (new route in `users.py` or new `community.py`)
- Update `/profile` to allow editing these fields

### Priority 2: Dashboard
- Create authenticated `/dashboard` route showing user's activity
- Recent lab submissions, session history, training stats
- Template extends `base_public.html` (it's a user-facing page, not testing console)

### Priority 3: Community / Blog Enhancement
- User-generated blog posts (create/edit/delete)
- Community comments on blog posts
- Voting/bookmarking system

### Priority 4: Admin Expansion
- `/admin/content` — manage blog posts, user content
- `/admin/training-data` — enhanced training pipeline management
- `/admin/models` — CyberLLM model status/configuration
- `/admin/evaluation` — model evaluation metrics

### Priority 5: Placeholder Sidebar Routes
- Wire up `/testing/sentinel`, `/testing/knowledge`, `/testing/training` sidebar links

---

## 15. IMPORTANT DESIGN DECISIONS

### Authentication Pattern
- **JWT in httpOnly cookies** — not in headers. This is the established pattern.
- **No bearer token auth** for browser routes — cookies handle everything.
- **API routes** could use bearer tokens in the future but currently use cookies too.

### Authorization Pattern
- **Dependency injection** via FastAPI `Depends()` — the ONLY place auth is enforced.
- **NEVER** rely on frontend/template checks alone for security.
- Use `get_current_user` for authenticated routes.
- Use `get_current_user_optional` for public routes that show user context.
- Use `require_tester` for `/testing/*`.
- Use `require_admin` for `/admin/*`.
- If adding new authenticated routes: chain off `get_current_user`.

### Template Variable Convention
- **Public routes** (users.py, blog.py): pass `current_user=user` in context
  - Templates do `{% set user = current_user %}` for compatibility with `base_public.html`
- **Testing routes** (testing.py): pass `user=user` directly
- **This inconsistency exists** but is manageable. New public templates should follow the `current_user` pattern.

### Detection Engine Authority
- The regex detection engine (`detection.py`) is the SECURITY ENFORCEMENT layer.
- CyberLLM is the INTELLIGENCE/EDUCATION layer.
- A detection engine `should_block=True` result MUST always terminate/block.
- CyberLLM can add explanation and context but CANNOT override blocking decisions.

### Lab Isolation
- Labs use in-memory fake data — NEVER real database queries with user input.
- No shell commands, no filesystem access, no network operations.
- This MUST be maintained.

---

## 16. INSTRUCTIONS FOR NEXT AGENT

### Before You Start
1. Read this entire checkpoint document.
2. Run `python test_phase2.py` (with server running) to verify everything still passes.
3. Check `git status` and `git diff` to see current state.
4. Read `app/main.py` to understand how routers are registered.
5. Read `app/services/auth_service.py` to understand the auth dependency chain.

### When Adding New Routes
1. Create router file in `app/api/` — follow existing naming pattern.
2. Import and `include_router()` in `app/main.py` `create_app()`.
3. Use appropriate auth dependency (see Section 15).
4. Create templates in the correct directory:
   - Public pages → `app/templates/` (extend `base_public.html`)
   - Testing pages → `app/templates/testing/` (extend `base_testing.html`)
   - Admin pages → `app/templates/` (extend `base_testing.html`)

### When Adding New Models
1. Create model file in `app/models/`.
2. Import in `app/models/__init__.py` and add to `__all__`.
3. Import in `app/database.py` `init_db()` function.
4. If modifying existing tables, add migration in `_run_migrations()`.

### When Modifying Auth
1. Any new role? Add to `VALID_ROLES` in `manage.py` and create corresponding dependency.
2. Any new protected route? Use `Depends(get_current_user)` at minimum.
3. NEVER remove existing auth checks without explicit approval.

### Git Discipline
1. Don't commit `.env` (it's in `.gitignore`).
2. Don't delete or reset existing model files.
3. Preserve all existing test cases.
4. Update this `PROJECT_CHECKPOINT.md` when you finish work.

### What NOT to Do
1. Don't rewrite the detection engine.
2. Don't replace the lab system.
3. Don't change the JWT cookie auth mechanism.
4. Don't remove the admin panel.
5. Don't merge legacy routes back in (attacks.py, labs.py) — they're dead code to be cleaned up.
6. Don't switch from server-side rendering to a SPA framework.

---

## 17. ENVIRONMENT VARIABLES

```
SECRET_KEY              — JWT signing key (REQUIRED, change from default)
DATABASE_URL            — SQLAlchemy URI (default: sqlite:///./data/sentientai.db)
ENVIRONMENT             — development | production (default: development)
CYBERLLM_API_URL        — Sentinel model inference endpoint (optional, uses mock if blank)
CYBERLLM_API_KEY        — Sentinel API key (optional)
SENTINEL_MODEL_NAME     — Model identifier (default: SentinelSmolLM2-360M-V9)
TEACHER_API_KEY         — Teacher reviewer model API key (optional, not wired)
TEACHER_BASE_URL        — Teacher model base URL (optional, not wired)
TEACHER_MODEL           — Teacher model identifier (optional, not wired)
```

---

## 18. HOW TO RUN

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Install deps
pip install -r requirements.txt

# Copy env template
Copy-Item .env.example .env

# Seed data + create admin
python manage.py seed-blog
python manage.py create-admin --username admin --email admin@sentientai.local --password "AdminPassword123!"

# Start server
python run.py
# → http://127.0.0.1:8000

# Run tests (in separate terminal, with server running)
python test_phase2.py
```
