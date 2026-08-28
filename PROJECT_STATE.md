# PROJECT_STATE.md — SentientAI

*Last updated: 2026-08-28 (Phase 2 Complete Checkpoint)*

---

## 1. PROJECT OVERVIEW

**SentientAI** is a dual-experience cybersecurity education and research platform designed to provide:
1. **A Public-Facing Website**: A believable, clean, content-first web experience offering security research articles, platform information, and standard user account management without exposing security testing telemetry or internal model dashboards.
2. **A Protected Testing Lab (`/testing`)**: A separate, technical, analyst-focused security research console where authorized users (testers and administrators) interact with isolated vulnerability labs, view deterministic detection telemetry, inspect session event timelines, and review candidate security knowledge.

### Current Architecture
- **Web Layer**: FastAPI application rendering server-side Jinja2 templates for both public and testing experiences, with REST API endpoints for data operations.
- **Security & Sandboxing**: Server-side sandboxed lab simulators running isolated mock data layers with regex-based deterministic detection pipelines.
- **Session Lifecycle**: `LabSession` model tracking each lab run with UUID-based session IDs, event counters, start/end timestamps, and termination reasons.
- **Data & Persistence**: SQLite database (configured for PostgreSQL migration capability via SQLAlchemy ORM) storing users, security events, training examples, blog posts, and lab sessions.
- **AI / Model Layer**: `CyberLLMClientInterface` abstraction backed by `MockCyberLLMClient`, with a fully implemented `RealSentinelClient` HTTP adapter for `SentinelSmolLM2-360M-V9`. Distinguishes OBSERVED / INFERRED / UNKNOWN findings.

### Technologies Currently in Use
- **Python 3.12 / 3.x**
- **FastAPI 0.115.6** & **Starlette** (Routing, middleware, dependency injection)
- **Uvicorn 0.34.0** (ASGI web server)
- **SQLAlchemy 2.0.36** (ORM & database schema management)
- **Passlib & bcrypt 4.2.1** (Password hashing)
- **python-jose 3.3.0** (JWT token encoding & decoding)
- **Jinja2 3.1.5** (HTML templating)
- **Vanilla CSS & JS** (Custom dual-experience theme: public documentation style vs. testing sidebar console)

---

## 2. COMPLETED WORK

### Phase 1 — Public Website / Testing Lab Separation & RBAC
- **Dual Template Hierarchy**: `base_public.html` and `base_testing.html` strictly isolate both surfaces.
- **Public Routes**: `/`, `/about`, `/contact`, `/blog`, `/blog/{slug}`, `/profile`.
- **RBAC**: `require_tester` guards all `/testing/*` routes. `require_admin` guards all `/admin/*` routes. All public signups default to `role="user"`.
- **CLI (`manage.py`)**: `create-admin`, `set-role`, `list-users`, `seed-blog`.
- **Data Models**: `User` (with `role`), `BlogPost`, `SecurityEvent`, `TrainingExample`.

### Phase 2 — Lab Session Architecture & Realistic Target UX

#### Session Lifecycle (`LabSession` Model)
- Created `app/models/lab_session.py` with UUID-based `session_id`, status (`active` / `terminated` / `completed`), start/end timestamps, attack/detected/blocked counters, and `termination_reason`.
- Added `session_id` FK to `SecurityEvent` (nullable for backward compat). Runs idempotent migration on startup via `_run_migrations()` in `app/database.py`.
- Sessions are created automatically when a user visits a lab page (`GET /testing/labs/{lab_id}`).
- Every submission updates the session counters and checks for critical-severity blocks.
- Critical-severity payloads (e.g. Command Injection) terminate the session and redirect to `/testing/session-ended/{session_id}` — a dead-end page that blocks further submissions.

#### New Routes (`app/api/testing.py`)
| Route | Description |
|---|---|
| `GET /testing/sessions` | Paginated list of all user sessions |
| `GET /testing/sessions/{session_id}` | Chronological event timeline for a session |
| `GET /testing/session-ended/{session_id}` | Dead-end termination page (blocks further submissions) |

#### Realistic Isolated Target Application
- `xss_stored` lab now loads `testing/target_xss_stored.html` — a standalone NexusBoard community forum with real-looking posts, comments, sidebar stats, and a vulnerable comment form. Completely separate from the SentientAI styling.
- An **Analyst Observer Bar** is fixed at the bottom of the target page: shows session ID, event count, and links back to Timeline/Events/Console without polluting the target app's UI.
- All other labs load `testing/lab_detail.html` (generic form).

#### Attack Timeline (`testing/session_timeline.html`)
- Chronological event list with colored dot markers: GREEN (session start), ORANGE (detected), RED (blocked), CYAN (active), GREEN (completed).
- Each event shows: timestamp, method, endpoint, attack category badge, severity badge, explanation snippet, and "View Detail" link.

#### Session Ended Dead-End (`testing/session_ended.html`)
- Shows: termination reason, session stats, **Terminating Event** card with attack category, severity, "What Was Detected", and "Defensive Lesson".
- Red warning note that further submissions to this session will redirect here.
- Actions: View Full Timeline, Start New Session, All Events, Overview.

#### Sentinel Adapter Architecture (`app/services/cyberllm_client.py`)
- `CyberLLMClientInterface` — abstract contract.
- `MockCyberLLMClient` — deterministic rule-based mock (unchanged behaviour, always available).
- `RealSentinelClient` — HTTP adapter for `SentinelSmolLM2-360M-V9` inference server. Falls back transparently to mock on any connection failure. Never fabricates telemetry.
- `SentinelFinding` dataclass with `AnalysisConfidence` enum: `OBSERVED`, `INFERRED`, `UNKNOWN`.
- `get_cyberllm_client()` factory: uses `RealSentinelClient` when `CYBERLLM_API_URL` is set, otherwise `MockCyberLLMClient`.

#### Detection Engine Update (`app/services/detection.py`)
- Command Injection is now always checked regardless of lab category (critical severity, must block everywhere).
- All other categories still scoped to the lab's declared category.

#### CSS Additions (`app/static/css/style.css`)
- `.timeline-*` classes for the chronological event flow.
- `.session-ended-*` classes for the dead-end termination page.
- `.lab-form textarea` monospace font.

#### Sessions List Page (`testing/sessions_list.html`)
- Table showing all sessions: session ID (truncated), lab, status badge, submission/detected/blocked counts, start time, Timeline or Ended action link.

---

## 3. PARTIALLY COMPLETED WORK

1. **Lab Sandboxing Expansion**:
   - Existing labs: `xss_stored`, `xss_reflected`, `sqli`.
   - Planned labs: Authentication Logic, Access Control / IDOR, Path Traversal, Command Injection sandboxed simulation.
   - Command Injection is detected/blocked but has no dedicated sandboxed lab module yet.
2. **Knowledge Pipeline & Teacher Review (Phase 3)**:
   - Training example queue exists in `/admin`, but `/testing/knowledge`, `/testing/training`, confidence scoring, and teacher verification APIs remain to be wired up.
3. **Real Sentinel Integration (Phase 3)**:
   - `RealSentinelClient` HTTP adapter is fully implemented. Awaits `CYBERLLM_API_URL` in `.env` to activate.
4. **Sidebar Placeholder Links**:
   - `/testing/sentinel`, `/testing/knowledge`, `/testing/training` in `base_testing.html` are visual placeholders awaiting dedicated router pages.

---

## 4. CURRENT PROJECT STRUCTURE

```
SentientAI/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── database.py               # engine, SessionLocal, init_db, _run_migrations
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── auth.py
│   │   ├── blog.py
│   │   ├── health.py
│   │   ├── testing.py            # Full session lifecycle, timeline, session-ended routes
│   │   └── users.py
│   ├── labs/
│   │   ├── __init__.py           # register_lab, get_lab, list_labs
│   │   ├── sql_injection.py
│   │   └── xss.py
│   ├── models/
│   │   ├── __init__.py           # User, SecurityEvent, TrainingExample, BlogPost, LabSession
│   │   ├── blog_post.py
│   │   ├── lab_session.py        # NEW: Session tracking model
│   │   ├── security_event.py     # UPDATED: +session_id FK
│   │   ├── training_example.py
│   │   └── user.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── analysis.py           # UPDATED: accepts optional session_id
│   │   ├── auth_service.py
│   │   ├── cyberllm_client.py    # UPDATED: RealSentinelClient + OBSERVED/INFERRED/UNKNOWN
│   │   ├── detection.py          # UPDATED: always checks command_injection
│   │   └── training.py
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css         # UPDATED: +timeline, session-ended, lab-form styles
│   │   └── js/
│   │       └── main.js
│   └── templates/
│       ├── 403.html
│       ├── 404.html
│       ├── about.html
│       ├── admin.html
│       ├── admin_event.html
│       ├── base_public.html
│       ├── base_testing.html     # UPDATED: +Sessions sidebar link
│       ├── contact.html
│       ├── index.html
│       ├── login.html
│       ├── profile.html
│       ├── register.html
│       ├── blog/
│       │   ├── index.html
│       │   └── post.html
│       └── testing/
│           ├── attack_result.html      # UPDATED: +Session Timeline button
│           ├── blocked.html            # Legacy (sessions without session_id)
│           ├── event_detail.html       # UPDATED: +session FK link
│           ├── events.html
│           ├── lab_detail.html         # UPDATED: +session_id hidden field, session banner
│           ├── labs.html
│           ├── overview.html
│           ├── session_ended.html      # NEW: dead-end termination page
│           ├── session_timeline.html   # NEW: chronological event timeline
│           ├── sessions_list.html      # NEW: all sessions table
│           └── target_xss_stored.html  # NEW: NexusBoard realistic forum target
├── data/
│   └── sentientai.db
├── .env
├── .env.example
├── .gitignore
├── manage.py
├── requirements.txt
├── run.py
└── PROJECT_STATE.md
```

---

## 5. BACKEND

- **FastAPI Structure**: Modular via `create_app()` in `app/main.py`.
- **Existing Routes**:
  - `GET /api/health`
  - `GET /`, `GET /about`, `GET /contact`, `POST /contact`, `GET /profile`
  - `GET /blog`, `GET /blog/{slug}`
  - `GET /login`, `POST /login`, `GET /register`, `POST /register`, `GET /logout`
  - `GET /testing`, `GET /testing/labs`, `GET /testing/labs/{lab_id}`, `POST /testing/labs/{lab_id}/submit`
  - `GET /testing/events`, `GET /testing/events/{event_id}`
  - `GET /testing/sessions`, `GET /testing/sessions/{session_id}` ← NEW
  - `GET /testing/session-ended/{session_id}` ← NEW
  - `GET /testing/blocked` (legacy — sessions without session_id)
  - `GET /admin`, `GET /admin/events/{event_id}`, `POST /admin/training/{id}/approve`, `POST /admin/training/{id}/reject`, `GET /admin/export`
- **Authentication**: JWT tokens in HTTP-only `access_token` cookies, bcrypt passwords.
- **Database**: SQLite via SQLAlchemy with safe idempotent migration in `init_db()`.

---

## 6. FRONTEND

- **Public**: `index.html`, `about.html`, `contact.html`, `blog/`, `login.html`, `register.html`, `profile.html` — all functional.
- **Testing**:
  - `overview.html`: Stats (active sessions counter added), recent sessions panel, recent events, labs catalog.
  - `labs.html`: Lab catalog.
  - `lab_detail.html`: Generic form with session_id hidden field and session banner.
  - `target_xss_stored.html`: Realistic standalone NexusBoard forum target. Not embedded in `base_testing.html`.
  - `attack_result.html`: Attack outcome breakdown with Session Timeline button.
  - `events.html` & `event_detail.html`: Telemetry event log and inspector (now shows session FK).
  - `session_timeline.html`: Chronological timeline with colored event markers. ← NEW
  - `session_ended.html`: Dead-end termination page with defensive lesson. ← NEW
  - `sessions_list.html`: All sessions table. ← NEW
  - `blocked.html`: Legacy interception page (still in use for null-session submits).
  - `admin.html` & `admin_event.html`: Admin dataset curation.
- **Status**: All navigation, authentication, RBAC, lab submissions, session tracking, timeline, and session-ended flows are fully functional.

---

## 7. SENTINEL / CYBERLLM

- **Connection Architecture**: `CyberLLMClientInterface` in `app/services/cyberllm_client.py`.
- **`MockCyberLLMClient`**: Deterministic. Always available. No external calls.
- **`RealSentinelClient`**: HTTP adapter with `/analyze`, `/classify`, `/explain` endpoints. Transparent mock fallback on connection failure.
- **`AnalysisConfidence`**: `OBSERVED` (directly seen in payload), `INFERRED` (logically derived), `UNKNOWN` (cannot determine). Never fabricates findings.
- **Activation**: Set `CYBERLLM_API_URL` in `.env` to activate real client.

---

## 8. TESTING / SECURITY LAB

- **Existing Labs**:
  - `xss_stored`: NexusBoard forum — realistic comment form target.
  - `xss_reflected`: Reflected parameter injection simulation.
  - `sqli`: Fake in-memory user DB with tautology/union/destructive injection paths.
- **Detection Engine**:
  - Checks SQLi, XSS, Path Traversal, Command Injection, Auth Bypass patterns.
  - **Command Injection always checked** regardless of lab category (critical — blocks everywhere).
  - Critical severity → session terminated → redirect to `/testing/session-ended/`.
- **Isolation Guarantees**:
  - No real SQL executed with user input.
  - No shell commands or OS processes executed.
  - No real network scanning or external targeting.
- **Planned**:
  - Dedicated Command Injection and Path Traversal sandbox modules.
  - Auth bypass and IDOR lab modules.

---

## 9. DATABASE

- **Type**: SQLite (`data/sentientai.db`)
- **Tables**:
  - `users`: `id`, `username`, `email`, `hashed_password`, `role`, `is_active`, `created_at`.
  - `blog_posts`: `id`, `slug`, `title`, `author`, `category`, `summary`, `content`, `reading_time`, `published`, `created_at`, `updated_at`.
  - `lab_sessions`: `id`, `session_id` (UUID str PK-like), `user_id`, `lab_id`, `status`, `started_at`, `ended_at`, `termination_reason`, `attack_count`, `detected_count`, `blocked_count`, `metadata_json`. ← NEW
  - `security_events`: `id`, `user_id`, `lab_id`, `session_id` (FK → lab_sessions, nullable), `timestamp`, `method`, `endpoint`, `sanitized_payload`, `detection_result`, `attack_category`, `severity`, `success`, `blocked`, `explanation`, `defense_recommendation`, `raw_analysis_json`.
  - `training_examples`: `id`, `event_id`, `instruction`, `input_text`, `output_text`, `attack_type`, `severity`, `source`, `approved`, `reviewed_by`, `created_at`.

---

## 10. ENVIRONMENT / CONFIGURATION

| Variable | Description | Default / Required |
|---|---|---|
| `SECRET_KEY` | JWT signature secret | Required |
| `DATABASE_URL` | SQLAlchemy URI | `sqlite:///./data/sentientai.db` |
| `ENVIRONMENT` | `development` or `production` | `development` |
| `SENTINEL_MODEL_NAME` | Active model identifier | `SentinelSmolLM2-360M-V9` |
| `CYBERLLM_API_URL` | Sentinel inference server endpoint | Optional (mock if blank) |
| `CYBERLLM_API_KEY` | Sentinel inference API key | Optional |
| `TEACHER_API_KEY` | Teacher reviewer API key | Optional |
| `TEACHER_BASE_URL` | Teacher reviewer base URL | Optional |
| `TEACHER_MODEL` | Teacher reviewer model ID | Optional |

---

## 11. HOW TO RUN

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# First time: create admin, seed blog
python manage.py create-admin --username admin --email admin@sentientai.local --password "AdminPassword123!"
python manage.py seed-blog

# Start app
python run.py
```

- Public: `http://127.0.0.1:8000/`
- Testing (tester/admin): `http://127.0.0.1:8000/testing`
- API docs: `http://127.0.0.1:8000/api/docs`

---

## 12. KNOWN BUGS / PROBLEMS

1. **Legacy Route Files**: `app/api/attacks.py` and `app/api/labs.py` may still exist; superseded by `testing.py`.
2. **Contact Form Storage**: `POST /contact` acknowledges but doesn't persist the message.
3. **Session Duration**: `LabSession.duration_seconds` is a computed property — displayed as `—` on the timeline while a session is active (correct). Only shows once ended.
4. **Detection Multi-Category**: When a payload matches both XSS and Command Injection patterns in the XSS lab, the first match wins. Category priority logic could be refined.

---

## 13. NEXT STEPS (PHASE 3)

1. **Wire Up Real Sentinel Client**: Set `CYBERLLM_API_URL` in `.env` to point to the local `SentinelSmolLM2-360M-V9` inference server. The adapter is ready.
2. **Build `/testing/knowledge`**: Analyst-facing knowledge candidate review queue (pending `TrainingExample` items, batch approve/reject, confidence display).
3. **Build `/testing/training`**: Training data export, JSONL inspection, and dataset health metrics.
4. **Build `/testing/sentinel`**: Live model status page (connection status, model version, inference latency, queue depth).
5. **Add Command Injection Lab Module**: A sandboxed `cmd_injection` lab with a realistic target (e.g. fake diagnostic tool UI) that demonstrates the vulnerability without executing real commands.
6. **Add Path Traversal Lab Module**: Sandboxed file browser simulation.
7. **Promote Existing Users to Tester**: `python manage.py set-role --username <name> --role tester`.

---

## 14. CURRENT CHECKPOINT

- **Current Phase**: **Phase 2 Complete** — Lab Session Architecture & Realistic Target UX.
- **Last Completed Task**: Full session lifecycle (create → track → terminate → session-ended dead-end), NexusBoard realistic XSS target, attack event timeline, Sentinel OBSERVED/INFERRED/UNKNOWN adapter, command injection always-blocks cross-lab.
- **First Task to Continue With**: Phase 3 — Real Sentinel integration, `/testing/knowledge`, `/testing/training`, `/testing/sentinel` pages.
- **Files Most Likely to be Modified Next**:
  - `app/api/testing.py` (new sentinel/knowledge/training routes)
  - `app/services/cyberllm_client.py` (activate `RealSentinelClient` via env)
  - `app/templates/testing/` (new sentinel status, knowledge, training pages)
  - `app/labs/` (new cmd_injection.py, path_traversal.py modules)
