# PROJECT_STATE.md — SentientAI

*Last updated: 2026-08-27 (Phase 1 Refactor Checkpoint)*

---

## 1. PROJECT OVERVIEW

**SentientAI** is a dual-experience cybersecurity education and research platform designed to provide:
1. **A Public-Facing Website**: A believable, clean, content-first web experience offering security research articles, platform information, and standard user account management without exposing security testing telemetry or internal model dashboards.
2. **A Protected Testing Lab (`/testing`)**: A separate, technical, analyst-focused security research console where authorized users (testers and administrators) interact with isolated vulnerability labs, view deterministic detection telemetry, inspect event timelines, and review candidate security knowledge.

### Current Architecture
- **Web Layer**: FastAPI application rendering server-side Jinja2 templates for both public and testing experiences, with REST API endpoints for data operations.
- **Security & Sandboxing**: Server-side sandboxed lab simulators running isolated mock data layers with regex-based deterministic detection pipelines.
- **Data & Persistence**: SQLite database (configured for PostgreSQL migration capability via SQLAlchemy ORM) storing users, security events, training examples, and blog posts.
- **AI / Model Layer**: Model abstraction interface (`CyberLLMClientInterface`) currently backed by `MockCyberLLMClient`, structured to consume local or remote inference from the `SentinelSmolLM2-360M-V9` model and teacher review APIs.

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

### Architecture & Routing Separation
- **Dual Template Hierarchy**: Created `app/templates/base_public.html` and `app/templates/base_testing.html` to strictly isolate the public website from the testing lab UI.
- **Public Routes (`app/api/users.py`, `app/api/blog.py`)**:
  - `/`: Public homepage with platform mission, features, latest articles, and learning philosophy.
  - `/about`: Platform explanation, lab isolation model, and Sentinel analysis philosophy.
  - `/contact`: Public contact form with acknowledgment handler.
  - `/blog` and `/blog/{slug}`: Technical blog listing with category filters and article view.
  - `/profile`: Public user profile displaying user role and link to `/testing` for authorized accounts.
- **Testing Environment Routes (`app/api/testing.py`)**:
  - `/testing`: Analyst overview displaying event statistics, available labs, and engine status.
  - `/testing/labs`: Lab browser showing sandboxed challenges.
  - `/testing/labs/{lab_id}`: Dedicated lab interface.
  - `POST /testing/labs/{lab_id}/submit`: Lab submission handler running sandboxing, detection, and telemetry capture.
  - `/testing/events`: Telemetry event log for user sessions.
  - `/testing/events/{event_id}`: Detailed inspection of individual security events.
  - `/testing/blocked`: Session interception/termination landing page.

### Role-Based Access Control (RBAC)
- **User Roles (`app/models/user.py`)**: Updated `User` model with `role` column (`user`, `tester`, `admin`).
- **Authorization Dependencies (`app/services/auth_service.py`)**:
  - `require_tester`: Restricts `/testing/*` routes strictly to accounts with `tester` or `admin` roles.
  - `require_admin`: Restricts `/admin/*` routes strictly to accounts with `admin` role.
  - `get_current_user_optional`: Provides safe contextual user extraction for public pages.
- **Registration Security (`app/api/auth.py`, `app/templates/register.html`)**:
  - Removed the insecure `admin_secret` field from the registration form.
  - All public sign-ups default safely to `role="user"`.
  - Role-based redirect on login: `user` accounts redirect to `/`, `tester`/`admin` accounts redirect to `/testing`.

### CLI & Management Tooling
- **`manage.py`**: Created a CLI utility with commands:
  - `create-admin`: Creates administrative users with secure password hashing.
  - `set-role`: Safely updates an existing user's role to `user`, `tester`, or `admin`.
  - `list-users`: Displays all database users and their active roles.
  - `seed-blog`: Populates realistic technical articles in the `blog_posts` table.

### Data Models & Schema
- **`BlogPost` (`app/models/blog_post.py`)**: Stores slugs, titles, authors, categories, markdown/text content, reading time estimates, and publication status.
- **`User` (`app/models/user.py`)**: Updated with `role` field, keeping `is_admin` and `is_tester` helper properties.
- **`SecurityEvent` (`app/models/security_event.py`)**: Structured telemetry recording payload, detection result, attack category, severity, blocked status, and raw analysis JSON.
- **`TrainingExample` (`app/models/training_example.py`)**: Records instruction, input, output, attack type, severity, approval status, and reviewer ID.

---

## 3. PARTIALLY COMPLETED WORK

1. **Lab Sandboxing Expansion (Phases 2 & 7)**:
   - Existing labs: Stored XSS (`xss_stored`), Reflected XSS (`xss_reflected`), SQL Injection (`sqli`).
   - Missing/Planned labs: Authentication Logic, Access Control / IDOR, Path Traversal simulation, Command Injection simulation.
2. **Dedicated Target Application Simulation UX (Phase 2)**:
   - Currently, lab pages (`lab_detail.html`) present a specification and test input box. The target application UI and the security console have not yet been split into two distinct visual surfaces (e.g. realistic mini-app target vs. console dock).
3. **Session & Timeline Tracking (`LabSession`) (Phase 2)**:
   - `SecurityEvent` currently tracks individual events per user and lab. A formal `LabSession` lifecycle model (with session IDs, start/stop timestamps, attack timeline graph, and dead-end redirects to `/testing/session-ended/{session_id}`) is not yet implemented.
4. **Live Sentinel / CyberLLM Integration (Phase 3)**:
   - `MockCyberLLMClient` provides structured mock responses. Real HTTP/client connection to the local `SentinelSmolLM2-360M-V9` inference server is ready for adapter implementation in Phase 3.
5. **Knowledge Candidate & Teacher Review Pipeline (Phases 4 & 5)**:
   - Training example queue exists in `/admin`, but the full analyst-facing `/testing/knowledge`, candidate confidence scoring, and teacher verification APIs (`TEACHER_API_KEY`, `TEACHER_BASE_URL`) remain to be wired up.

---

## 4. CURRENT PROJECT STRUCTURE

```
SentientAI/
├── app/
│   ├── __init__.py               # Package marker
│   ├── config.py                 # Environment configuration (pydantic/env loader)
│   ├── database.py               # SQLAlchemy engine, SessionLocal, init_db
│   ├── main.py                   # FastAPI app factory, middleware, router inclusions
│   ├── api/                      # Route handlers
│   │   ├── __init__.py           # API package marker
│   │   ├── admin.py              # Admin panel, event review, training example review & JSONL export
│   │   ├── auth.py               # Login, registration, logout, session cookies
│   │   ├── blog.py               # Public blog listing & article view
│   │   ├── health.py             # Healthcheck endpoint (/api/health)
│   │   ├── testing.py            # Protected /testing lab, event, and overview routes
│   │   └── users.py              # Public site routes (/, /about, /contact, /profile)
│   ├── labs/                     # Isolated vulnerability simulations
│   │   ├── __init__.py           # Lab registry (register_lab, get_lab, list_labs)
│   │   ├── sql_injection.py      # Sandboxed in-memory SQL injection lab
│   │   └── xss.py                # Sandboxed in-memory Stored and Reflected XSS labs
│   ├── models/                   # SQLAlchemy database models
│   │   ├── __init__.py           # Model exports (User, SecurityEvent, TrainingExample, BlogPost)
│   │   ├── blog_post.py          # BlogPost schema & category constants
│   │   ├── security_event.py     # SecurityEvent telemetry schema
│   │   ├── training_example.py   # TrainingExample dataset curation schema
│   │   └── user.py               # User model with role field
│   ├── services/                 # Business logic & security engines
│   │   ├── __init__.py           # Services package marker
│   │   ├── analysis.py           # Analysis orchestrator (Detection -> Model -> DB logging)
│   │   ├── auth_service.py       # Password hashing, JWT tokens, RBAC dependencies
│   │   ├── cyberllm_client.py    # Sentinel/CyberLLM interface & Mock client
│   │   ├── detection.py          # Rule-based regex detection engine (SQLi, XSS, Cmd, Traversal, Auth)
│   │   └── training.py           # Training example retrieval, approval, rejection, JSONL export
│   ├── static/                   # Static web assets
│   │   ├── css/
│   │   │   └── style.css         # Complete stylesheet for public & testing layouts
│   │   └── js/
│   │       └── main.js           # Client-side helpers (mobile nav toggle, alert dismiss, anti-dblsubmit)
│   └── templates/                # Jinja2 HTML templates
│       ├── 403.html              # Access denied page for unauthorized roles
│       ├── 404.html              # Page not found
│       ├── about.html            # Public about page
│       ├── admin.html            # Admin dashboard (extends base_testing.html)
│       ├── admin_event.html      # Admin detailed event inspector
│       ├── base_public.html      # Public website base layout
│       ├── base_testing.html     # Testing lab console sidebar layout
│       ├── contact.html          # Public contact page
│       ├── index.html            # Public homepage
│       ├── login.html            # Public sign-in page
│       ├── profile.html          # User profile page
│       ├── register.html         # Public account registration page
│       ├── blog/
│       │   ├── index.html        # Blog post listing & category filters
│       │   └── post.html         # Blog post article reader
│       └── testing/
│           ├── attack_result.html# Lab attack execution & telemetry breakdown
│           ├── blocked.html      # Critical payload blocked / interception notice
│           ├── event_detail.html # Event inspection page
│           ├── events.html       # Security events table
│           ├── lab_detail.html   # Lab execution & submission view
│           ├── labs.html         # Lab challenge catalog
│           └── overview.html     # Testing environment overview dashboard
├── data/
│   └── sentientai.db             # Local SQLite database file
├── .env                          # Local environment settings (git-ignored)
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore file
├── manage.py                     # CLI management script (admin creation, role setting, seeding)
├── requirements.txt              # Python dependency manifest
├── run.py                        # Uvicorn entrypoint script
└── PROJECT_STATE.md              # Current project state checkpoint
```

---

## 5. BACKEND

- **FastAPI Structure**: Modular application initialized via `create_app()` in `app/main.py`. Includes `SecurityHeadersMiddleware` enforcing strict security headers (`nosniff`, `DENY` frames, XSS protection, Referrer Policy).
- **Existing Routes**:
  - `GET /api/health`
  - `GET /`, `GET /about`, `GET /contact`, `POST /contact`, `GET /profile`
  - `GET /blog`, `GET /blog/{slug}`
  - `GET /login`, `POST /login`, `GET /register`, `POST /register`, `GET /logout`
  - `GET /testing`, `GET /testing/labs`, `GET /testing/labs/{lab_id}`, `POST /testing/labs/{lab_id}/submit`, `GET /testing/events`, `GET /testing/events/{event_id}`, `GET /testing/blocked`
  - `GET /admin`, `GET /admin/events/{event_id}`, `POST /admin/training/{id}/approve`, `POST /admin/training/{id}/reject`, `GET /admin/export`
- **Authentication**: JWT tokens stored in HTTP-only `access_token` cookies with lax SameSite policy. Passwords hashed using bcrypt.
- **Database**: SQLite (via SQLAlchemy engine) with `check_same_thread=False` and automatic model table generation in `init_db()`.
- **AI / Sentinel Integration**: Managed in `app/services/cyberllm_client.py` and `app/services/analysis.py`. Calls `analyze_attack()` to format explanations, CWE/MITRE classifications, and generate structured training candidates.

---

## 6. FRONTEND

- **Public Website Pages**:
  - `index.html`: Hero section, feature breakdown, latest blog posts, platform mission. Fully functional.
  - `about.html`: Platform overview, lab isolation principles, Sentinel model explanation. Fully functional.
  - `contact.html`: Clean contact submission form. Functional UI with state acknowledgment.
  - `blog/index.html` & `blog/post.html`: Technical articles and category filtering. Functional with seed data.
  - `login.html` & `register.html`: Clean auth pages extending `base_public.html`.
  - `profile.html`: Displays user account details, role badge, and testing link.
- **Testing Interface Pages**:
  - `testing/overview.html`: Live metrics, available labs, and recent activity inside a fixed sidebar console layout.
  - `testing/labs.html` & `testing/lab_detail.html`: Lab catalog and execution form.
  - `testing/attack_result.html`: Visual breakdown of attack outcome (Blocked/Success/Detected/Clean) with sanitized payload and detection signals.
  - `testing/events.html` & `testing/event_detail.html`: Dense event log table and inspector.
  - `testing/blocked.html`: Interception notice with links to review telemetry or restart lab.
  - `admin.html` & `admin_event.html`: Administrator overview with training dataset curation controls.
- **Status (Functional vs Placeholder)**:
  - Navigation, authentication, role authorization, and lab submissions are completely functional.
  - Sidebar links for `/testing/sentinel`, `/testing/knowledge`, and `/testing/training` in `base_testing.html` are visual placeholders awaiting their respective dedicated router pages in subsequent phases.

---

## 7. SENTINEL / CYBERLLM

- **Connection Architecture**: Sentinel model consumption is abstracted behind `CyberLLMClientInterface` in `app/services/cyberllm_client.py`.
- **Integration Status**:
  - Currently uses `MockCyberLLMClient` to format deterministic detection results into structured educational analysis.
  - Ready to connect to the local inference server (`SentinelSmolLM2-360M-V9`) when `CYBERLLM_API_URL` and `CYBERLLM_API_KEY` are populated in the environment.
- **Separation of Concerns**:
  - SentientAI acts purely as an inference consumer and training candidate collector.
  - Model training itself is handled externally in the dedicated CyberLLM project.

---

## 8. TESTING / SECURITY LAB

- **Existing Lab Implementations**:
  - **Stored XSS (`xss_stored`)**: In-memory comment guestbook simulating unsanitized reflection of stored payload vectors.
  - **Reflected XSS (`xss_reflected`)**: Unescaped parameter reflection simulation for script injection vectors.
  - **SQL Injection (`sqli`)**: Simulated user lookup concatenating input into a mock query evaluated against a fake in-memory user dataset (`FAKE_USERS_DB`).
- **Detection & Security Controls**:
  - Deterministic detection engine (`app/services/detection.py`) analyzes payloads against categorized regex rules for SQLi, XSS, Path Traversal, Command Injection, and Auth Bypass.
  - Assigns attack classification, confidence, severity (low, medium, high, critical), and defense recommendations.
  - Intercepts and blocks critical-severity attacks, redirecting to `/testing/blocked`.
- **Isolation & Safety Guarantees**:
  - No database queries execute raw user input on the real SQLite database.
  - No shell commands or operating system processes are executed.
  - No real network scanning or external targeting capabilities exist.
- **Planned / Not Yet Implemented**:
  - Formal `LabSession` tracking and live attack timeline visualization.
  - Standalone target web app frames (e.g. realistic mini blog/store UI).
  - Path traversal and command injection sandboxed simulation modules.

---

## 9. DATABASE

- **Type**: SQLite (path: `data/sentientai.db`)
- **Tables / Models**:
  - `users`: `id`, `username`, `email`, `hashed_password`, `role` (`user`|`tester`|`admin`), `is_active`, `created_at`.
  - `blog_posts`: `id`, `slug`, `title`, `author`, `category`, `summary`, `content`, `reading_time`, `published`, `created_at`, `updated_at`.
  - `security_events`: `id`, `user_id`, `lab_id`, `timestamp`, `method`, `endpoint`, `sanitized_payload`, `detection_result`, `attack_category`, `severity`, `success`, `blocked`, `explanation`, `defense_recommendation`, `raw_analysis_json`.
  - `training_examples`: `id`, `event_id`, `instruction`, `input_text`, `output_text`, `attack_type`, `severity`, `source`, `approved`, `reviewed_by`, `created_at`.

---

## 10. ENVIRONMENT / CONFIGURATION

Configuration is loaded from `.env` in the root directory via `app/config.py`:

| Variable | Description | Default / Required |
|---|---|---|
| `SECRET_KEY` | JWT signature encryption secret | Required (Set to secure random string) |
| `DATABASE_URL` | SQLAlchemy database connection URI | Default: `sqlite:///./data/sentientai.db` |
| `ENVIRONMENT` | Deployment mode (`development` or `production`) | Default: `development` |
| `SENTINEL_MODEL_NAME` | Active Sentinel model identifier | Default: `SentinelSmolLM2-360M-V9` |
| `CYBERLLM_API_URL` | Endpoint for external/local Sentinel model server | Optional (uses Mock client if blank) |
| `CYBERLLM_API_KEY` | API authentication key for Sentinel model server | Optional |
| `TEACHER_API_KEY` | API key for external Teacher reviewer model | Optional |
| `TEACHER_BASE_URL` | Base URL for Teacher reviewer model API | Optional |
| `TEACHER_MODEL` | Identifier for Teacher reviewer model | Optional |

*(Note: Never commit `.env` containing sensitive credentials to Git).*

---

## 11. HOW TO RUN

### 1. Activate Environment & Install Dependencies
```powershell
# In project root:
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment
```powershell
# Copy template to .env if not already present
Copy-Item .env.example .env
```

### 3. Seed Initial Data & Create Admin
```powershell
# Seed initial technical blog articles
python manage.py seed-blog

# Create an administrator account
python manage.py create-admin --username admin --email admin@sentientai.local --password "AdminPassword123!"

# Or promote an existing user to tester/admin
python manage.py set-role --username <username> --role tester
```

### 4. Start the Application
```powershell
python run.py
```
Access the application:
- Public Website: `http://127.0.0.1:8000/`
- Testing Environment (Requires tester/admin login): `http://127.0.0.1:8000/testing`
- API Documentation: `http://127.0.0.1:8000/api/docs`

---

## 12. KNOWN BUGS / PROBLEMS

1. **Legacy Route Cleanliness**: `app/api/attacks.py` and `app/api/labs.py` are superseded by `app/api/testing.py` but still exist in the repository; they should be cleanly deprecated or removed in Phase 2.
2. **Contact Form Storage**: `POST /contact` acknowledges the user's message but does not currently persist the message to a database table or forward via email.
3. **Session Lifecycle Tracking**: Attack events are logged independently without a parent `LabSession` entity, meaning multi-step attack state cannot currently be correlated across a single lab attempt.

---

## 13. NEXT STEPS

1. **Implement `LabSession` & Session Lifecycle**: Create `LabSession` model to track active user test runs with distinct session tokens and state management.
2. **Build Realistic Lab Target Sub-Apps**: Separate the lab interface into a believable mock application (e.g. comment service, customer portal) and an adjacent analyst telemetry panel.
3. **Build Attack Timeline View**: Implement interactive event timelines mapping each request from initial reconnaissance to detection and session termination (`/testing/session-ended/{session_id}`).
4. **Implement Real Sentinel Service Adapter**: Replace `MockCyberLLMClient` with a robust client connecting to the locally hosted `SentinelSmolLM2-360M-V9` model, formatting observed vs. inferred vs. unknown findings.
5. **Develop Knowledge Pipeline & Review Workflow**: Build out `/testing/knowledge` and `/testing/training` views for auto-generating and approving knowledge candidates from lab incidents.

---

## 14. CURRENT CHECKPOINT

- **Current Phase**: Completed Phase 1 (Public Website / Testing Environment Separation & RBAC).
- **Last Completed Task**: Created `manage.py` CLI, established public content routes/templates, implemented `require_tester` RBAC, and created `PROJECT_STATE.md`.
- **First Task to Continue With**: Phase 2 — Lab Session & Event Timeline Architecture (defining `LabSession` model, session lifecycle, and target application interface).
- **Files Most Likely to be Modified Next**:
  - `app/models/lab_session.py` (New model)
  - `app/models/security_event.py` (Adding `session_id` foreign key)
  - `app/api/testing.py` (Session creation, event timeline, and termination handlers)
  - `app/templates/testing/session_detail.html` or `timeline.html`
  - `app/services/analysis.py` (Session-aware analysis orchestration)
