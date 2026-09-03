# REFACTOR_PLAN.md — working tracker for the full refactor

*Transient scaffolding. Folded into PROJECT_CHECKPOINT.md and deleted at the end.*
*Branch: `redesign/public-site-and-security-foundation` — no merge to main, no PR. Every phase ends with a green `./venv/Scripts/python.exe -m pytest` and its own commit.*

Goal: turn the "cybersecurity attack-lab platform" into a clean, legitimate
blogging/social site + a private `/admin` panel + an **internal** AI/Sentinel
(no security-testing vocabulary anywhere in the public product). Remove old
code; do not layer on top. Do not fabricate features or test results.

## Locked decisions (interpretations of the spec)
- **Password column** `hashed_password` → **`password_hash`** (spec names it; DB reset makes the rename free of migration). Hash-only, never plaintext.
- **Hashing**: passlib **Argon2id** — `schemes=["argon2"], argon2__type="ID", m=19456, t=2, p=1` (OWASP-recommended Argon2id). Not weakened for tests.
- **Session invalidation**: add `User.token_version` (int, default 0) + `tv` JWT claim; `get_current_user` fails closed on mismatch/missing. Bump on logout (logout-all), password change (+ re-issue current session cookie), reset, suspend, delete, remove-all-users.
- **SECRET_KEY**: fail-safe — raise at startup if missing while `ENVIRONMENT=production`; dev keeps an insecure default.
- **AI/Sentinel re-sourcing**: dataset candidates come from **content-moderation assistance** (posts/comments), not attack payloads. Keep `TrainingExample` (drop `event_id`), `scoring.py` (generalize signature), `training.py` (export = the honest "clean dataset export interface" of §14). No fabricated training.
- **Simplify the learning stack** (pending a usage re-grep in Phase 2b): drop routeless model-artifact tables `ModelCheckpoint`, `EvaluationRun`, `DatasetVersion` and the lab-coupled `AnalysisFeedback` — they imply model-training we don't do (§14) and have no routes. `TrainingExample` review lifecycle (approve/reject/needs-edit + review_note + reviewed_by) covers §13.
- **Requests/Reports (§11)**: reuse the existing `Report`/`ModerationAction` two-tier system (already keyed on post/comment/profile with audit trail).
- **Messaging (§1)**: simple server-rendered DMs (inbox + thread + send), no websockets. New `Message` model.
- **admin@12345** invalid-email is a spec-mandated literal; comply, flag as a limitation (reset email to it can't actually send).

## Keep / delete (from the 3 exploration maps)
**KEEP (public/general):** routers users, blog, feed, social, community, auth, moderation(`/report`), health; models User, BlogPost, Tag/post_tags, PostLike/Comment/CommentLike/Bookmark/Follow/Notification, Report, ModerationAction, AuditEvent, DailyMetric, SearchQueryStat, Activity; services content, audit, sanitize, ratelimit, activity_service, tags, pagination, errors, auth_service, csrf; templates base_public + public set + error pages + partials; public.css, public.js.
**KEEP (internal, decouple from labs):** TrainingExample, scoring.py, training.py, cyberllm_client.py (repurpose to content analysis).
**DELETE (security-lab):** routers testing.py, attacks.py(dead), labs.py(dead); app/labs/; services detection.py, analysis.py; models SecurityEvent, LabSession; templates testing/*, base.html, orphan root attack/lab templates, base_testing.html, style.css, main.js; tests test_testing_area, test_lab_sessions, test_cyberllm, test_analysis_feedback (+ trim test_scoring, test_training_pipeline); verify_security.py.
**LEAK fixes:** base_public.html (is_tester/testing link), dashboard_user.html (lab sections), activity.html (lab label map), community.py (lab stats/lab_sessions_count), ACTIVITY_TYPES, AUDIT_EVENT_TYPES, ratelimit (limit_analysis/limit_feedback). Reparent 4 admin_*.html + admin/moderation.html onto base_admin.html.

## Phases (each green + committed)
- [x] **P1 — Security/secrets foundation.** argon2-cffi req; Argon2id; `password_hash` rename; `token_version` + `tv` claim + fail-closed check; logout/password-change invalidation; SECRET_KEY prod guard; SMTP + reset settings in config; `.env.example`/`.gitignore` rewrite; DATABASE_URL→`app.db`; drop dead TEACHER_*/ADMIN_SECRET. (SENTINEL_MODEL_NAME kept until P2b.)
- [x] **P2a — Delete unregistered dead code** (attacks.py/labs.py + orphan templates + base.html).
- [x] **P2b — Remove /testing area + lab backend + their tests**; decouple TrainingExample/scoring/training; drop SecurityEvent/LabSession (+ simplify learning stack); fix leaks; reparent admin templates; delete base_testing/style.css/main.js; drop init_labs from conftest+main; extend test_public_routes to /dashboard,/activity; delete verify_security.py.
- [x] **P3 — Password reset via SMTP** (PasswordResetToken model, email service, forgot/reset routes+templates, no enumeration, single-use/expiry, session invalidation, no auto-login).
- [x] **P4 — Admin panel** (base_admin + nav Dashboard/Users/Posts/Comments/Requests/Logs/AI-Dataset/Settings; user mgmt incl Remove-All-Users w/ confirm+transaction; posts/comments mgmt; logs viewer w/ filters; settings read-only; every route require_admin).
- [x] **P5 — Internal Sentinel re-sourcing** (moderation→candidate producer in app/services/collection.py, wired into the admin-only moderation flow; admin review→approve→export JSONL; advisory scoring only, never auto-trains; integration tests re-added).
- [x] **P6 — Messaging/chat** (Message model + `app/services/messaging.py` + `app/api/messages.py` inbox/thread/send; header envelope badge via `unread_messages`; profile "Message" button; message→Notification; server-rendered, no websockets; tests).
- [x] **P7 — Seed/reset → single admin** (`seed_blog` rewritten to legitimate posts — Python type hints / web typography / writing tests — authored by real seed users `maya` & `devon` with `apply_state(POST_PUBLISHED)`; the old stored-XSS / SQL-injection / detection-pipeline posts removed). Reset-db already seeds exactly one admin (admin/admin@12345).
- [x] **P8 — Public UI cleanup.** Purged dead `RESEARCH_CATEGORIES`/`ALL_CATEGORIES` from `blog_post.py` and the two leak comments (`blog.py` whitelist note, `users.py` `/profile` redirect). Unified all seven hand-rolled post-card blocks (index, explore, community, search, feed×2, profile, bookmarks) onto `partials/post_card.html` — added one optional `show_bookmark` toggle to the partial for the pages that carried a bookmark control; removed the invalid `<a>`-wrapped cards. Net −173 lines of duplicated markup. Zero security-testing vocabulary in any template.
- [ ] **P9 — DOCUMENTATION.md + README rewrite**; consolidate PROJECT_STATE/PROJECT_CHECKPOINT.
- [ ] **P10 — Final verification** (full suite, security checklist, smoke) + implementation report (§23).
