# TEST PLAN — SentientAI (2026-10-20)

Scope: `http://127.0.0.1:8000` (FastAPI `app.main:app`). Evidence root `TESTv1/`. Read `INVENTORY.md` + `ENVIRONMENT.md` before execution.

## Conventions
- Verdict: PASS / FAIL / BLOCKED / N/A. BLOCKED = cannot complete, explain why. No invented results.
- Every check records route, action, expected, actual, status, evidence path.
- Screenshots → `evidence/screenshots/<name>.png` (descriptive names). Browser traces → `evidence/browser/`. Raw logs → `logs/`.
- Synthetic test accounts/data only. No destructive security payloads, no external targets.

## P0 — Must pass (auth, security, navigation)
| ID | Area | Route(s) | Action | Expected | Priority |
|---|---|---|---|---|---|
| P0-01 | Health | `GET /api/health` | Fetch unauthenticated | 200 `{"status":"ok","service":"sentientai"}` + CSP + security headers + `csrf_token` cookie | P0 |
| P0-02 | Public index | `GET /` | Load anon | 200, nav shows /, /explore, /blog, /community, /search, /login, /register | P0 |
| P0-03 | Public pages | `GET /about`, `/contact`, `/explore`, `/blog`, `/community`, `/search` | Load anon | 200, no auth required | P0 |
| P0-04 | Register | `GET/POST /register` | GET form, POST invalid email / empty / duplicate | Validation errors, CSRF enforced | P0 |
| P0-05 | Login/Logout | `GET/POST /login`, `POST|GET /logout` | Valid + invalid creds, logout clears session | Success redirect + error messages, back-nav after logout | P0 |
| P0-06 | Password reset | `GET/POST /forgot-password`, `GET/POST /reset-password`, `GET/POST /account/password` | Empty/invalid/valid flows | Token expiry + single-use (30m), dev SMTP logs link | P0 |
| P0-07 | CSRF | Any `POST` without token / with bad token | Submit | 403 + security headers still present | P0 |
| P0-08 | Security headers | Any response | Inspect headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, CSP as in ENVIRONMENT.md | P0 |
| P0-09 | Admin access control | `GET /admin`, `/admin/users`, `/admin/moderation`, `/admin/security`, `/admin/sentinel/*`, `/api/sentinel/readiness/load` | Anon + non-admin vs admin | 401/403 or redirect for anon/non-admin; 200 for admin | P0 |

## P1 — Core product
| ID | Area | Route(s) | Expected | Priority |
|---|---|---|---|---|
| P1-01 | Blog write/edit | `GET/POST /write`, `GET/POST /blog/{slug}/edit`, `POST /blog/{slug}/state`, `POST /blog/{slug}/delete` | Create, edit own, state transitions, delete own | P1 |
| P1-02 | Social | `POST /blog/{slug}/like`, `/comment/{id}/like`, `/blog/{slug}/comment`, `/blog/{slug}/bookmark`, `POST /users/{username}/follow` | Counts update, rate-limit (`limit_reaction`, `limit_comment`) | P1 |
| P1-03 | Bookmarks/feed | `GET /bookmarks`, `GET /feed`, `GET /explore` | Authed vs anon filtering | P1 |
| P1-04 | Messages | `GET /messages`, `GET/POST /messages/{username}` | Thread appears, rate-limit `limit_message` | P1 |
| P1-05 | Notifications | `GET /notifications`, `POST /notifications/read-all`, `POST /notifications/{id}/read` | Read state updates | P1 |
| P1-06 | Profile | `GET /u/{username}`, `GET /users/{username}`, `GET/POST /profile/edit`, `GET /profile` | Public profile anon, edit own | P1 |
| P1-07 | Moderation | `GET/POST /report`, `GET /admin/moderation` + resolve/dismiss/hide/restore/suspend | Report creates, admin actions mutate state | P1 |
| P1-08 | Search | `GET /search?q=...` | Results for valid, empty handling | P1 |
| P1-09 | Theme | `GET/POST /theme`, `GET /theme-resolve`, `static/js/theme.js` | system/light/dark persists localStorage + server, no FOUC, meta theme-color sync | P1 |
| P1-10 | Errors | `/nonexistent`, 403/429/500 templates | Correct error pages, no stack disclosure in prod | P1 |

## P2 — Security Lab, Sentinel, ATT&CT
| ID | Area | Route(s) | Expected | Priority |
|---|---|---|---|---|
| P2-01 | Security Lab API | `POST /run`, `GET /runs`, `GET /runs/{rid}`, `POST /analyze`, `POST /log-analyze`, `DELETE /runs/{rid}` | Validate target URL allowlist (SSRF defense), synthetic evidence labels | P2 |
| P2-02 | Security Lab runners | `app/services/security_lab*.py` (`validate_target_url`, `_synthetic_evidence`, `CANARYForType`, `_TEST_LOCK`) | Canonical helpers re-exported, lock prevents concurrent runs | P2 |
| P2-03 | ATT&CT / Security API | `POST /attact/run`, `GET /assessments`, `GET /assessments/{aid}/export`, `GET /events`, `GET /events/export`, `POST /findings/{fid}/triage`, `POST /demo/run/{case_id}` | AuthZ, exports, triage | P2 |
| P2-04 | Admin security reports | `GET /admin/security`, `GET /admin/reports/security`, `GET /admin/reports/security/{rid}`, `GET /admin/assessments/{aid}` | HTML renders, alias `_reports_alias` in main.py | P2 |
| P2-05 | Sentinel readiness | `GET /api/sentinel/readiness`, `POST /api/sentinel/readiness/load` | `ready`, `a`/`b`, `vocab_size`, `prompt_chars`, background load, fail-open without torch | P2 |
| P2-06 | Sentinel analyze | `POST /api/sentinel/analyze` (`log_text`, `extra_prompt`, `max_new_tokens` 16-256) | Schema validation, incident dedup (ip+log hash, 10m), SecurityEvent persisted | P2 |
| P2-07 | Sentinel pipeline | `sentinel_loader.py`, `sentinel_inference.py`, `sentinel_schema.py`, `sentinel_fusion.py`, `sentinel_bridge.py`, `prompt_service.py` | 0% valid-output history must be reproduced; distinguish model vs rules vs fused | P2 |
| P2-08 | Sentinel UI | `GET /sentinel`, `GET /admin/sentinel/incidents`, `POST /api/sentinel/incidents/{id}/review`, blocks/training endpoints | Review + containment flows | P2 |
| P2-09 | Rate limiting | `app/services/ratelimit.py` (limit_message, limit_reaction, limit_comment, limit_post_write) | 429 on abuse, headers correct | P2 |
| P2-10 | Sanitization/XSS | `app/services/sanitize.py` + templates | Stored XSS blocked, output encoding, CSP second line | P2 |

## Execution order
1. P0 in browser + direct fetch (headers/CSRF/admin gates).
2. P1 in browser (forms, navigation, theme, errors).
3. P2 API + backend (lab allowlist, sentinel readiness, ATT&CT) — targeted pytest only.
4. Fix reproducible bugs (Ponytail minimal fixes), retest affected area, log in FIX_LOG.md.
