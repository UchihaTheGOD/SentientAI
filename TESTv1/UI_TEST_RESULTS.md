# UI TEST RESULTS — SentientAI (2026-10-20)

> Browser-based checks against `http://127.0.0.1:8000` (openclaw/chromium, Edge detected pid 21336). Navigation via browser tool BLOCKED by policy — fallback to direct fetch (Invoke-WebRequest) for factual verification. Synthetic data only. Screenshots `evidence/screenshots/<name>.png`, logs `logs/browser_retry.log`.

| # | Page / Route | Action | Expected | Actual | Result | Evidence |
|---|---|---|---|---|---|---|
| 1 | GET / | Fetch public homepage | 200 html, nav links present | 200 len=16633, nav /explore /blog /community /search /login /register /about /contact all found=True | PASS | `logs/browser_retry.log` §FETCH + NAV |
| 2 | GET /explore | Fetch explore feed | 200 html | 200 len=11320 | PASS | `logs/browser_retry.log` |
| 3 | GET /search?q=test | Fetch search | 200 html | 200 len=5910 | PASS | `logs/browser_retry.log` |
| 4 | GET /blog | Fetch blog index | 200 html | 200 len=11459 | PASS | `logs/browser_retry.log` |
| 5 | GET /community | Fetch community | 200 html | 200 len=16631 | PASS | `logs/browser_retry.log` |
| 6 | GET /login | Fetch + verify csrf_token hidden field | 200 html, hidden input csrf_token present | 200 len=6366, `name="csrf_token" value="toTAb1Bx-...501c368"` len 65, type=hidden count 1 | PASS | `logs/browser_retry.log` CSRF § |
| 7 | GET /register | Fetch + verify csrf_token hidden field | 200 html, hidden input csrf_token present | 200 len=7086, `name="csrf_token" value="B1wAtzRU...1d64a"` len 65, hidden count 1 | PASS | `logs/browser_retry.log` CSRF § |
| 8 | Theme | Verify data-theme attr + js/theme.js + localStorage via HTML + static fetch | html has data-theme, ref to theme.js, localStorage; GET /static/js/theme.js 200 contains localStorage+data-theme logic | Homepage data-theme=True, theme.js ref=True, localStorage=True; GET /static/js/theme.js 200 len=6006 hasLocalStorage=True hasDataTheme=True (comment: three-way system/light/dark, no FOUC) | PASS | `logs/browser_retry.log` THEME § |
| 9 | GET /nonexistent | Fetch error page | 404 | 404 status (Exception.Response 404), template `templates/404.html` exists (INVENTORY.md) | PASS | `logs/browser_retry.log` 404 § |
| 10 | GET /admin | Fetch anon admin gate | 303 redirect to /login | 303 Location=/login?next=/admin | PASS | `logs/browser_retry.log` admin § |

## Browser tool status
- `browser status` → enabled, chromium, Edge `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, cdpReady true, pageReady true, pid 21336 — but `navigate`/`open` to `http://127.0.0.1:8000/` → `browser navigation blocked by policy`, screenshot → same error. Fallback to fetch used for all rows. Screenshots: 0 saved of 2 attempted — BLOCKED by Gateway navigation policy (headless browser in isolated Windows agent session may be blocked from localhost; evidence via fetch HTML instead). Directory `evidence/screenshots/` exists, no new files. No claim of screenshot existence.
- Snapshot/console/requests/errors via browser: BLOCKED (no page loaded). Fetch-level failed requests: 0 among 9 routes.

## Coverage (this retry)
- Public: `/`, `/explore`, `/search?q=test`, `/blog`, `/community` + nav links — PASS (5 routes 200)
- Auth forms: `/login`, `/register` csrf_token hidden field — PASS
- Theme: `data-theme` attr + `js/theme.js` + `localStorage` — PASS
- Error pages: `/nonexistent` → 404 — PASS
- Admin gate: `/admin` anon → 303 `/login?next=/admin` — PASS

## Notes
- Only features that actually exist are tested (discovered via `INVENTORY.md` + live nav).
- Every important test records console errors + failed network requests where available — here via fetch; browser console/requests BLOCKED with reason above.
- Screenshots: attempted 2 (homepage, login), saved 0 — BLOCKED by policy, not file error.
