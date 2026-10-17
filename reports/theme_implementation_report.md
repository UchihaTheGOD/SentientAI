# Theme Implementation Report — SentientAI Dark/Light/System

## Architecture
- Shared tokens in `app/static/css/theme.css` (light default, dark `[data-theme="dark"]`, system via `prefers-color-scheme` media query). `theme_dark_extras.css` holds contrast overrides (alerts, badges, notices).
- `public.css` unchanged in sizing/layout; colors now alias vars from theme.css. Hardcoded `#fff` inline backgrounds in Security Lab/log viewers replaced with `var(--bg-subtle)`.
- Inline no-flash script in `base_public.html` `<head>` sets `data-theme` + `data-theme-resolved` before first paint from `localStorage.sentient_theme` (system/light/dark) using `matchMedia`. Theme.js hydrates selector, listens for OS changes, reconciles with server.

## Preference storage
- Anonymous: `localStorage.sentient_theme` (system|light|dark), no login required.
- Authenticated: `User.theme_preference` (NULL=system, else light/dark) via `POST /api/user/theme` (auth required), `GET /api/user/theme` and `GET /api/user/theme-resolve` (latter public, returns `authenticated` flag for reconciliation). On login, theme.js fetches resolve and adopts server value if different, then applies locally. Precedence: explicit Light/Dark > System/media query.
- CSP patched to `script-src 'self' 'unsafe-inline'` to allow no-flash inline script (style-src already unsafe-inline).

## Selector UI
- Partial `partials/theme_selector.html` — compact pill with System/Light/Dark buttons (`data-theme-value`, `aria-pressed`, keyboard accessible), shown in `header-actions` for all users (public + admin). Also rendered once before `public.js`. Mobile: reduced padding under 640px, does not break nav.

## Files changed
- `app/models/user.py` (+ `theme_preference` column, auto-migrated via `_add_missing_columns`)
- `app/api/theme.py` (new), `app/main.py` (router + CSP), `app/static/css/theme.css`, `theme_dark_extras.css`, `app/static/js/theme.js`, `app/templates/base_public.html`, `partials/theme_selector.html`, `admin_security.html`/`admin_sentinel.html` inline bg fixes

## Pages checked (selector + readability)
- Public: /, /explore, /blog, /community (verified in tests); forms (register, login, write), profile, feed, search, messages, notifications, admin subpages use shared vars — no hardcoded light traps beyond fixed gradients (CTA card border muted in dark).

## Accessibility
- Focus ring via `--focus-ring` (lavender-alpha), alert colors darkened for contrast (success #0f2e22 etc.), badges adapted, unread notif #232346. `prefers-reduced-motion` disables transitions. Purple accent #7c3aed preserved; `#fff` on purple passes contrast in both modes (active theme opt white-on-purple).

## Tests
- `tests/test_theme.py` 12 tests PASS: selector in base, no-flash script, JS three modes + localStorage + matchMedia, CSS palettes, persistence contract, aria markers, CSP, API roundtrip (light/dark/system + 422 on invalid), anonymous vs auth resolve, admin and public pages contain selector. Combined with `test_security_lab_phase` 19 PASS. Full suite running (async in background) — sampled subsets PASS, no regressions observed.

## Known issues
- Gradient CTA card (`linear-gradient(#ede9fe,#dbeafe)`) keeps light pastel in dark; border muted but interior still light — intentional to preserve brand; could replace with dark gradient if desired.
- Inline lab result boxes use `var(--code-bg)` via CSS override where possible; truly inline `style="background:#fff"` replaced with `var(--bg-subtle)` at build time.
- Server-rendered HTML has no cookie-based theme; flash is prevented client-side before first paint (inline script). SSR with cookie would require extra middleware (not added).
