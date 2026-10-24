# ENVIRONMENT — SentientAI QA (2026-10-20)

Recorded 2026-10-20 IST (UTC+5:30). Secrets redacted as `***REDACTED***`.

## Host
- **OS:** Microsoft Windows 11 Pro, Version 10.0.26300, 64-bit
- **Hostname:** HOLA
- **Workspace:** `C:\Users\DARK\Desktop\wild clude\SentientAI`
- **Shell:** PowerShell

## Runtime
- **Framework:** FastAPI 0.115.6, Uvicorn 0.34.0 (standard)
- **Python (venv):** `venv/pyvenv.cfg` → Python 3.11.0 from `C:\Users\DARK\AppData\Local\Programs\Python\Python311\python.exe` — host `python`/`py` not on PATH for agent user U3-R6; server runs via existing Uvicorn process (PID 24608, also 9028/24840 python.exe present)
- **Database:** SQLite `sqlite:///./data/sentientai.db` — file `data/sentientai.db` 1,466,368 bytes at check
- **ORM:** SQLAlchemy 2.0.36, `check_same_thread=False` for SQLite
- **Templating:** Jinja2 3.1.5 + aiofiles 24.1.0
- **Auth:** passlib[argon2] 1.7.4, argon2-cffi, python-jose[cryptography] 3.3.0 (HS256), python-multipart 0.0.20
- **Config:** python-dotenv 1.0.1
- **Tests:** pytest 8.3.4, httpx 0.28.1, pytest.ini `testpaths = tests` `addopts = -q` (in-process throwaway SQLite via `tests/conftest.py`, no running server needed)

## Dependencies (requirements.txt)
```
fastapi==0.115.6
uvicorn[standard]==0.34.0
sqlalchemy==2.0.36
passlib[argon2]==1.7.4
argon2-cffi>=23.1.0
python-jose[cryptography]==3.3.0
python-dotenv==1.0.1
python-multipart==0.0.20
jinja2==3.1.5
aiofiles==24.1.0
```
Dev: `pytest==8.3.4`, `httpx==0.28.1`

## Server
- **URL:** `http://127.0.0.1:8000`
- **Health:** `GET /api/health` → `200 {"status":"ok","service":"sentientai"}` (verified live)
- **CSP (live header):** `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'`
- **Security headers (live):** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`, `Set-Cookie: csrf_token=...; HttpOnly`
- **Startup:** `run.py` → `uvicorn.run("app.main:app", host 127.0.0.1:8000, reload=True, reload_dirs=["app"])` — do NOT start a second server if healthy
- **Port:** `127.0.0.1:8000` LISTENING PID 24608

## Sentinel & Prompts
- **Checkpoints:** `local_models/sentinel/sentinel_best_model.pt` (~1.09 GB), `best_autolab_checkpoint.pt` (~1.09 GB)
- **Config:** `local_models/sentinel/config.json` (450 B), tokenizer `sentinel_tokenizer.json` (473700 B)
- **Prompt:** `prompts/prompt.txt` (2081 B), loader `app/services/sentinel_loader.py` (dual-checkpoint, background warm-load in lifespan, fail-open)
- **Prompt service:** `app/services/prompt_service.py` (PROMPT_PATH, MAX_LOG_CHARS, MAX_EXTRA_CHARS, validate_extra_prompt, build_analysis_prompt)

## Configuration (secrets redacted)
- `.env` keys: `SECRET_KEY=***REDACTED***`, `DATABASE_URL=sqlite:///./data/sentientai.db`, `CYBERLLM_API_URL=127.0.0.1:8000`, `CYBERLLM_API_KEY=***REDACTED***`, `ENVIRONMENT=development`, `ADMIN_SECRET=***REDACTED***`
- `app/config.py` Settings: `SECRET_KEY` (dev fallback `dev-insecure-key-change-me`), `DATABASE_URL`, `ALGORITHM HS256`, `ACCESS_TOKEN_EXPIRE_MINUTES 60`, `PASSWORD_RESET_TOKEN_EXPIRE 30`, `SMTP_*` (blank → log link in dev)

## Limitations
- Host `python`/`py` not on PATH for agent user; use venv python via full path or rely on running server
- No browser session active at scaffold (chromium managed, Edge detected) — UI testing requires `browser` tool start
- `.env` secrets must never appear in reports/screenshots/logs
- Tests must use synthetic accounts/data only; do not mutate real user data
- Do not run full pytest suite; targeted tests only
