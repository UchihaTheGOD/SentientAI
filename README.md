# SentientAI — Cybersecurity Training Platform

Interactive cybersecurity training platform with sandboxed labs, real-time attack detection, and AI-powered analysis architecture.

## Features

- **Sandboxed Labs** — SQL Injection, Stored/Reflected XSS (more coming)
- **Attack Detection** — Rule-based pattern matching engine
- **Educational Analysis** — Explains attacks, techniques, and defenses
- **Security Event Logging** — Every lab interaction is recorded
- **Training Data Pipeline** — Curate examples for CyberLLM fine-tuning
- **Admin Panel** — Review events, approve/reject training data, export JSONL
- **CyberLLM Integration** — Mock client ready for real model connection

## Quick Start

### 1. Clone & Navigate

```powershell
cd C:\Users\DARK\Desktop\SentientAI
```

### 2. Create Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure Environment

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set a strong `SECRET_KEY`:
```
SECRET_KEY=your-random-secret-key-here
ADMIN_SECRET=your-admin-registration-secret
```

### 5. Start the Server

```powershell
python run.py
```

The server starts at **http://127.0.0.1:8000**

### 6. Create an Account

1. Go to http://127.0.0.1:8000/register
2. Fill in username, email, password
3. To create an admin account, enter the `ADMIN_SECRET` value in the admin secret field
4. Log in at http://127.0.0.1:8000/login

### 7. Run Labs

1. Navigate to **Labs** from the dashboard
2. Select a lab (SQL Injection, Stored XSS, Reflected XSS)
3. Enter a payload and submit
4. View the detection result and educational analysis

### 8. Admin Panel

Access `/admin` (requires admin account) to:
- View all security events
- Review training examples
- Approve/reject for CyberLLM training
- Export approved data as JSONL

## Project Structure

```
sentientai/
├── app/
│   ├── main.py              # FastAPI app, middleware, router registration
│   ├── config.py             # Settings from environment variables
│   ├── database.py           # SQLAlchemy engine, session, Base
│   ├── api/                  # Route handlers
│   │   ├── auth.py           # Register, login, logout
│   │   ├── users.py          # Dashboard, profile
│   │   ├── labs.py           # Lab listing, detail, submission
│   │   ├── attacks.py        # Attack history, blocked page
│   │   ├── admin.py          # Admin dashboard, training management
│   │   └── health.py         # Health check
│   ├── models/               # SQLAlchemy models
│   │   ├── user.py
│   │   ├── security_event.py
│   │   └── training_example.py
│   ├── services/             # Business logic
│   │   ├── auth_service.py   # Password hashing, JWT, dependencies
│   │   ├── detection.py      # Rule-based attack detection engine
│   │   ├── analysis.py       # Analysis orchestrator
│   │   ├── cyberllm_client.py # CyberLLM interface + mock
│   │   └── training.py       # Training example CRUD + export
│   ├── labs/                 # Sandboxed lab implementations
│   │   ├── __init__.py       # Lab registry
│   │   ├── sql_injection.py  # SQL injection simulation
│   │   └── xss.py            # Stored + Reflected XSS simulation
│   ├── templates/            # Jinja2 HTML templates
│   └── static/               # CSS + JS
├── data/                     # SQLite database (created at runtime)
├── requirements.txt
├── .env.example
├── run.py
└── README.md
```

## CyberLLM Integration

The platform is designed for future CyberLLM/Sentinel integration.

**Current state:** `MockCyberLLMClient` provides structured analysis using detection engine output.

**To connect the real model:**

1. Set `CYBERLLM_API_URL` and `CYBERLLM_API_KEY` in `.env`
2. Implement `RealCyberLLMClient` in `app/services/cyberllm_client.py`
3. Update the factory function `get_cyberllm_client()` to return the real client

The interface:
```python
class CyberLLMClientInterface:
    def analyze_attack(self, event: dict) -> AttackAnalysis
    def classify_attack(self, event: dict) -> str
    def explain_attack(self, event: dict) -> str
    def generate_training_example(self, event: dict) -> dict
```

## Database

SQLite by default. To switch to PostgreSQL:

1. Install `psycopg2-binary`: `pip install psycopg2-binary`
2. Update `DATABASE_URL` in `.env`:
   ```
   DATABASE_URL=postgresql://user:password@localhost:5432/sentientai
   ```
3. Restart the server — tables are auto-created on startup.

## Security Notes

- Passwords are hashed with bcrypt
- Authentication uses JWT in httpOnly cookies
- All lab inputs are sandboxed — no real OS commands, filesystem access, or database queries
- Parameterized queries via SQLAlchemy
- Security headers applied via middleware
- Secrets stored in `.env` (never committed)

## API Health Check

```
GET /api/health
→ {"status": "ok", "service": "sentientai"}
```
