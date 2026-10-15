"""10-category controlled demo harness: real app routes only.

Each case hits the real app via TestClient/fetch and returns evidence.
Ground truth is the app's actual HTTP response; Sentinel judgment is separate.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

CASES: list[dict[str, Any]] = [
    # category, id, method/path, payload description, expected app behaviour
    {"case_id": "sqli-01", "category": "sqli", "title": "SQLi indicator probe (search)",
     "method": "GET", "path": "/search?q='\" ATTACT", "ground_truth": "defended - parameterized query, no SQL disclosed",
     "expected_status": 200},
    {"case_id": "xss-01", "category": "xss", "title": "XSS canary reflection (search)",
     "method": "GET", "path": "/search?q=ATTACT-XSS-CANARY-9f3a1b<script>alert(1)</script>", "ground_truth": "defended - output escaped",
     "expected_status": 200},
    {"case_id": "traversal-01", "category": "traversal", "title": "Path traversal rejection",
     "method": "GET", "path": "/static/../../etc/passwd", "ground_truth": "defended - normalized / 404",
     "expected_status": 404},
    {"case_id": "auth-01", "category": "auth", "title": "Auth: bad password rejected",
     "method": "POST", "path": "/login", "payload": {"username": "demo_auth_user", "password": "wrong"},
     "ground_truth": "defended - 401/redirect with error", "expected_status": 303},
    {"case_id": "access-01", "category": "access", "title": "Access control: /admin requires admin",
     "method": "GET", "path": "/admin", "ground_truth": "defended - 303/403 for anonymous",
     "expected_status": 303},
    {"case_id": "csrf-01", "category": "csrf", "title": "CSRF missing token rejected",
     "method": "POST", "path": "/api/sentinel/analyze", "ground_truth": "defended - 403 CSRF",
     "expected_status": 403},
    {"case_id": "methods-01", "category": "methods", "title": "HTTP methods: OPTIONS/TRACE handling",
     "method": "OPTIONS", "path": "/", "ground_truth": "benign - safe methods allowed, dangerous not",
     "expected_status": 200},
    {"case_id": "rate-01", "category": "rate-limit", "title": "Rate limit: repeated logins throttled",
     "method": "POST", "path": "/login", "ground_truth": "defended - 429 after threshold",
     "expected_status": 429},
    {"case_id": "headers-01", "category": "headers-cookies", "title": "Security headers & cookie flags",
     "method": "GET", "path": "/", "ground_truth": "defended when headers present",
     "expected_status": 200},
    {"case_id": "info-01", "category": "info-disclosure", "title": "Info disclosure: /.env not exposed",
     "method": "GET", "path": "/.env", "ground_truth": "defended - 404",
     "expected_status": 404},
]


def get_case(case_id: str) -> dict | None:
    for c in CASES:
        if c["case_id"] == case_id:
            return c
    return None


def catalog() -> list[dict]:
    return [dict(c) for c in CASES]
