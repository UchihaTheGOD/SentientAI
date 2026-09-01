"""SentientAI management CLI — user role management.

Usage:
    python manage.py create-admin --username X --email Y --password Z
    python manage.py set-role --username X --role tester
    python manage.py list-users
"""
import argparse
import sys
from app.database import SessionLocal, init_db
from app.models.user import User
from app.services.auth_service import hash_password


VALID_ROLES = ("user", "tester", "admin")


def create_admin(args):
    """Create a new admin user."""
    init_db()
    db = SessionLocal()
    try:
        existing = db.query(User).filter(
            (User.username == args.username) | (User.email == args.email)
        ).first()
        if existing:
            print(f"[ERROR] User already exists: {existing.username} ({existing.email})")
            sys.exit(1)

        user = User(
            username=args.username,
            email=args.email,
            password_hash=hash_password(args.password),
            role="admin",
        )
        db.add(user)
        db.commit()
        print(f"[OK] Admin user created: {args.username} ({args.email})")
    finally:
        db.close()


def set_role(args):
    """Change the role of an existing user."""
    if args.role not in VALID_ROLES:
        print(f"[ERROR] Invalid role: {args.role}. Valid: {', '.join(VALID_ROLES)}")
        sys.exit(1)

    init_db()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == args.username).first()
        if not user:
            print(f"[ERROR] User not found: {args.username}")
            sys.exit(1)

        old_role = user.role
        user.role = args.role
        db.commit()
        print(f"[OK] {args.username}: {old_role} -> {args.role}")
    finally:
        db.close()


def list_users(args):
    """List all users with their roles."""
    init_db()
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id).all()
        if not users:
            print("No users found.")
            return

        print(f"{'ID':<6} {'Username':<20} {'Email':<30} {'Role':<10} {'Active':<8}")
        print("-" * 74)
        for u in users:
            print(f"{u.id:<6} {u.username:<20} {u.email:<30} {u.role:<10} {u.is_active!s:<8}")
    finally:
        db.close()


def seed_blog(args):
    """Seed placeholder blog posts."""
    init_db()
    db = SessionLocal()
    try:
        from app.models.blog_post import BlogPost
        existing = db.query(BlogPost).count()
        if existing > 0:
            print(f"[SKIP] {existing} blog posts already exist.")
            return

        posts = [
            BlogPost(
                slug="understanding-stored-xss",
                title="Understanding Stored XSS: From Injection to Impact",
                author="SentientAI Team",
                category="Web Security",
                summary="A practical walkthrough of how stored cross-site scripting works, what makes it dangerous, and how to build detection for it.",
                content="""Cross-site scripting remains one of the most prevalent web vulnerabilities. In this article, we walk through how stored XSS works using a controlled lab environment.

## What is Stored XSS?

Stored XSS occurs when an attacker's payload is persisted by the application — typically in a database, message forum, comment field, or similar storage mechanism — and later rendered to other users without proper sanitization.

Unlike reflected XSS, stored XSS does not require the victim to click a crafted link. The payload executes automatically when any user views the affected page.

## The Attack Surface

Common injection points include:
- User profile fields (display name, bio)
- Comment and review systems
- Forum posts and messages
- File upload filenames
- Support ticket descriptions

## Detection Approach

Effective detection combines multiple signals:

1. **Input analysis** — Pattern matching for known XSS vectors (`<script>`, event handlers, javascript: URIs)
2. **Context analysis** — Understanding where the input will be rendered (HTML body, attribute, JavaScript context)
3. **Behavioral analysis** — Monitoring for unusual DOM modifications or network requests after page load

## Lab Exercise

Our Stored XSS lab demonstrates this vulnerability in a controlled environment. The lab uses an in-memory comment system that intentionally renders user input without escaping.

*This is a placeholder article. Real content will replace this as the platform develops.*""",
                reading_time=6,
                published=True,
            ),
            BlogPost(
                slug="sql-injection-fundamentals",
                title="SQL Injection Fundamentals: What Every Developer Should Know",
                author="SentientAI Team",
                category="Vulnerability Research",
                summary="A foundational guide to SQL injection — how it works, why parameterized queries matter, and what detection looks like from the defender's perspective.",
                content="""SQL injection has been a top vulnerability for over two decades. Despite well-known mitigations, it continues to appear in production applications.

## How SQL Injection Works

SQL injection exploits occur when user input is concatenated directly into SQL query strings without parameterization or proper escaping.

Consider a login form that constructs a query like:

```
SELECT * FROM users WHERE username = '{input}'
```

An attacker can supply input like `' OR '1'='1` to bypass authentication logic entirely.

## Categories of SQL Injection

1. **In-band (Classic)** — Results are returned directly in the application response
2. **Blind** — The application doesn't return query results, but the attacker can infer information from response differences
3. **Out-of-band** — Data is exfiltrated through a different channel (DNS, HTTP requests to attacker-controlled servers)

## The Defense

The primary defense is straightforward: **use parameterized queries**.

```python
# Vulnerable
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# Safe
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

Additional layers include:
- Input validation (allowlisting expected patterns)
- Web Application Firewalls (WAF)
- Least-privilege database accounts
- Monitoring for anomalous query patterns

## Detection Engineering

From a detection perspective, SQL injection attempts produce observable signals:
- Unusual characters in form fields (quotes, semicolons, comment sequences)
- SQL keywords in unexpected contexts (UNION, SELECT, DROP)
- Time-based anomalies (SLEEP, BENCHMARK calls causing response delays)

*This is a placeholder article. Real content will replace this as the platform develops.*""",
                reading_time=7,
                published=True,
            ),
            BlogPost(
                slug="building-a-detection-pipeline",
                title="Building a Detection Pipeline: From Raw Events to Actionable Alerts",
                author="SentientAI Team",
                category="Detection Engineering",
                summary="How SentientAI processes security events through deterministic detection, model-based analysis, and human review to generate reliable intelligence.",
                content="""Detection engineering is the practice of designing, building, and maintaining systems that identify security threats. In SentientAI, we approach detection as a pipeline with multiple stages.

## The Pipeline

```
Event → Collector → Detector → Analyzer → Knowledge
```

Each stage adds context and confidence to the raw event data.

### Stage 1: Event Collection

Every interaction within a lab generates structured telemetry:
- HTTP method and path
- Sanitized request metadata
- Timestamp and session context
- User and lab identifiers

### Stage 2: Deterministic Detection

Pattern-based rules provide the first layer of analysis. These rules match known attack signatures — SQL injection patterns, XSS vectors, path traversal sequences — with high precision but limited coverage of novel attacks.

### Stage 3: Model Analysis

The Sentinel model (currently SentinelSmolLM2-360M) provides contextual analysis that goes beyond pattern matching. It can:
- Classify attack techniques
- Explain what was observed
- Distinguish between observed facts and inferences
- Identify gaps in evidence

### Stage 4: Knowledge Generation

When an attack is detected and analyzed, the system generates a knowledge candidate — a structured lesson that captures what happened and what was learned. These candidates require human review before becoming part of the knowledge base.

## Why Multiple Stages?

No single detection method is sufficient:
- Pattern matching is fast but brittle
- ML models are flexible but can hallucinate
- Human review is accurate but doesn't scale

The pipeline combines these approaches, using each stage's strengths to compensate for others' weaknesses.

*This is a placeholder article. Real content will replace this as the platform develops.*""",
                reading_time=5,
                published=True,
            ),
        ]

        for post in posts:
            db.add(post)
        db.commit()
        print(f"[OK] Created {len(posts)} seed blog posts.")
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="SentientAI Management CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # create-admin
    p_create = subparsers.add_parser("create-admin", help="Create an admin user")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--email", required=True)
    p_create.add_argument("--password", required=True)
    p_create.set_defaults(func=create_admin)

    # set-role
    p_role = subparsers.add_parser("set-role", help="Change a user's role")
    p_role.add_argument("--username", required=True)
    p_role.add_argument("--role", required=True, choices=VALID_ROLES)
    p_role.set_defaults(func=set_role)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List all users")
    p_list.set_defaults(func=list_users)

    # seed-blog
    p_seed = subparsers.add_parser("seed-blog", help="Create placeholder blog posts")
    p_seed.set_defaults(func=seed_blog)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
