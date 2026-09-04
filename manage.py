"""SentientAI management CLI — user and database administration.

Usage:
    python manage.py create-admin --username X --email Y --password Z
    python manage.py set-role --username X --role admin
    python manage.py list-users
    python manage.py seed-admin              # create the initial admin (idempotent)
    python manage.py remove-all-users        # delete every non-admin account
    python manage.py reset-db --yes          # DESTRUCTIVE: drop, recreate, seed one admin
"""
import argparse
import sys
from app.database import SessionLocal, init_db
from app.models.user import User
from app.services.auth_service import hash_password


VALID_ROLES = ("user", "admin")

# The initial administrator. These are the project's fixed bootstrap credentials;
# change the password after first sign-in in any real deployment.
INITIAL_ADMIN_USERNAME = "admin"
INITIAL_ADMIN_EMAIL = "admin@12345"
INITIAL_ADMIN_PASSWORD = "admin@12345"


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


def _get_or_create_user(db, username, email, display_name, bio):
    """Fetch a seed author, creating it as a normal user if absent."""
    user = db.query(User).filter(User.username == username).first()
    if user:
        return user
    user = User(
        username=username,
        email=email,
        password_hash=hash_password("ChangeMe123!"),
        role="user",
        is_active=True,
        display_name=display_name,
        bio=bio,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def seed_blog(args):
    """Seed a few example blog posts, authored by real seed users."""
    init_db()
    db = SessionLocal()
    try:
        from app.models.blog_post import POST_PUBLISHED, BlogPost

        existing = db.query(BlogPost).count()
        if existing > 0:
            print(f"[SKIP] {existing} blog posts already exist.")
            return

        maya = _get_or_create_user(
            db, "maya", "maya@example.com", "Maya Chen",
            "Backend engineer who writes about clean, readable code.",
        )
        devon = _get_or_create_user(
            db, "devon", "devon@example.com", "Devon Park",
            "Designer and writer interested in typography and the craft of the web.",
        )

        specs = [
            dict(
                author=maya,
                slug="getting-started-with-python-type-hints",
                title="Getting Started with Python Type Hints",
                category="Programming",
                summary="Type hints make Python easier to read and safer to change. A gentle, practical introduction for everyday code.",
                reading_time=6,
                content="""Type hints have quietly become one of the best things about modern Python. They don't change how your program runs, but they change how it reads — and how confidently you can change it later.

## What a type hint is

A type hint is an annotation that says what kind of value a name is expected to hold:

```python
def greet(name: str) -> str:
    return f"Hello, {name}!"
```

The `: str` and `-> str` tell a reader — and your editor — that `greet` takes a string and returns one. Python itself does not enforce this at runtime; the value is documentation that tools can check.

## Why bother

- **Editors get smarter.** Autocomplete and inline errors work far better when your functions describe their inputs and outputs.
- **Refactoring gets safer.** Rename a field or change a return type and a checker points at every place that needs updating.
- **Code reviews get shorter.** A signature that says what it accepts answers half the questions before they're asked.

## Start small

You don't have to annotate everything at once. Add hints to the functions at the edges of your modules first — the ones other code calls most — and let the value grow from there.

*This is an example post included with the starter database.*""",
            ),
            dict(
                author=devon,
                slug="designing-for-readability-typography-on-the-web",
                title="Designing for Readability: Typography on the Web",
                category="Design",
                summary="Good typography is invisible. A short field guide to line length, spacing, and contrast that makes long-form writing comfortable to read.",
                reading_time=5,
                content="""Most reading on the web is long-form, and most long-form pages are harder to read than they need to be. A handful of typographic choices do most of the work.

## Line length

Aim for roughly 60–75 characters per line. Much longer and the eye loses its place returning to the next line; much shorter and the rhythm breaks. A simple `max-width` on your text column is usually all it takes.

## Space is not empty

Generous line height (around 1.5–1.7 for body text) and clear spacing between paragraphs give the eye somewhere to rest. Crowded text feels like work before a word is read.

## Contrast, carefully

Pure black on pure white can feel harsh. A very dark grey on a soft off-white is often calmer while still meeting contrast guidelines. Always check your colours against an accessibility contrast checker.

## Hierarchy over decoration

Readers scan before they read. Distinct heading sizes, and restraint everywhere else, let people find their place without any visual noise.

*This is an example post included with the starter database.*""",
            ),
            dict(
                author=maya,
                slug="writing-tests-you-will-actually-keep",
                title="Writing Tests You'll Actually Keep",
                category="Programming",
                summary="Tests earn their keep when they describe behaviour, not implementation. How to write a suite that helps you change code instead of fighting it.",
                reading_time=7,
                content="""A test suite is only worth having if you trust it and don't dread it. The difference usually comes down to what the tests are actually checking.

## Test behaviour, not internals

A good test reads like a small story about what the code does for its user: given this input, you get that result. When a test asserts on private helpers or exact call order, every refactor breaks it — even when nothing a user cares about changed.

## One clear reason to fail

When a test fails, its name and its single focus should tell you what broke. A test that checks five things at once makes you debug the test before you can debug the code.

## Make the setup obvious

Shared fixtures are helpful until they hide what a test depends on. Keep the arrange step close enough that a reader can see the whole picture without scrolling through layers of setup.

## Keep them fast

A suite that runs in seconds gets run constantly; one that takes minutes gets skipped exactly when it matters. Prefer in-memory data and avoid the network wherever you can.

*This is an example post included with the starter database.*""",
            ),
        ]

        posts = []
        for spec in specs:
            author = spec.pop("author")
            post = BlogPost(author=author.display, user_id=author.id, **spec)
            post.apply_state(POST_PUBLISHED)
            posts.append(post)
            db.add(post)
        db.commit()
        print(f"[OK] Created {len(posts)} seed blog posts by 2 example authors.")
    finally:
        db.close()


def seed_admin(args):
    """Create the initial administrator if it does not already exist.

    Idempotent: if an account with the admin username already exists it is left
    untouched (its password is not reset), so running this on an existing
    database is safe.
    """
    init_db()
    db = SessionLocal()
    try:
        existing = db.query(User).filter(
            User.username == INITIAL_ADMIN_USERNAME
        ).first()
        if existing:
            print(f"[SKIP] Admin '{INITIAL_ADMIN_USERNAME}' already exists (id={existing.id}).")
            return
        admin = User(
            username=INITIAL_ADMIN_USERNAME,
            email=INITIAL_ADMIN_EMAIL,
            password_hash=hash_password(INITIAL_ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"[OK] Initial admin created: {INITIAL_ADMIN_USERNAME} ({INITIAL_ADMIN_EMAIL})")
    finally:
        db.close()


def remove_all_users(args):
    """Delete every non-admin account and its data. Admins are preserved."""
    from app.services import admin_service

    init_db()
    db = SessionLocal()
    try:
        removed = admin_service.remove_all_normal_users(db)
        print(f"[OK] Removed {removed} non-admin account(s). Administrators preserved.")
    finally:
        db.close()


def reset_db(args):
    """DESTRUCTIVE: drop every table, recreate the schema, seed exactly one admin.

    This is the development "start over" button. It refuses to run without an
    explicit --yes so it can't wipe a database by reflex.
    """
    if not args.yes:
        print("[ABORT] reset-db is destructive. Re-run with --yes to confirm.")
        sys.exit(1)

    from app.database import Base, engine

    # init_db() imports every model module, and that import is what registers
    # each table on Base.metadata. Running it first guarantees drop_all() sees
    # the whole schema — otherwise it would only drop the handful of tables
    # already imported and silently leave the rest behind.
    init_db()
    print("[..] Dropping all tables…")
    Base.metadata.drop_all(bind=engine)
    print("[..] Recreating schema…")
    init_db()

    db = SessionLocal()
    try:
        admin = User(
            username=INITIAL_ADMIN_USERNAME,
            email=INITIAL_ADMIN_EMAIL,
            password_hash=hash_password(INITIAL_ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"[OK] Database reset. Single admin: {INITIAL_ADMIN_USERNAME} ({INITIAL_ADMIN_EMAIL})")
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

    # seed-admin
    p_seed_admin = subparsers.add_parser(
        "seed-admin", help="Create the initial admin account (idempotent)")
    p_seed_admin.set_defaults(func=seed_admin)

    # remove-all-users
    p_remove = subparsers.add_parser(
        "remove-all-users", help="Delete every non-admin account and its data")
    p_remove.set_defaults(func=remove_all_users)

    # reset-db
    p_reset = subparsers.add_parser(
        "reset-db", help="DESTRUCTIVE: drop, recreate, and seed one admin")
    p_reset.add_argument("--yes", action="store_true", help="Confirm the destructive reset")
    p_reset.set_defaults(func=reset_db)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
