"""SQLAlchemy database setup. SQLite now, Postgres-ready."""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

# For SQLite we need check_same_thread=False
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session, closes after request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _safe_add_column(conn, table: str, column: str, col_type: str):
    """Idempotent ALTER TABLE ADD COLUMN — ignores if column already exists."""
    try:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
        conn.commit()
    except Exception:
        conn.rollback()


def _run_migrations():
    """Safe, idempotent schema migrations for existing databases.

    Only used to add columns to tables that SQLAlchemy create_all won't
    touch because the table already exists. Never drops data.
    """
    with engine.connect() as conn:
        # Phase 1 migration: session_id on security_events
        _safe_add_column(conn, "security_events", "session_id", "TEXT")

        # Phase 2 migrations: User profile fields
        _safe_add_column(conn, "users", "display_name", "VARCHAR(100)")
        _safe_add_column(conn, "users", "bio", "TEXT")
        _safe_add_column(conn, "users", "website", "VARCHAR(255)")
        _safe_add_column(conn, "users", "avatar_url", "VARCHAR(500)")

        # Phase 2 migrations: BlogPost enhancements
        _safe_add_column(conn, "blog_posts", "user_id", "INTEGER")
        _safe_add_column(conn, "blog_posts", "views", "INTEGER DEFAULT 0")
        _safe_add_column(conn, "blog_posts", "excerpt", "TEXT")


def init_db():
    """Create all tables. Import models before calling this."""
    import app.models.user  # noqa: F401
    import app.models.security_event  # noqa: F401
    import app.models.training_example  # noqa: F401
    import app.models.blog_post  # noqa: F401
    import app.models.lab_session  # noqa: F401
    import app.models.activity  # noqa: F401
    import app.models.tag  # noqa: F401
    import app.models.social  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _run_migrations()


