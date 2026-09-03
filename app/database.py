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


def _safe_exec(conn, sql: str):
    """Run a statement, swallowing failures (used for idempotent backfills)."""
    try:
        conn.execute(text(sql))
        conn.commit()
    except Exception:
        conn.rollback()


def _run_migrations():
    """Safe, idempotent schema migrations for existing databases.

    Only used to add columns to tables that SQLAlchemy create_all won't
    touch because the table already exists. Never drops data.
    """
    with engine.connect() as conn:
        # User profile fields
        _safe_add_column(conn, "users", "display_name", "VARCHAR(100)")
        _safe_add_column(conn, "users", "display_name", "VARCHAR(100)")
        _safe_add_column(conn, "users", "bio", "TEXT")
        _safe_add_column(conn, "users", "website", "VARCHAR(255)")
        _safe_add_column(conn, "users", "avatar_url", "VARCHAR(500)")

        # Phase 2 migrations: BlogPost enhancements
        _safe_add_column(conn, "blog_posts", "user_id", "INTEGER")
        _safe_add_column(conn, "blog_posts", "views", "INTEGER DEFAULT 0")
        _safe_add_column(conn, "blog_posts", "excerpt", "TEXT")

        # ---- Redesign migrations ----------------------------------------
        # Post lifecycle (draft / published / archived) + moderation hide.
        _safe_add_column(conn, "blog_posts", "status", "VARCHAR(20) DEFAULT 'draft'")
        _safe_add_column(conn, "blog_posts", "published_at", "DATETIME")
        _safe_add_column(conn, "blog_posts", "is_hidden", "BOOLEAN DEFAULT 0")
        _safe_add_column(conn, "blog_posts", "hidden_reason", "VARCHAR(255)")

        # Account suspension, kept separate from is_active.
        _safe_add_column(conn, "users", "is_suspended", "BOOLEAN DEFAULT 0")
        _safe_add_column(conn, "users", "suspension_reason", "VARCHAR(255)")
        _safe_add_column(conn, "users", "suspended_at", "DATETIME")

        # Session invalidation counter (User.token_version / auth_service).
        _safe_add_column(conn, "users", "token_version", "INTEGER DEFAULT 0")

        # Comment moderation hide, distinct from the author's own delete.
        _safe_add_column(conn, "comments", "is_hidden", "BOOLEAN DEFAULT 0")
        _safe_add_column(conn, "comments", "hidden_reason", "VARCHAR(255)")

        # Training pipeline: review lifecycle, provenance, dedup, split.
        for column, coltype in (
            ("status", "VARCHAR(20) DEFAULT 'candidate'"),
            ("quality_score", "INTEGER DEFAULT 0"),
            ("quality_notes", "TEXT"),
            ("quality_band", "VARCHAR(10)"),
            ("model_prediction", "VARCHAR(80)"),
            ("human_label", "VARCHAR(80)"),
            ("safe_to_train", "BOOLEAN DEFAULT 0"),
            ("dedup_hash", "VARCHAR(64)"),
            ("split", "VARCHAR(10) DEFAULT 'train'"),
            ("provenance", "VARCHAR(60) DEFAULT 'moderation_flag'"),
            ("review_note", "TEXT"),
            ("reviewed_at", "DATETIME"),
            ("updated_at", "DATETIME"),
        ):
            _safe_add_column(conn, "training_examples", column, coltype)

        # ---- Backfills ---------------------------------------------------
        # Legacy rows predate `status`; derive it from the `published` bool so
        # `BlogPost.state` and the new queries agree with what users already see.
        _safe_exec(conn, "UPDATE blog_posts SET status='published' "
                         "WHERE (status IS NULL OR status='') AND published=1")
        _safe_exec(conn, "UPDATE blog_posts SET status='draft' "
                         "WHERE (status IS NULL OR status='') AND (published=0 OR published IS NULL)")
        _safe_exec(conn, "UPDATE blog_posts SET published_at=created_at "
                         "WHERE published_at IS NULL AND status='published'")
        _safe_exec(conn, "UPDATE blog_posts SET is_hidden=0 WHERE is_hidden IS NULL")
        _safe_exec(conn, "UPDATE users SET is_suspended=0 WHERE is_suspended IS NULL")
        _safe_exec(conn, "UPDATE users SET token_version=0 WHERE token_version IS NULL")
        _safe_exec(conn, "UPDATE comments SET is_hidden=0 WHERE is_hidden IS NULL")
        # Existing approved/pending examples map onto the new review lifecycle.
        _safe_exec(conn, "UPDATE training_examples SET status='approved', safe_to_train=1 "
                         "WHERE (status IS NULL OR status='') AND approved=1")
        _safe_exec(conn, "UPDATE training_examples SET status='candidate', safe_to_train=0 "
                         "WHERE (status IS NULL OR status='') AND (approved=0 OR approved IS NULL)")
        _safe_exec(conn, "UPDATE training_examples SET split='train' WHERE split IS NULL OR split=''")
        _safe_exec(conn, "UPDATE training_examples SET provenance='moderation_flag' "
                         "WHERE provenance IS NULL OR provenance=''")


def init_db():
    """Create all tables. Import models before calling this."""
    import app.models.user  # noqa: F401
    import app.models.password_reset  # noqa: F401
    import app.models.training_example  # noqa: F401
    import app.models.blog_post  # noqa: F401
    import app.models.activity  # noqa: F401
    import app.models.tag  # noqa: F401
    import app.models.social  # noqa: F401
    import app.models.message  # noqa: F401
    import app.models.moderation  # noqa: F401
    import app.models.audit  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _run_migrations()


