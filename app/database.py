"""SQLAlchemy database setup. SQLite now, Postgres-ready.

Schema management has two layers, both **non-destructive**:

* ``Base.metadata.create_all`` creates any *table* that does not yet exist,
  with its full, current set of columns.
* ``_run_migrations`` upgrades tables that already existed from an older
  release. SQLite's ``create_all`` never alters an existing table, so a column
  added to a model *after* the table was first created — for example
  ``users.password_hash`` on a database created before that column existed —
  would otherwise stay missing and every query touching it would fail with
  ``sqlite3.OperationalError: no such column``. The migration is *model-driven*:
  for each mapped table already in the database it adds every column the model
  declares but the table lacks. The source of truth is the models, so the
  upgrade can never "forget" a column.

``init_db`` never drops or deletes anything; the only destructive path is
``manage.py reset-db --yes``.
"""
from sqlalchemy import create_engine, inspect, text
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


def _safe_exec(conn, sql: str):
    """Run a statement, swallowing failures (used for idempotent ALTERs and
    value backfills so a re-run, or a column that already exists, is a no-op)."""
    try:
        conn.execute(text(sql))
        conn.commit()
    except Exception:
        conn.rollback()


def _sqlite_type(column, dialect) -> str:
    """The column's SQL type as this dialect emits it (VARCHAR(255), INTEGER,
    BOOLEAN, DATETIME, TEXT, ...). Falls back to TEXT — SQLite is dynamically
    typed, so an imperfect affinity is still safe."""
    try:
        return column.type.compile(dialect=dialect)
    except Exception:
        return "TEXT"


def _default_clause(column):
    """A SQL literal for a safe column DEFAULT, or ``None`` to add it without one.

    Only *scalar* model defaults are translated (booleans, numbers, plain
    strings), so an existing row gets a sensible value for columns like
    ``token_version`` (0) or ``status`` ('candidate'). Callable defaults
    (timestamps) and columns with no default are added without a DEFAULT.

    Every added column is nullable at the DDL level regardless of the model's
    ``nullable=False``: SQLite forbids adding a NOT NULL column without a
    default, and we cannot invent a value for a pre-existing row (there is no
    real password hash to backfill, for instance). New inserts still flow
    through the ORM, which enforces the model's NOT NULL constraint.
    """
    default = column.default
    if default is not None and getattr(default, "is_scalar", False):
        value = default.arg
        if isinstance(value, bool):            # bool before int: bool *is* an int
            return "1" if value else "0"
        if isinstance(value, (int, float)):
            return repr(value)
        if isinstance(value, str):
            return "'" + value.replace("'", "''") + "'"
    return None


def _add_missing_columns(conn, dialect, insp) -> None:
    """For every mapped table that already exists, add each column the model
    declares but the table is missing. This upgrades an old database to the
    current schema (this is what restores ``users.password_hash``). Tables that
    ``create_all`` just built already have every column, so they are skipped;
    tables in the database but not mapped by a model (legacy leftovers) are left
    untouched — nothing is dropped."""
    existing_tables = set(insp.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # create_all already built it with every current column
        present = {col["name"] for col in insp.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            ddl = (
                f'ALTER TABLE "{table.name}" '
                f'ADD COLUMN "{column.name}" {_sqlite_type(column, dialect)}'
            )
            default = _default_clause(column)
            if default is not None:
                ddl += f" DEFAULT {default}"
            _safe_exec(conn, ddl)


def _run_migrations(bind=None) -> None:
    """Safe, idempotent schema upgrade for existing databases. Never drops data.

    First add any column a model gained after its table was created, then run a
    few value backfills so legacy rows agree with the new columns.
    """
    target = bind or engine
    insp = inspect(target)
    with target.connect() as conn:
        _add_missing_columns(conn, target.dialect, insp)

        # ---- Backfills: give legacy rows values consistent with new columns ---
        # Legacy posts predate `status`; derive it from the `published` bool so
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


def init_db(bind=None) -> None:
    """Create every table, then upgrade any pre-existing table to the current
    schema. Import the models first so all tables are registered on ``Base``.

    Non-destructive: it never drops or deletes. Pass ``bind`` to target a
    specific engine (used by tests); production callers use the default engine.
    """
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
    target = bind or engine
    Base.metadata.create_all(bind=target)
    _run_migrations(target)
