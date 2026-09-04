"""Regression tests for the schema upgrade path (app/database.py).

The bug these guard against: SQLAlchemy's ``create_all`` only creates *missing
tables* — it never alters an existing one. A ``users`` table created before the
``password_hash`` column existed therefore stayed without it, and every query
touching ``User`` failed with::

    sqlite3.OperationalError: no such column: users.password_hash

``init_db`` now runs a model-driven migration that adds any column a model
declares but an existing table lacks. These tests build a real legacy database
on a throwaway engine and prove the upgrade.
"""
from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from app.database import init_db
from app.models.user import User


def _engine(tmp_path, name: str):
    db_file = tmp_path / name
    return create_engine(
        f"sqlite:///{db_file.as_posix()}",
        connect_args={"check_same_thread": False},
    )


def _make_legacy_users_table(engine) -> None:
    """A ``users`` table shaped like an early release: no ``password_hash`` and
    none of the redesign columns (token_version, is_suspended, profile fields)."""
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE users ("
            "  id INTEGER PRIMARY KEY,"
            "  username VARCHAR(50) NOT NULL,"
            "  email VARCHAR(255) NOT NULL,"
            "  role VARCHAR(20) NOT NULL DEFAULT 'user',"
            "  is_active BOOLEAN DEFAULT 1,"
            "  created_at DATETIME"
            ")"
        ))
        conn.execute(text(
            "INSERT INTO users (username, email, role) "
            "VALUES ('legacy_user', 'legacy@example.com', 'user')"
        ))


def test_old_users_table_without_password_hash_is_upgraded(tmp_path):
    engine = _engine(tmp_path, "legacy.db")
    _make_legacy_users_table(engine)

    # Precondition: the column really is missing, so this test would reproduce
    # the reported OperationalError before the fix.
    before = {c["name"] for c in inspect(engine).get_columns("users")}
    assert "password_hash" not in before

    # The upgrade under test.
    init_db(bind=engine)

    after = {c["name"] for c in inspect(engine).get_columns("users")}
    # The reported-missing column is now present …
    assert "password_hash" in after
    # … along with every other column the current redesign introduced on users.
    for expected in (
        "token_version", "is_suspended", "suspension_reason", "suspended_at",
        "display_name", "bio", "website", "avatar_url",
    ):
        assert expected in after, f"migration did not add users.{expected}"

    # Existing data is preserved, and the query that powers the homepage
    # (SELECT ... users.password_hash ...) no longer raises.
    with Session(engine) as session:
        rows = session.query(User).all()
        assert len(rows) == 1
        legacy = rows[0]
        assert legacy.username == "legacy_user"
        # A row that predates password_hash gets NULL — it simply cannot sign in
        # until a reset sets a real hash. That is the safe outcome.
        assert legacy.password_hash is None

    engine.dispose()


def test_upgraded_table_accepts_new_users(tmp_path):
    """After the upgrade the table is fully usable: a new account with a real
    hash inserts and reads back through the ORM."""
    engine = _engine(tmp_path, "legacy2.db")
    _make_legacy_users_table(engine)
    init_db(bind=engine)

    with Session(engine) as session:
        session.add(User(
            username="fresh_user",
            email="fresh@example.com",
            password_hash="$argon2id$v=19$m=19456,t=2,p=1$placeholderhash",
            role="user",
        ))
        session.commit()
        created = session.query(User).filter(User.username == "fresh_user").one()
        assert created.password_hash.startswith("$argon2id$")
        assert created.token_version == 0        # scalar default backfilled
        assert created.is_suspended in (False, 0)

    engine.dispose()


def test_migration_is_idempotent(tmp_path):
    """Running the upgrade twice is a no-op the second time — no error, no
    duplicate columns."""
    engine = _engine(tmp_path, "legacy3.db")
    _make_legacy_users_table(engine)

    init_db(bind=engine)
    cols_first = [c["name"] for c in inspect(engine).get_columns("users")]
    init_db(bind=engine)
    cols_second = [c["name"] for c in inspect(engine).get_columns("users")]

    assert cols_first == cols_second
    assert len(cols_second) == len(set(cols_second))  # no duplicates
    engine.dispose()


def test_fresh_empty_database_has_full_user_schema(tmp_path):
    """The other half of requirement #10: a brand-new database gets the complete
    current schema straight from create_all."""
    engine = _engine(tmp_path, "fresh.db")
    init_db(bind=engine)

    cols = {c["name"] for c in inspect(engine).get_columns("users")}
    assert {"password_hash", "token_version", "is_suspended", "display_name"} <= cols
    engine.dispose()
