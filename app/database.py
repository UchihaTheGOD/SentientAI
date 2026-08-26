"""SQLAlchemy database setup. SQLite now, Postgres-ready."""
from sqlalchemy import create_engine
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


def init_db():
    """Create all tables. Import models before calling this."""
    import app.models.user  # noqa: F401
    import app.models.security_event  # noqa: F401
    import app.models.training_example  # noqa: F401
    import app.models.blog_post  # noqa: F401
    Base.metadata.create_all(bind=engine)
