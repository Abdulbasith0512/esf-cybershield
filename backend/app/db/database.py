"""SQLAlchemy engine, session factory, and request dependency."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for future ORM models."""

    pass


def _build_engine(url: str | None = None):  # type: ignore[no-untyped-def]
    from app.core.config import get_settings

    db_url = url or str(get_settings().database_url)
    if db_url.startswith("sqlite"):
        return create_engine(db_url, pool_pre_ping=True, connect_args={"check_same_thread": False})
    if db_url.startswith("postgres"):
        # Storage convention is naive UTC everywhere. Pin the session time
        # zone so TIMESTAMPTZ columns interpret naive datetimes as UTC no
        # matter the server default. SQLite branch above is untouched.
        return create_engine(db_url, pool_pre_ping=True,
                             connect_args={"options": "-c timezone=UTC"})
    return create_engine(db_url, pool_pre_ping=True)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a request-scoped database session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
