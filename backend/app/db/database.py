"""SQLAlchemy engine, session factory, and request dependency."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for future ORM models."""

    pass


def _build_engine():  # type: ignore[no-untyped-def]
    settings = get_settings()
    return create_engine(str(settings.database_url), pool_pre_ping=True)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a request-scoped database session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
