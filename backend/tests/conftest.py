"""Shared fixtures: SQLite-backed app (no external DB needed for unit tests)."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.db.database import Base, get_db

import app.db.models  # noqa: F401 -- register tables


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", "")
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    from app.main import create_app

    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


@pytest.fixture()
def authed_client(client, monkeypatch):
    monkeypatch.setenv("INGEST_API_KEY", "test-key-123")
    get_settings.cache_clear()
    client.headers.update({"X-API-Key": "test-key-123"})
    yield client
    get_settings.cache_clear()


def make_event(**kw):
    base = {
        "event_id": f"evt-{uuid.uuid4().hex[:8]}",
        "timestamp": "2026-09-06T10:21:31Z",
        "event_type": "authentication",
        "source": "windows",
        "host": "WIN-042",
        "user": "john.doe",
        "source_ip": "192.168.1.20",
        "status": "failed",
        "raw_event": {"original_field": "original_value"},
    }
    base.update(kw)
    return base
