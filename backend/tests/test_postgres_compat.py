"""PostgreSQL deployment compatibility. No live server required.

Guards the additive PG path: URL detection, engine connect_args split,
portable migrations, and assumption-free seed code. The normal suite keeps
running on SQLite; nothing here connects anywhere.
"""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from alembic.script import ScriptDirectory  # noqa: E402
from alembic.config import Config  # noqa: E402

from app.db import database  # noqa: E402

PG_URL = "postgresql+psycopg://user:pass@localhost:5432/esf"
PG_PLAIN_URL = "postgresql://user:pass@localhost:5432/esf"
SQLITE_URL = "sqlite:///./esf_incidents.db"
SQLITE_ABS_URL = "sqlite:////data/esf.db"

SQLITE_ONLY_MARKERS = ("PRAGMA", "pragma", "sqlite_master", "sqlite_sequence",
                       "VACUUM", "vacuum", "AUTOINCREMENT", "autoincrement",
                       "check_same_thread", "rowid")


def _captured_engine(monkeypatch):
    calls = []

    def fake_create_engine(url, **kwargs):
        calls.append((url, kwargs))
        raise RuntimeError("no connections in compatibility tests")

    monkeypatch.setattr(database, "create_engine", fake_create_engine)
    return calls


def test_sqlite_keeps_thread_args(monkeypatch):
    calls = _captured_engine(monkeypatch)
    for url in (SQLITE_URL, SQLITE_ABS_URL, "sqlite://"):
        try:
            database._build_engine(url)
        except RuntimeError:
            pass
    assert len(calls) == 3
    for url, kwargs in calls:
        assert kwargs.get("connect_args") == {"check_same_thread": False}, url
        assert "options" not in kwargs.get("connect_args", {})


def test_postgres_gets_utc_without_sqlite_args(monkeypatch):
    calls = _captured_engine(monkeypatch)
    for url in (PG_URL, PG_PLAIN_URL):
        try:
            database._build_engine(url)
        except RuntimeError:
            pass
    assert len(calls) == 2
    for url, kwargs in calls:
        connect_args = kwargs.get("connect_args", {})
        assert "check_same_thread" not in connect_args, url
        assert connect_args.get("options") == "-c timezone=UTC", url
    # Unknown schemes keep the previous default behavior (no connect_args).
    try:
        database._build_engine("custom://host/db")
    except RuntimeError:
        pass
    assert calls[-1][1].get("connect_args") is None


def _migration_sources():
    versions = BACKEND / "alembic" / "versions"
    return {path.name: path.read_text(encoding="utf-8")
            for path in sorted(versions.glob("*.py"))}


def test_migration_chain_intact_and_portable():
    sources = _migration_sources()
    assert sorted(sources) == ["0001_security_event.py", "0002_incidents.py",
                               "0003_detections.py", "0004_case_management.py"]
    for name, source in sources.items():
        for marker in SQLITE_ONLY_MARKERS:
            assert marker not in source, (name, marker)
    assert 'down_revision: str | None = "0003_detections"' in \
        sources["0004_case_management.py"]
    for token in ("assignee", "assigned_at", "bucket_event_ids",
                  "incident_notes", "incident_activity"):
        assert token in sources["0004_case_management.py"], token
    cfg = Config()
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    assert list(heads) == ["0004_case_management"]


def test_seed_has_no_sqlite_only_assumptions():
    source = (REPO / "scripts" / "seed_demo.py").read_text(encoding="utf-8")
    for marker in ("PRAGMA", "pragma", "sqlite_master", "sqlite_sequence",
                   "VACUUM", "vacuum", "AUTOINCREMENT", "autoincrement"):
        assert marker not in source, marker
    # The one SQLite-specific connect arg stays behind an explicit gate.
    assert "check_same_thread" in source
    assert 'startswith("sqlite")' in source
    assert "make_url" in source


def test_seed_resolves_postgres_url(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "seed_demo_pg", REPO / "scripts" / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    url, sqlite_path = module._resolve_database()
    assert url == PG_URL and sqlite_path is None
