"""Deployment-readiness regression tests: migration 0004 + CORS + sqlite path.

No PG, no network. Alembic runs against tmp SQLite files only.
"""

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402
from sqlalchemy import create_engine, inspect, text  # noqa: E402

ORIGIN = "http://localhost:3000"


@pytest.fixture()
def workdir():
    path = Path(tempfile.mkdtemp(prefix="esf-deploy-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def alembic_config(db_path: Path, monkeypatch=None) -> Config:
    """Config bound to a scratch SQLite file.

    alembic/env.py resolves DATABASE_URL from the process environment at run
    time (falling back to the repo .env, which points at PostgreSQL), so the
    variable must be pinned for every in-process upgrade.
    """
    url = f"sqlite:///{db_path.as_posix()}"
    if monkeypatch is not None:
        monkeypatch.setenv("DATABASE_URL", url)
    cfg = Config()
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_single_head_is_0004():
    heads = ScriptDirectory.from_config(
        alembic_config(Path("unused.db"))).get_heads()
    assert list(heads) == ["0004_case_management"]


def test_fresh_upgrade_matches_models(workdir, monkeypatch):
    from app.db.database import Base

    import app.db.models  # noqa: F401

    db_path = workdir / "fresh.db"
    command.upgrade(alembic_config(db_path, monkeypatch), "head")
    migrated = create_engine(f"sqlite:///{db_path.as_posix()}")
    other_path = workdir / "models.db"
    reference = create_engine(f"sqlite:///{other_path.as_posix()}")
    Base.metadata.create_all(reference)

    def _shape(engine):
        inspector = inspect(engine)
        shape = {}
        for table in ("security_events", "incidents", "detections",
                      "incident_notes", "incident_activity"):
            columns = sorted(c["name"] for c in inspector.get_columns(table))
            indexes = sorted(i["name"] for i in inspector.get_indexes(table))
            shape[table] = (columns, indexes)
        return shape

    assert _shape(migrated) == _shape(reference)
    shape = _shape(migrated)
    assert "assignee" in shape["incidents"][0]
    assert "assigned_at" in shape["incidents"][0]
    assert "bucket_event_ids" in shape["detections"][0]


def test_upgrade_preserves_existing_rows(workdir, monkeypatch):
    db_path = workdir / "existing.db"
    cfg = alembic_config(db_path, monkeypatch)
    command.upgrade(cfg, "0003_detections")
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO incidents (id, incident_id, title, severity, status, "
            "confidence, reason, risk_score, risk_band, risk_explanation, "
            "first_seen, last_seen, detection_ids, evidence_event_ids, metadata, "
            "mitre_techniques, risk_breakdown, ueba_evidence, created_at, updated_at) "
            "VALUES ('11111111111111111111111111111111', 'inc-old', 'T', 'HIGH', "
            "'NEW', 0.5, 'r', 10, 'LOW', 'e', '2026-09-01T00:00:00', "
            "'2026-09-01T01:00:00', '[]', '[]', '{}', '[]', '{}', '{}', "
            "'2026-09-01T01:00:00', '2026-09-01T01:00:00')"))
        conn.execute(text(
            "INSERT INTO detections (id, detection_id, rule_id, rule_name, severity, "
            "confidence, reason, evidence_event_ids, metadata, first_seen, last_seen, "
            "created_at, updated_at) "
            "VALUES ('22222222222222222222222222222222', 'det-old', 'FLOW-001', "
            "'R', 'MEDIUM', 0.6, 'r', '[\"e1\"]', '{}', '2026-09-01T00:00:00', "
            "'2026-09-01T00:00:00', '2026-09-01T00:00:00', '2026-09-01T00:00:00')"))
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        incident = conn.execute(
            text("SELECT title, assignee, assigned_at FROM incidents "
                 "WHERE incident_id = 'inc-old'")).one()
    # ORM-visible read: the JSON storage text '[]' must deserialize to [].
    import uuid

    from sqlalchemy.orm import Session

    from app.db.models.detection import Detection as DetectionRow
    from app.db.models.incident import Incident as IncidentRow

    with Session(engine) as session:
        det_row = session.execute(
            text("SELECT detection_id FROM detections")).all()
        assert [r[0] for r in det_row] == ["det-old"]
        loaded = session.get(DetectionRow,
                             uuid.UUID("22222222-2222-2222-2222-222222222222"))
        assert loaded.bucket_event_ids == []
        loaded_inc = session.get(IncidentRow,
                                 uuid.UUID("11111111-1111-1111-1111-111111111111"))
        assert loaded_inc.assignee is None and loaded_inc.assigned_at is None
    assert incident[0] == "T" and incident[1] is None and incident[2] is None


def test_downgrade_roundtrip(workdir, monkeypatch):
    db_path = workdir / "roundtrip.db"
    cfg = alembic_config(db_path, monkeypatch)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "-1")
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    tables = set(inspect(engine).get_table_names())
    assert "incident_notes" not in tables and "incident_activity" not in tables
    columns = {c["name"] for c in inspect(engine).get_columns("incidents")}
    assert "assignee" not in columns and "assigned_at" not in columns
    command.upgrade(cfg, "head")
    tables = set(inspect(engine).get_table_names())
    assert {"incident_notes", "incident_activity"} <= tables


def test_absolute_sqlite_url_accepted(workdir):
    from app.db.database import Base

    import app.db.models  # noqa: F401

    # POSIX absolute form (deployment target): absolute, never cwd-relative.
    # sqlalchemy's own URL parser is the authority on the database path.
    from sqlalchemy.engine import make_url

    assert make_url("sqlite:////data/esf.db").database == "/data/esf.db"
    # Functional form on this host: drive-absolute file URL.
    db_path = workdir / "abs.db"
    assert db_path.is_absolute()
    engine = create_engine(f"sqlite:///{db_path.as_posix()}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    assert db_path.exists()
    assert "incidents" in inspect(engine).get_table_names()


def test_cors_preflight_allows_patch(client):
    response = client.options(
        "/api/v1/incidents/inc-1",
        headers={"Origin": ORIGIN, "Access-Control-Request-Method": "PATCH"},
    )
    assert response.status_code == 200
    methods = response.headers.get("access-control-allow-methods", "")
    assert "PATCH" in methods and "GET" in methods and "POST" in methods
    assert "PUT" not in methods.split(",") and "DELETE" not in [m.strip() for m in methods.split(",")]


def test_cors_preflight_preserves_post_and_origin(client):
    response = client.options(
        "/api/v1/incidents/inc-1/notes",
        headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == ORIGIN
    foreign = client.options(
        "/api/v1/incidents/inc-1/notes",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert foreign.headers.get("access-control-allow-origin") != "http://evil.example"


def test_api_contracts_intact(client):
    assert client.get("/health").json() == {
        "status": "healthy", "service": "esf-cybershield-backend"}
    body = client.get("/api/v1/incidents", params={"page_size": 5}).json()
    assert body["items"] == [] and body["total"] == 0
