"""Demo-seed workflow tests. Local SQLite files only; no network, no benchmarks."""

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
SCRIPTS = REPO / "scripts"
DEMO_DATA = REPO / "data" / "synthetic" / "sample_demo.jsonl"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def load_seed_demo():
    spec = importlib.util.spec_from_file_location(
        "seed_demo", SCRIPTS / "seed_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def workdir():
    path = Path(tempfile.mkdtemp(prefix="esf-seed-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def db_url_for(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def migrate(url: str, monkeypatch, revision: str = "head") -> None:
    from alembic import command
    from alembic.config import Config

    monkeypatch.setenv("DATABASE_URL", url)
    cfg = Config()
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, revision)


def seed(url: str, monkeypatch, capsys=None) -> int:
    monkeypatch.setenv("DATABASE_URL", url)
    module = load_seed_demo()
    code = module.main()
    if capsys is not None:
        return code, capsys.readouterr()
    return code


def counts(url: str) -> dict:
    from sqlalchemy import create_engine, func, select

    from app.db.models.case import IncidentActivity, IncidentNote
    from app.db.models.detection import Detection as DetectionRow
    from app.db.models.incident import Incident as IncidentRow
    from app.db.models.security_event import SecurityEvent as SecurityEventRow

    import app.db.models  # noqa: F401

    engine = create_engine(url)
    with engine.connect() as conn:
        out = {}
        for name, model in (("events", SecurityEventRow), ("detections", DetectionRow),
                            ("incidents", IncidentRow), ("notes", IncidentNote),
                            ("activity", IncidentActivity)):
            out[name] = conn.execute(
                select(func.count()).select_from(model)).scalar_one()
        out["event_ids"] = sorted(conn.execute(
            select(SecurityEventRow.event_id)).scalars().all())
        out["detection_ids"] = sorted(conn.execute(
            select(DetectionRow.detection_id)).scalars().all())
        out["incident_ids"] = sorted(conn.execute(
            select(IncidentRow.incident_id)).scalars().all())
    engine.dispose()
    return out


def manifest_total() -> int:
    manifest = json.loads((DEMO_DATA.parent / "sample_demo.manifest.json").read_text())
    lines = sum(1 for line in DEMO_DATA.read_text(encoding="utf-8").splitlines() if line.strip())
    assert lines == manifest["total"]
    return manifest["total"]


def test_fresh_seed_populates_demo(workdir, monkeypatch, capsys):
    url = db_url_for(workdir / "fresh.db")
    migrate(url, monkeypatch)
    code, out = seed(url, monkeypatch, capsys)
    assert code == 0
    assert "events: 200" in out.out and "status: success" in out.out
    found = counts(url)
    assert found["events"] == manifest_total() == 200
    assert found["detections"] == 20 and found["incidents"] == 12
    assert found["notes"] == 1 and found["activity"] == 2
    # Relationship integrity: incident detections + detection evidence resolve.
    from sqlalchemy import create_engine, select

    from app.db.models.detection import Detection as DetectionRow
    from app.db.models.incident import Incident as IncidentRow
    from app.db.models.security_event import SecurityEvent as SecurityEventRow

    engine = create_engine(url)
    with engine.connect() as conn:
        det_ids = set(conn.execute(select(DetectionRow.detection_id)).scalars().all())
        event_ids = set(conn.execute(select(SecurityEventRow.event_id)).scalars().all())
        for (ids,) in conn.execute(select(IncidentRow.detection_ids)).all():
            assert set(ids) <= det_ids
        for (ids,) in conn.execute(select(DetectionRow.evidence_event_ids)).all():
            assert set(ids) <= event_ids
    engine.dispose()


def test_repeat_seed_is_idempotent(workdir, monkeypatch, capsys):
    url = db_url_for(workdir / "repeat.db")
    migrate(url, monkeypatch)
    assert seed(url, monkeypatch) == 0
    before = counts(url)
    code, out = seed(url, monkeypatch, capsys)
    assert code == 0
    assert "already seeded / nothing to do" in out.out
    assert counts(url) == before


def test_determinism_across_fresh_databases(workdir, monkeypatch):
    first = db_url_for(workdir / "a.db")
    second = db_url_for(workdir / "b.db")
    migrate(first, monkeypatch)
    assert seed(first, monkeypatch) == 0
    migrate(second, monkeypatch)
    assert seed(second, monkeypatch) == 0
    a, b = counts(first), counts(second)
    assert a["event_ids"] == b["event_ids"]
    assert a["detection_ids"] == b["detection_ids"]
    assert a["incident_ids"] == b["incident_ids"]


def test_no_benchmark_contamination():
    source = (SCRIPTS / "seed_demo.py").read_text(encoding="utf-8")
    assert "sample_demo.jsonl" in source
    for banned in ("cse_cic", "cicids", "data/public", "drop_table",
                   "DROP TABLE", ".delete(", "urlopen", "urllib.request",
                   "requests.", "socket"):
        assert banned not in source, banned
    lowered = source.lower()
    assert "drop " not in lowered and "delete from" not in lowered


def test_missing_database_url_fails_clearly(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    module = load_seed_demo()
    assert module.main() == 2
    assert "DATABASE_URL" in capsys.readouterr().err


def test_unmigrated_database_fails_clearly(workdir, monkeypatch, capsys):
    url = db_url_for(workdir / "empty.db")
    Path(workdir / "empty.db").touch()
    monkeypatch.setenv("DATABASE_URL", url)
    module = load_seed_demo()
    assert module.main() == 2
    assert "alembic upgrade head" in capsys.readouterr().err


def test_seeded_api_serves_investigation(workdir, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.database import get_db
    from app.main import create_app

    url = db_url_for(workdir / "api.db")
    migrate(url, monkeypatch)
    assert seed(url, monkeypatch) == 0
    engine = create_engine(url, connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = override
    client = TestClient(app)
    try:
        body = client.get("/api/v1/incidents", params={"page_size": 50}).json()
        assert body["total"] == 12
        iid = body["items"][0]["incident_id"]
        for path in (f"/api/v1/incidents/{iid}",
                     f"/api/v1/incidents/{iid}/investigation",
                     f"/api/v1/incidents/{iid}/recommendations",
                     f"/api/v1/incidents/{iid}/threat-intelligence",
                     f"/api/v1/incidents/{iid}/notes",
                     f"/api/v1/incidents/{iid}/activity"):
            assert client.get(path).status_code == 200, path
        copilot = client.post(f"/api/v1/incidents/{iid}/copilot",
                              json={"question": "Summarize this incident"})
        assert copilot.status_code == 200 and copilot.json()["citations"]
    finally:
        client.close()
        engine.dispose()
