"""End-to-end pipeline tests on SQLite (portable schema; prod uses PostgreSQL)."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base, get_db
from app.main import create_app

import app.db.models  # noqa: F401 -- register tables


def make_client():
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

    app = create_app()
    app.dependency_overrides[get_db] = override
    return TestClient(app)


def _evt(**kw):
    base = {"source": "test", "event_type": "authentication", "user_id": "alice",
            "host": "ws-01", "src_ip": "10.0.0.1", "action": "logon", "status": "success"}
    base.update(kw)
    base.setdefault("event_id", str(uuid.uuid4()))
    return base


def test_health():
    c = make_client()
    r = c.get("/health")
    assert r.status_code == 200


def test_ingest_dedupe():
    c = make_client()
    e = _evt(event_id="dup-1")
    r1 = c.post("/api/v1/events", json=e)
    assert r1.status_code == 201, r1.text
    r2 = c.post("/api/v1/events", json=e)
    assert r2.status_code == 201
    assert r2.json()["deduped"] is True
    assert r1.json()["raw_id"] == r2.json()["raw_id"]


def test_invalid_ip_rejected():
    c = make_client()
    r = c.post("/api/v1/events", json=_evt(src_ip="not-an-ip"))
    assert r.status_code == 422, r.text


def test_brute_force_creates_incident_with_mitre_and_risk():
    c = make_client()
    now = datetime.now(timezone.utc)
    evts = []
    for i in range(6):
        evts.append(_evt(user_id="victim1", src_ip="203.0.113.9", status="failure",
                         timestamp=(now - timedelta(minutes=4) + timedelta(seconds=i * 30)).isoformat()))
    r = c.post("/api/v1/events/bulk", json=evts)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ingested"] == 6
    assert len(body["incidents"]) >= 1

    inc_id = body["incidents"][0]
    d = c.get(f"/api/v1/incidents/{inc_id}")
    assert d.status_code == 200, d.text
    detail = d.json()
    assert "T1110" in detail["incident"]["mitre_techniques"]
    assert detail["incident"]["risk_score"] >= 70
    assert detail["incident"]["event_count"] >= 1


def test_priv_esc_single_event_incident():
    c = make_client()
    r = c.post("/api/v1/events", json=_evt(event_type="privilege", action="privilege-escalation",
                                           status="success", user_id="victim9"))
    assert r.status_code == 201, r.text
    assert r.json()["incident_id"] is not None
    d = c.get(f"/api/v1/incidents/{r.json()['incident_id']}")
    assert "T1068" in d.json()["incident"]["mitre_techniques"]


def test_stats_summary():
    c = make_client()
    c.post("/api/v1/events", json=_evt())
    r = c.get("/api/v1/stats/summary")
    assert r.status_code == 200
    assert r.json()["events_24h"] >= 1
