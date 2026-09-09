"""Slice 9 tests: incident persistence (A-L) + read API. No PG needed."""

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.db.database import Base, get_db  # noqa: E402
from app.db.models.incident import Incident as IncidentRow  # noqa: E402
from app.services.persist.incidents import upsert_incidents  # noqa: E402
from test_correlate_rules import devt, evmap  # noqa: E402
from test_ueba_enrich import background, fit_model, h, incident_for_dets  # noqa: E402

import app.db.models  # noqa: E402,F401


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()


def make_items(n=3, user_prefix="persist"):
    """Build n IncidentWithUeba objects with distinct users (separate incidents)."""
    items = []
    for i in range(n):
        user = f"{user_prefix}{i}"
        evts = [h(user=user, minutes=j * 70) for j in range(6)]
        by_id = {e["event_id"]: e for e in evts}
        model = fit_model([])
        dets = [devt("AUTH-002", user=user, severity="MEDIUM", start_min=65,
                     evidence=[evts[1]["event_id"]])]
        enr, mp = incident_for_dets(dets, by_id)
        from app.services.ueba.attach import attach_ueba

        (wrapped,) = attach_ueba([enr], by_id, model)
        items.append(wrapped)
    return items


def row_count(db):
    return db.execute(select(func.count()).select_from(IncidentRow)).scalar_one()


def test_insert_and_retrieve(db):
    (item,) = make_items(1)
    assert upsert_incidents(db, [item]) == (1, 0)
    assert row_count(db) == 1
    row = db.execute(
        select(IncidentRow).where(IncidentRow.incident_id == item.incident_id)
    ).scalars().one()
    assert row.title == item.enriched.incident.title
    assert row.severity == item.enriched.incident.severity
    assert row.status == item.enriched.incident.status
    assert row.risk_score == item.enriched.risk_score
    assert row.risk_band == item.enriched.risk_band


def test_idempotent_insert(db):
    (item,) = make_items(1)
    assert upsert_incidents(db, [item]) == (1, 0)
    assert upsert_incidents(db, [item]) == (0, 1)
    assert row_count(db) == 1


def test_upsert_update_preserves_id(db):
    (item,) = make_items(1)
    upsert_incidents(db, [item])
    changed = item.model_copy(deep=True)
    changed.enriched.incident.status = "INVESTIGATING"
    assert upsert_incidents(db, [changed]) == (0, 1)
    assert row_count(db) == 1
    row = db.execute(
        select(IncidentRow).where(IncidentRow.incident_id == item.incident_id)
    ).scalars().one()
    assert row.status == "INVESTIGATING"
    assert row.incident_id == item.incident_id


def test_id_lists_preserved_no_dupes(db):
    (item,) = make_items(1)
    upsert_incidents(db, [item])
    row = db.execute(select(IncidentRow)).scalars().one()
    assert sorted(row.detection_ids) == row.detection_ids
    assert sorted(row.evidence_event_ids) == row.evidence_event_ids
    assert len(set(row.detection_ids)) == len(row.detection_ids)
    assert len(set(row.evidence_event_ids)) == len(row.evidence_event_ids)
    assert set(row.detection_ids) == set(item.enriched.incident.detection_ids)
    assert set(row.evidence_event_ids) == set(item.enriched.incident.evidence_event_ids)


def test_mitre_round_trip(db):
    (item,) = make_items(1)
    upsert_incidents(db, [item])
    row = db.execute(select(IncidentRow)).scalars().one()
    assert row.mitre_techniques == [m.model_dump(mode="json") for m in item.enriched.mitre_techniques]


def test_ueba_round_trip_all_states(db):
    from app.services.ueba.attach import attach_ueba

    # Anomalous.
    loud = [h(user="zzloud", minutes=i * 2) for i in range(3)]
    loud.append(h(user="zzloud", minutes=40, event_type="data_transfer",
                  source="firewall", status="completed", destination_ip="10.0.0.9",
                  bytes_sent=3_000_000_000))
    by_id = {e["event_id"]: e for e in background() + loud}
    model = fit_model(loud)
    dets = [devt("DATA-001", user="zzloud", start_min=40, evidence=[loud[3]["event_id"]],
                 extra_meta={"bytes_sent": 3_000_000_000, "threshold": 1_000_000_000})]
    enr, mp = incident_for_dets(dets, by_id)
    anomalous = attach_ueba([enr], by_id, model)[0]
    # Unavailable (no model).
    clean_item = make_items(1, user_prefix="zzclean")[0]
    assert upsert_incidents(db, [anomalous, clean_item]) == (2, 0)
    rows = {r.incident_id: r for r in db.execute(select(IncidentRow)).scalars().all()}
    assert rows[anomalous.incident_id].ueba_evidence == anomalous.ueba.model_dump(mode="json")
    assert rows[clean_item.incident_id].ueba_evidence == clean_item.ueba.model_dump(mode="json")
    assert rows[anomalous.incident_id].ueba_evidence["available"] is True


def test_risk_round_trip_exact(db):
    (item,) = make_items(1)
    upsert_incidents(db, [item])
    row = db.execute(select(IncidentRow)).scalars().one()
    assert row.risk_score == item.enriched.risk_score
    assert row.risk_band == item.enriched.risk_band
    assert row.risk_breakdown == item.enriched.risk_breakdown.model_dump(mode="json")


def _override_session(client):
    """Yield a session on the SAME in-memory DB the TestClient uses."""
    gen = client.app.dependency_overrides[get_db]()
    db = next(gen)
    try:
        yield db
    finally:
        try:
            gen.close()
        except Exception:
            pass


def test_timestamps_aware_on_read(client):
    (item,) = make_items(1, user_prefix="tzcheck")
    for db in _override_session(client):
        upsert_incidents(db, [item])
        db.commit()
    r = client.get(f"/api/v1/incidents/{item.incident_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    from datetime import datetime

    assert datetime.fromisoformat(body["first_seen"]).tzinfo is not None
    assert datetime.fromisoformat(body["last_seen"]).tzinfo is not None


def test_deterministic_serialization(db):
    (item,) = make_items(1)
    upsert_incidents(db, [item])
    first = db.execute(select(IncidentRow)).scalars().one()
    snap1 = {c.name: getattr(first, c.name) for c in IncidentRow.__table__.columns
             if c.name not in ("id", "created_at", "updated_at")}
    upsert_incidents(db, [item])
    db.expire_all()
    second = db.execute(select(IncidentRow)).scalars().one()
    snap2 = {c.name: getattr(second, c.name) for c in IncidentRow.__table__.columns
             if c.name not in ("id", "created_at", "updated_at")}
    assert snap1 == snap2


def test_failed_row_leaves_no_partial(db):
    (good,) = make_items(1)
    bad = good.model_copy(deep=True)
    bad.enriched.incident.title = None  # violates NOT NULL
    with pytest.raises(Exception):
        upsert_incidents(db, [good, bad])
    assert row_count(db) == 1
    assert db.execute(select(IncidentRow)).scalars().one().incident_id == good.incident_id


def test_unique_constraint_declared():
    cols = {c.name: c for c in IncidentRow.__table__.columns}
    assert cols["incident_id"].unique is True


# ---------------- API ----------------

def _seed_api(client, n=5):
    for db in _override_session(client):
        items = make_items(n, user_prefix="api")
        upsert_incidents(db, items)
        db.commit()
        return items


def test_api_list_pagination(client):
    _seed_api(client, 5)
    r = client.get("/api/v1/incidents", params={"page": 1, "page_size": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 5 and body["pages"] == 3 and len(body["items"]) == 2
    keys = set(body["items"][0])
    assert {"incident_id", "title", "severity", "status", "risk_score",
            "risk_band", "ueba_anomaly_flag", "first_seen", "last_seen"} <= keys
    assert "raw_event" not in str(keys) and "reason" not in keys


def test_api_ordering_last_seen_desc(client):
    _seed_api(client, 3)
    body = client.get("/api/v1/incidents", params={"page_size": 50}).json()
    seen = [i["last_seen"] for i in body["items"]]
    assert seen == sorted(seen, reverse=True)


def test_api_filters(client):
    items = _seed_api(client, 4)
    sev = items[0].enriched.incident.severity
    assert client.get("/api/v1/incidents", params={"severity": sev.lower()}).json()["total"] >= 1
    band = items[0].enriched.risk_band
    assert client.get("/api/v1/incidents", params={"risk_band": band}).json()["total"] >= 1
    assert client.get("/api/v1/incidents", params={"status": "new"}).json()["total"] == 4
    top = max(i.enriched.risk_score for i in items)
    assert client.get("/api/v1/incidents", params={"min_risk_score": top}).json()["total"] >= 1
    assert client.get("/api/v1/incidents", params={"min_risk_score": 101}).status_code == 422


def test_api_validation_errors(client):
    assert client.get("/api/v1/incidents", params={"page_size": 501}).status_code == 422
    assert client.get("/api/v1/incidents", params={
        "start_time": "2026-09-10T00:00:00Z",
        "end_time": "2026-09-01T00:00:00Z"}).status_code == 422


def test_api_detail_and_404(client):
    items = _seed_api(client, 2)
    r = client.get(f"/api/v1/incidents/{items[0].incident_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident_id"] == items[0].incident_id
    assert body["risk_breakdown"]["total"] == body["risk_score"]
    assert isinstance(body["mitre_techniques"], list)
    assert isinstance(body["detection_ids"], list)
    assert isinstance(body["evidence_event_ids"], list)
    assert body["ueba_evidence"]["incident_id"] == items[0].incident_id
    r404 = client.get("/api/v1/incidents/does-not-exist")
    assert r404.status_code == 404
    assert r404.json() == {"detail": "incident not found"}
