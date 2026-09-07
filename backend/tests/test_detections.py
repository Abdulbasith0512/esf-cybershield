"""Slice 11 tests: detection persistence (A-L) + read API + relationships."""

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
from app.db.models.detection import Detection as DetectionRow  # noqa: E402
from app.services.detect.models import detection_id_for  # noqa: E402
from app.services.persist.detections import upsert_detections  # noqa: E402
from test_correlate_rules import devt  # noqa: E402

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


def make_dets(n=3, rule="AUTH-001", user_prefix="det"):
    return [devt(rule, user=f"{user_prefix}{i}", start_min=i * 10,
                 evidence=[f"evt-d{i:04d}"]) for i in range(n)]


def row_count(db):
    return db.execute(select(func.count()).select_from(DetectionRow)).scalar_one()


def test_insert_and_retrieve(db):
    (det,) = make_dets(1)
    assert upsert_detections(db, [det]) == (1, 0)
    assert row_count(db) == 1
    row = db.execute(
        select(DetectionRow).where(DetectionRow.detection_id == det.detection_id)
    ).scalars().one()
    assert (row.rule_id, row.rule_name, row.severity) == (det.rule_id, det.rule_name, det.severity)
    assert row.confidence == det.confidence and row.reason == det.reason


def test_idempotent_insert(db):
    (det,) = make_dets(1)
    assert upsert_detections(db, [det]) == (1, 0)
    assert upsert_detections(db, [det]) == (0, 1)
    assert row_count(db) == 1


def test_upsert_update_preserves_id(db):
    (det,) = make_dets(1)
    upsert_detections(db, [det])
    changed = det.model_copy(deep=True)
    changed.confidence = 0.99
    assert upsert_detections(db, [changed]) == (0, 1)
    assert row_count(db) == 1
    row = db.execute(
        select(DetectionRow).where(DetectionRow.detection_id == det.detection_id)
    ).scalars().one()
    assert row.confidence == 0.99 and row.detection_id == det.detection_id


def test_evidence_preserved_no_dupes(db):
    det = devt("NET-001", evidence=["e2", "e1", "e2"])
    upsert_detections(db, [det])
    row = db.execute(select(DetectionRow)).scalars().one()
    assert row.evidence_event_ids == ["e1", "e2"]


def test_deterministic_id_untouched(db):
    det = devt("PROC-001", evidence=["evt-x1"])
    assert det.detection_id == detection_id_for("PROC-001", ["evt-x1"])
    upsert_detections(db, [det])
    row = db.execute(select(DetectionRow)).scalars().one()
    assert row.detection_id == det.detection_id


def test_unique_constraint_declared():
    cols = {c.name: c for c in DetectionRow.__table__.columns}
    assert cols["detection_id"].unique is True


def test_failed_row_leaves_no_partial(db):
    good = make_dets(1)[0]
    bad = good.model_copy(deep=True)
    bad.rule_id = None  # violates NOT NULL
    with pytest.raises(Exception):
        upsert_detections(db, [good, bad])
    assert row_count(db) == 1


def test_timestamps_aware_on_read(client):
    (det,) = make_dets(1, user_prefix="tzdet")

    def _seed():
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        try:
            upsert_detections(db, [det])
            db.commit()
        finally:
            try:
                gen.close()
            except Exception:
                pass

    _seed()
    r = client.get(f"/api/v1/detections/{det.detection_id}")
    assert r.status_code == 200, r.text
    from datetime import datetime

    assert datetime.fromisoformat(r.json()["first_seen"]).tzinfo is not None


# ---------------- API ----------------

def _seed_api(client, dets):
    gen = client.app.dependency_overrides[get_db]()
    db = next(gen)
    try:
        upsert_detections(db, dets)
        db.commit()
    finally:
        try:
            gen.close()
        except Exception:
            pass


def test_api_list_pagination(client):
    _seed_api(client, make_dets(5, user_prefix="pg"))
    r = client.get("/api/v1/detections", params={"page": 1, "page_size": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 5 and body["pages"] == 3 and len(body["items"]) == 2
    assert set(body["items"][0]) >= {"detection_id", "rule_id", "rule_name",
                                     "severity", "confidence", "first_seen", "last_seen"}


def test_api_ordering_last_seen_desc(client):
    _seed_api(client, make_dets(3, user_prefix="ord"))
    seen = [i["last_seen"] for i in
            client.get("/api/v1/detections", params={"page_size": 50}).json()["items"]]
    assert seen == sorted(seen, reverse=True)


def test_api_filters(client):
    dets = make_dets(2) + [devt("NET-001", user="flt9", start_min=50, severity="HIGH")]
    _seed_api(client, dets)
    assert client.get("/api/v1/detections", params={"rule_id": "auth-001"}).json()["total"] == 2
    assert client.get("/api/v1/detections", params={"severity": "high"}).json()["total"] == 3
    assert client.get("/api/v1/detections", params={"min_confidence": 0.79}).json()["total"] == 3
    assert client.get("/api/v1/detections", params={"page_size": 501}).status_code == 422
    assert client.get("/api/v1/detections", params={
        "start_time": "2026-09-10T00:00:00Z",
        "end_time": "2026-09-01T00:00:00Z"}).status_code == 422


def test_api_detail_and_404(client):
    (det,) = make_dets(1, user_prefix="one")
    _seed_api(client, [det])
    r = client.get(f"/api/v1/detections/{det.detection_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detection_id"] == det.detection_id
    assert body["rule_name"] == det.rule_name and body["reason"] == det.reason
    assert set(body["evidence_event_ids"]) == set(det.evidence_event_ids)
    assert body["detection_metadata"]["user"] == det.metadata["user"]
    r404 = client.get("/api/v1/detections/does-not-exist")
    assert r404.status_code == 404
    assert r404.json() == {"detail": "detection not found"}


def test_no_recalculation_on_get(client):
    (det,) = make_dets(1, user_prefix="norecalc")
    _seed_api(client, [det])
    first = client.get(f"/api/v1/detections/{det.detection_id}").json()
    second = client.get(f"/api/v1/detections/{det.detection_id}").json()
    assert first == second
