"""Slice 1 tests: contracts, idempotency, batch, query, auth, constraints."""

import pytest
from sqlalchemy.exc import IntegrityError

from tests.conftest import make_event


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_valid_ingestion(client):
    r = client.post("/api/v1/events", json=make_event(event_id="evt-000001"))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["event_id"] == "evt-000001"
    assert body["event_type"] == "authentication"  # canonicalized
    assert body["raw_event"] == {"original_field": "original_value"}


def test_invalid_timestamp(client):
    r = client.post("/api/v1/events", json=make_event(timestamp="not-a-time"))
    assert r.status_code == 422
    r = client.post("/api/v1/events", json=make_event(timestamp="2026-09-06T10:21:31"))
    assert r.status_code == 422  # naive rejected


def test_invalid_ip(client):
    assert client.post("/api/v1/events", json=make_event(source_ip="999.1.1.1")).status_code == 422
    assert client.post("/api/v1/events", json=make_event(destination_ip="nope")).status_code == 422


def test_invalid_port(client):
    assert client.post("/api/v1/events", json=make_event(destination_port=70000)).status_code == 422
    assert client.post("/api/v1/events", json=make_event(destination_port=-1)).status_code == 422


def test_missing_required(client):
    evt = make_event()
    del evt["event_type"]
    assert client.post("/api/v1/events", json=evt).status_code == 422
    evt = make_event()
    del evt["raw_event"]
    assert client.post("/api/v1/events", json=evt).status_code == 422


def test_duplicate_event_id_idempotent(client):
    evt = make_event(event_id="evt-dup-1")
    r1 = client.post("/api/v1/events", json=evt)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/events", json=evt)
    assert r2.status_code in (200, 201)
    assert r2.json()["id"] == r1.json()["id"]
    total = client.get("/api/v1/events").json()["total"]
    assert total == 1


def test_batch_ingestion(client):
    evts = [make_event() for _ in range(8)]
    r = client.post("/api/v1/events/batch", json={"events": evts})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 8 and body["duplicates"] == 0 and body["rejected"] == 0


def test_batch_duplicate_handling(client):
    evts = [make_event() for _ in range(3)]
    client.post("/api/v1/events/batch", json={"events": evts})
    r = client.post("/api/v1/events/batch", json={"events": evts})
    body = r.json()
    assert body["accepted"] == 0 and body["duplicates"] == 3
    assert client.get("/api/v1/events").json()["total"] == 3


def test_pagination(client):
    for _ in range(5):
        client.post("/api/v1/events", json=make_event())
    r = client.get("/api/v1/events", params={"page": 1, "page_size": 2})
    body = r.json()
    assert body["total"] == 5 and body["pages"] == 3 and len(body["items"]) == 2
    r2 = client.get("/api/v1/events", params={"page": 3, "page_size": 2})
    assert len(r2.json()["items"]) == 1


def test_filtering(client):
    client.post("/api/v1/events", json=make_event(event_type="authentication", host="WIN-042", user="john.doe"))
    client.post("/api/v1/events", json=make_event(event_type="network", host="FW-01", user="jane"))
    assert client.get("/api/v1/events", params={"event_type": "network"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"host": "FW-01"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"user": "john.doe"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"source_ip": "192.168.1.20"}).json()["total"] == 2


def test_date_range_filtering(client):
    client.post("/api/v1/events", json=make_event(timestamp="2026-09-01T00:00:00Z"))
    client.post("/api/v1/events", json=make_event(timestamp="2026-09-10T00:00:00Z"))
    r = client.get("/api/v1/events", params={"start_time": "2026-09-05T00:00:00Z", "end_time": "2026-09-06T00:00:00Z"})
    assert r.json()["total"] == 0
    r = client.get("/api/v1/events", params={"start_time": "2026-09-09T00:00:00Z"})
    assert r.json()["total"] == 1
    assert client.get("/api/v1/events", params={"start_time": "2026-09-10T00:00:00Z", "end_time": "2026-09-01T00:00:00Z"}).status_code == 422


def test_db_unique_constraint():
    # The UNIQUE(event_id) constraint is the idempotency guarantee.
    from app.db.models.security_event import SecurityEvent

    cols = {c.name: c for c in SecurityEvent.__table__.columns}
    assert cols["event_id"].unique is True


def test_api_key_rejected(client, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("INGEST_API_KEY", "secret-xyz")
    get_settings.cache_clear()
    try:
        assert client.post("/api/v1/events", json=make_event()).status_code == 401
        assert client.post("/api/v1/events", json=make_event(),
                           headers={"X-API-Key": "wrong"}).status_code == 401
        # Reads stay open.
        assert client.get("/api/v1/events").status_code == 200
    finally:
        get_settings.cache_clear()


def test_api_key_accepted(authed_client):
    r = authed_client.post("/api/v1/events", json=make_event())
    assert r.status_code == 201, r.text


def test_get_single_event(client):
    client.post("/api/v1/events", json=make_event(event_id="evt-single-1"))
    r = client.get("/api/v1/events/evt-single-1")
    assert r.status_code == 200
    assert r.json()["event_id"] == "evt-single-1"
    assert client.get("/api/v1/events/evt-missing").status_code == 404


def test_raw_event_preserved(client):
    raw = {"weird": ["nested", {"a": 1}], "num": 42}
    r = client.post("/api/v1/events", json=make_event(event_id="evt-raw-1", raw_event=raw))
    assert r.json()["raw_event"] == raw
