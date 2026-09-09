"""Slice 38 tests: incident case management. No PG needed."""

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.db.database import get_db  # noqa: E402
from app.services import case as case_domain  # noqa: E402
from app.services.persist import cases as case_store  # noqa: E402
from app.services.persist.incidents import upsert_incidents  # noqa: E402
from test_correlate_rules import devt  # noqa: E402
from test_ueba_enrich import fit_model  # noqa: E402

import app.db.models  # noqa: E402,F401


@pytest.fixture()
def db(client):
    """Yield a session on the SAME in-memory DB the TestClient uses."""
    gen = client.app.dependency_overrides[get_db]()
    session = next(gen)
    try:
        yield session
    finally:
        try:
            next(gen)
        except StopIteration:
            pass


def seed_incident(client, db, user="alice"):
    from conftest import make_event
    from test_ueba_enrich import incident_for_dets

    evts = [make_event(event_id="case-evt-1", user=user),
            make_event(event_id="case-evt-2", user=user)]
    for e in evts:
        assert client.post("/api/v1/events", json=e).status_code == 201
    dets = [devt("AUTH-001", user=user, start_min=0, evidence=["case-evt-1"])]
    by_id = {e["event_id"]: e for e in evts}
    enr, _mp = incident_for_dets(dets, by_id)
    from app.services.ueba.attach import attach_ueba

    (wrapped,) = attach_ueba([enr], by_id, fit_model([]))
    from app.services.persist.detections import upsert_detections

    assert upsert_detections(db, dets) == (1, 0)
    assert upsert_incidents(db, [wrapped]) == (1, 0)
    return wrapped.incident_id


def test_lifecycle_valid_transitions(db):
    assert case_domain.validate_transition("NEW", "INVESTIGATING") == "INVESTIGATING"
    assert case_domain.validate_transition("INVESTIGATING", "CONTAINED") == "CONTAINED"
    assert case_domain.validate_transition("INVESTIGATING", "RESOLVED") == "RESOLVED"
    assert case_domain.validate_transition("CONTAINED", "INVESTIGATING") == "INVESTIGATING"
    assert case_domain.validate_transition("CONTAINED", "RESOLVED") == "RESOLVED"
    assert case_domain.allowed_transitions("NEW") == ["INVESTIGATING"]
    assert case_domain.allowed_transitions("RESOLVED") == []


def test_lifecycle_invalid_transitions_rejected(db):
    with pytest.raises(ValueError):
        case_domain.validate_transition("NEW", "RESOLVED")
    with pytest.raises(ValueError):
        case_domain.validate_transition("NEW", "CONTAINED")
    with pytest.raises(ValueError):
        case_domain.validate_transition("RESOLVED", "INVESTIGATING")
    with pytest.raises(ValueError):
        case_domain.validate_transition("NEW", "BOGUS")


def test_patch_status_flow(client, db):
    iid = seed_incident(client, db)
    r = client.patch(f"/api/v1/incidents/{iid}", json={"status": "INVESTIGATING"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "INVESTIGATING"
    r = client.patch(f"/api/v1/incidents/{iid}", json={"status": "NEW"})
    assert r.status_code == 422
    r = client.patch(f"/api/v1/incidents/does-not-exist", json={"status": "INVESTIGATING"})
    assert r.status_code == 404


def test_patch_invalid_status_value(client, db):
    iid = seed_incident(client, db)
    assert client.patch(f"/api/v1/incidents/{iid}", json={"status": "BOGUS"}).status_code == 422


def test_assign_unassign(client, db):
    iid = seed_incident(client, db)
    r = client.patch(f"/api/v1/incidents/{iid}", json={"assignee": "analyst-7"})
    assert r.status_code == 200, r.text
    assert r.json()["assignee"] == "analyst-7"
    assert r.json()["assigned_at"] is not None
    r = client.patch(f"/api/v1/incidents/{iid}", json={"assignee": None})
    assert r.status_code == 200, r.text
    assert r.json()["assignee"] is None
    assert client.patch(f"/api/v1/incidents/nope", json={"assignee": "x"}).status_code == 404


def test_add_note_validation(client, db):
    iid = seed_incident(client, db)
    r = client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "  eshift handoff  "})
    assert r.status_code == 201, r.text
    assert r.json()["body"] == "eshift handoff"
    assert client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "   "}).status_code == 422
    assert client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "x" * 5001}).status_code == 422
    assert client.post(f"/api/v1/incidents/{iid}/notes", json={}).status_code == 422
    assert client.post("/api/v1/incidents/nope/notes", json={"body": "x"}).status_code == 404
    assert client.get(f"/api/v1/incidents/{iid}/notes").json()[0]["body"] == "eshift handoff"


def test_activity_records_actions_in_order(client, db):
    iid = seed_incident(client, db)
    client.patch(f"/api/v1/incidents/{iid}", json={"status": "INVESTIGATING"})
    client.patch(f"/api/v1/incidents/{iid}", json={"assignee": "analyst-7"})
    client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "n1"})
    client.patch(f"/api/v1/incidents/{iid}", json={"assignee": None})
    acts = client.get(f"/api/v1/incidents/{iid}/activity").json()
    assert [a["action"] for a in acts] == ["STATUS_CHANGED", "ASSIGNED", "NOTE_ADDED", "UNASSIGNED"]
    keys = [(a["created_at"], a["activity_id"]) for a in acts]
    assert keys == sorted(keys)
    assert client.get("/api/v1/incidents/nope/activity").status_code == 404


def test_investigation_includes_case(client, db):
    iid = seed_incident(client, db)
    client.patch(f"/api/v1/incidents/{iid}", json={"status": "INVESTIGATING", "assignee": "a1"})
    client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "look"})
    body = client.get(f"/api/v1/incidents/{iid}/investigation").json()
    assert body["case"]["status"] == "INVESTIGATING"
    assert body["case"]["assignee"] == "a1"
    assert body["case"]["assigned_at"] is not None
    assert body["case"]["allowed_transitions"] == ["CONTAINED", "RESOLVED"]
    assert len(body["case"]["notes"]) == 1 and len(body["case"]["activity"]) == 3
    assert body["timeline"] and body["detections"]


def test_case_ops_preserve_evidence(client, db):
    iid = seed_incident(client, db)
    before = client.get(f"/api/v1/incidents/{iid}").json()
    client.patch(f"/api/v1/incidents/{iid}", json={"status": "INVESTIGATING", "assignee": "a"})
    client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "n"})
    after = client.get(f"/api/v1/incidents/{iid}").json()
    assert after["detection_ids"] == before["detection_ids"]
    assert after["evidence_event_ids"] == before["evidence_event_ids"]
    inv = client.get(f"/api/v1/incidents/{iid}/investigation").json()
    assert [d["detection_id"] for d in inv["detections"]] == before["detection_ids"]


def test_incident_response_carries_assignee(client, db):
    iid = seed_incident(client, db)
    assert client.get(f"/api/v1/incidents/{iid}").json()["assignee"] is None
    client.patch(f"/api/v1/incidents/{iid}", json={"assignee": "on-call"})
    assert client.get(f"/api/v1/incidents/{iid}").json()["assignee"] == "on-call"
