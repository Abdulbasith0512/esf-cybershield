"""Slice 37 tests: SOC investigation contract. No PG needed."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.investigate import build_investigation  # noqa: E402
from app.services.mitre.enrich import enrich as mitre_enrich  # noqa: E402
from app.services.persist.detections import upsert_detections  # noqa: E402
from app.services.persist.incidents import upsert_incidents  # noqa: E402
from app.services.ueba.attach import attach_ueba  # noqa: E402
from test_correlate_rules import devt  # noqa: E402
from test_ueba_enrich import fit_model  # noqa: E402


def bucketed(det, bucket):
    return det.model_copy(update={"bucket_event_ids": sorted(set(bucket))})


def ns_incident(**kw):
    base = {
        "incident_id": "inc-1", "title": "T", "severity": "HIGH", "status": "OPEN",
        "confidence": 0.8, "reason": "r", "risk_score": 60, "risk_band": "HIGH",
        "risk_explanation": "Risk 60 (HIGH) is elevated.",
        "first_seen": "2026-09-03T09:00:00", "last_seen": "2026-09-03T09:05:00",
        "created_at": "2026-09-03T09:06:00", "updated_at": "2026-09-03T09:06:00",
        "detection_ids": [], "evidence_event_ids": [],
        "incident_metadata": {}, "mitre_techniques": [], "risk_breakdown": {},
        "ueba_evidence": {"available": False},
    }
    base.update(kw)
    return SimpleNamespace(**base)


def ns_det(detection_id, rule_id="AUTH-001", first="2026-09-03T09:00:00", **kw):
    base = {
        "detection_id": detection_id, "rule_id": rule_id, "rule_name": f"Rule {rule_id}",
        "severity": "HIGH", "confidence": 0.8, "reason": "r",
        "first_seen": first, "last_seen": first,
        "evidence_event_ids": [f"{detection_id}-e1"], "bucket_event_ids": [],
        "metadata": {},
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_contract_schema_keys():
    out = build_investigation(ns_incident(), [], [])
    assert set(out) == {"incident", "explanation", "timeline", "entities", "detections",
                        "evidence_sample", "evidence_total", "mitre_techniques", "ueba",
                        "risk", "missing_detections"}


def test_timeline_ordering_tiebreak():
    a = ns_det("det-b", first="2026-09-03T09:00:00")
    b = ns_det("det-a", first="2026-09-03T09:00:00")
    c = ns_det("det-c", first="2026-09-03T08:00:00")
    out = build_investigation(ns_incident(), [a, b, c], [])
    assert [t["detection_id"] for t in out["timeline"]] == ["det-c", "det-a", "det-b"]


def test_entities_from_sample_only():
    ev = SimpleNamespace(event_id="e1", timestamp="2026-09-03T09:00:00",
                         event_type="x", source="s", host=None, user="u1",
                         source_ip="10.0.0.5", destination_ip="10.0.0.10",
                         destination_port=443, protocol="TCP", process_name=None,
                         command_line=None, status=None, raw_event={})
    out = build_investigation(ns_incident(), [], [ev])
    assert out["entities"]["source_ips"] == ["10.0.0.5"]
    assert out["entities"]["ports"] == [443]
    assert out["entities"]["hosts"] == []


def test_evidence_traceability_and_buckets():
    d = ns_det("det-1")
    d.evidence_event_ids = ["e1", "e2"]
    d.bucket_event_ids = ["e1", "e2", "e3"]
    out = build_investigation(ns_incident(detection_ids=["det-1"]), [d], [])
    (trace,) = out["detections"]
    assert trace["evidence_event_ids"] == ["e1", "e2"]
    assert trace["bucket_event_ids"] == ["e1", "e2", "e3"]
    assert trace["bucket_available"] is True
    assert trace["fingerprint"] == "FLOW-X:e1,e2" or trace["fingerprint"].startswith("AUTH-001:")


def test_mitre_grouped_by_detection():
    techs = [{"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence",
              "source_rule_id": "AUTH-001", "rationale": "r", "confidence": 0.7,
              "catalog_version": "v1"}]
    out = build_investigation(ns_incident(mitre_techniques=techs), [ns_det("d1")], [])
    assert out["timeline"][0]["mitre_technique_ids"] == ["T1078"]
    assert out["explanation"]["mitre_context"][0]["rule_ids"] == ["AUTH-001"]


def test_ueba_states():
    off = build_investigation(ns_incident(), [], [])
    assert off["ueba"]["available"] is False
    assert "No UEBA" in off["ueba"]["note"]
    assert "UEBA evidence" in off["explanation"]["unavailable"]
    on = build_investigation(ns_incident(ueba_evidence={"available": True, "anomaly_flag": True,
                                                        "anomaly_score": 0.9, "model_version": "m1"}), [], [])
    assert on["ueba"]["anomaly_flag"] is True
    assert "UEBA evidence" not in on["explanation"]["unavailable"]


def test_risk_factors_only_nonzero():
    out = build_investigation(ns_incident(risk_breakdown={"severity_points": 10, "diversity_points": 0,
                                                          "sequence_points": 5}), [], [])
    factors = {f["factor"]: f["points"] for f in out["explanation"]["risk_factors"]}
    assert factors.get("incident severity") == 10
    assert "multiple distinct detection rules" not in factors
    assert any("sequence" in f["factor"] for f in out["explanation"]["risk_factors"])


def test_missing_data_marked_not_fabricated():
    out = build_investigation(ns_incident(), [], [], expected_detection_ids=["ghost"])
    assert out["missing_detections"] == ["ghost"]
    assert any("ghost" in u for u in out["explanation"]["unavailable"])
    blob = json.dumps(out, default=str)
    assert "alice" not in blob and "unknown-user" not in blob


def test_no_fabricated_fields():
    d = ns_det("det-1")
    out = build_investigation(ns_incident(), [d], [])
    blob = json.dumps(out, default=str)
    assert "Not available" in blob
    assert "user" not in out["entities"]["users"]


def test_deterministic_repeat():
    d = ns_det("det-1")
    first = json.dumps(build_investigation(ns_incident(), [d], []), default=str, sort_keys=True)
    second = json.dumps(build_investigation(ns_incident(), [d], []), default=str, sort_keys=True)
    assert first == second


def test_endpoint_contract(client):
    from app.db.database import get_db

    gen = client.app.dependency_overrides[get_db]()
    try:
        db = next(gen)
        try:
            wrapped, dets, evts = _seeded_via_db(client, db)
            iid = wrapped.incident_id
        finally:
            gen.close()
    except StopIteration:
        raise AssertionError("db fixture failed")
    r = client.get(f"/api/v1/incidents/{iid}/investigation")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident"]["incident_id"] == iid
    assert len(body["timeline"]) == 1
    assert body["detections"][0]["bucket_available"] is True
    assert body["entities"]["users"] == ["alice"]
    assert body["missing_detections"] == []


def _seeded_via_db(client, db):
    from test_ueba_enrich import incident_for_dets

    from conftest import make_event

    evts = [make_event(event_id="inv-evt-1", user="alice"),
            make_event(event_id="inv-evt-2", user="alice")]
    for e in evts:
        assert client.post("/api/v1/events", json=e).status_code == 201
    dets = [devt("AUTH-001", user="alice", start_min=0,
                 evidence=["inv-evt-1"]).model_copy(
                     update={"bucket_event_ids": ["inv-evt-1", "inv-evt-2"]})]
    by_id = {e["event_id"]: e for e in evts}
    enr, _mp = incident_for_dets(dets, by_id)
    from app.services.ueba.attach import attach_ueba

    (wrapped,) = attach_ueba([enr], by_id, fit_model([]))
    assert upsert_detections(db, dets) == (1, 0)
    assert upsert_incidents(db, [wrapped]) == (1, 0)
    return wrapped, dets, evts


def test_endpoint_404(client):
    assert client.get("/api/v1/incidents/nope/investigation").status_code == 404
