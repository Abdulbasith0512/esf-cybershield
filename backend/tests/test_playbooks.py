"""Slice 39 tests: analyst response recommendations. No PG needed."""

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.investigate import build_investigation  # noqa: E402
from app.services.persist.detections import upsert_detections  # noqa: E402
from app.services.persist.incidents import upsert_incidents  # noqa: E402
from app.services.playbooks import recommend  # noqa: E402
from test_correlate_rules import devt  # noqa: E402
from test_ueba_enrich import fit_model  # noqa: E402

BANNED = ["confirmed attack", "attacker", "malware", "compromised",
          "exfiltration confirmed", "proven breach"]


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


def ns_det(detection_id, rule_id="FLOW-001", first="2026-09-03T09:00:00", **kw):
    base = {
        "detection_id": detection_id, "rule_id": rule_id, "rule_name": f"Rule {rule_id}",
        "severity": "MEDIUM", "confidence": 0.6, "reason": "r",
        "first_seen": first, "last_seen": first,
        "evidence_event_ids": [f"{detection_id}-e1"], "bucket_event_ids": [],
        "metadata": {},
    }
    base.update(kw)
    return SimpleNamespace(**base)


def inv_for(rule_id, severity="MEDIUM", **kw):
    return build_investigation(
        ns_incident(severity=severity, **kw),
        [ns_det("det-1", rule_id=rule_id, severity=severity)], [])


def test_each_flow_rule_gets_recommendation():
    for rule_id in ("FLOW-001", "FLOW-002", "FLOW-003",
                    "FLOW-004", "FLOW-005", "FLOW-006"):
        recs = recommend(inv_for(rule_id))
        ids = [r["id"] for r in recs]
        assert "rec-triage" in ids
        assert f"rec-network-{rule_id}" in ids


def test_priority_differs_by_severity():
    hi = {r["id"]: r["priority"] for r in recommend(inv_for("FLOW-002", "CRITICAL"))}
    lo = {r["id"]: r["priority"] for r in recommend(inv_for("FLOW-005", "LOW"))}
    assert hi["rec-triage"] == "HIGH"
    assert lo["rec-triage"] == "LOW"
    assert any(r["category"] == "CONTAINMENT"
               for r in recommend(inv_for("FLOW-002", "CRITICAL")))
    assert not any(r["category"] == "CONTAINMENT"
                   for r in recommend(inv_for("FLOW-005", "LOW")))


def test_deterministic_and_ordered():
    inv = inv_for("FLOW-001", "HIGH")
    first = recommend(inv)
    second = recommend(inv)
    assert json.dumps(first, sort_keys=True, default=str) == \
        json.dumps(second, sort_keys=True, default=str)
    order = ["TRIAGE", "NETWORK", "ENDPOINT", "IDENTITY", "MITRE", "UEBA", "CONTAINMENT"]
    cats = [r["category"] for r in first]
    assert cats == sorted(cats, key=order.index)
    assert len({r["id"] for r in first}) == len(first)


def test_missing_contexts_ok():
    inv = build_investigation(ns_incident(severity="LOW"), [], [])
    recs = recommend(inv)
    assert [r["id"] for r in recs] == ["rec-triage"]
    assert recs[0]["actions"] and recs[0]["evidence_refs"]["detection_count"] == 0


def test_recommend_is_pure():
    inv = inv_for("FLOW-003", "HIGH")
    snap = copy.deepcopy(inv)
    recommend(inv)
    assert inv == snap


def test_evidence_refs_capped():
    dets = [ns_det(f"det-{i:03d}", rule_id="FLOW-006", severity="HIGH")
            for i in range(40)]
    inv = build_investigation(ns_incident(severity="HIGH"), dets, [])
    recs = recommend(inv)
    triage = next(r for r in recs if r["id"] == "rec-triage")
    assert triage["evidence_refs"]["detection_count"] == 40
    assert len(triage["evidence_refs"]["detection_ids"]) <= 25
    assert triage["evidence_refs"]["detection_ids"] == \
        sorted(triage["evidence_refs"]["detection_ids"])


def test_mitre_and_ueba_and_identity_sections():
    techs = [{"technique_id": "T1110", "technique_name": "Brute Force",
              "tactic": "Credential Access", "source_rule_id": "AUTH-001",
              "confidence": 0.85,
              "rationale": "Multiple failed authentications followed by success."}]
    inv = build_investigation(
        ns_incident(severity="HIGH", mitre_techniques=techs),
        [ns_det("det-1", rule_id="AUTH-001", severity="HIGH")], [])
    inv["ueba"] = {"available": True, "anomaly_flag": True,
                   "anomaly_score": 0.9, "model_version": "test-v1"}
    recs = recommend(inv)
    cats = {r["category"] for r in recs}
    assert {"TRIAGE", "IDENTITY", "MITRE", "UEBA", "CONTAINMENT"} <= cats
    mitre = next(r for r in recs if r["category"] == "MITRE")
    assert mitre["evidence_refs"]["technique_id"] == "T1110"


def test_language_guarded():
    corpus = []
    for rule_id in ("FLOW-001", "FLOW-002", "FLOW-003",
                    "FLOW-004", "FLOW-005", "FLOW-006"):
        for sev in ("LOW", "HIGH", "CRITICAL"):
            for r in recommend(inv_for(rule_id, sev)):
                corpus.append(r["title"] + " " + r["reason"] + " " + " ".join(r["actions"]))
    blob = " ".join(corpus).lower()
    for phrase in BANNED:
        assert phrase not in blob


def _seeded_via_db(client, db):
    from test_ueba_enrich import incident_for_dets

    from conftest import make_event

    evts = [make_event(event_id="rec-evt-1", user="alice"),
            make_event(event_id="rec-evt-2", user="alice")]
    for e in evts:
        assert client.post("/api/v1/events", json=e).status_code == 201
    dets = [devt("AUTH-001", user="alice", start_min=0,
                 evidence=["rec-evt-1"]).model_copy(
                     update={"bucket_event_ids": ["rec-evt-1", "rec-evt-2"]})]
    by_id = {e["event_id"]: e for e in evts}
    enr, _mp = incident_for_dets(dets, by_id)
    (wrapped,) = __import__("app.services.ueba.attach",
                            fromlist=["attach_ueba"]).attach_ueba([enr], by_id, fit_model([]))
    assert upsert_detections(db, dets) == (1, 0)
    assert upsert_incidents(db, [wrapped]) == (1, 0)
    return wrapped


def test_endpoint_contract(client):
    from app.db.database import get_db

    gen = client.app.dependency_overrides[get_db]()
    try:
        db = next(gen)
        try:
            wrapped = _seeded_via_db(client, db)
            iid = wrapped.incident_id
        finally:
            gen.close()
    except StopIteration:
        raise AssertionError("db fixture failed")
    r = client.get(f"/api/v1/incidents/{iid}/recommendations")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident_id"] == iid
    assert body["recommendations"]
    assert body["recommendations"][0]["category"] == "TRIAGE"
    assert all({"id", "priority", "category", "title", "reason",
                "actions", "evidence_refs"} <= set(rec) for rec in body["recommendations"])
    assert client.get("/api/v1/incidents/nope/recommendations").status_code == 404
