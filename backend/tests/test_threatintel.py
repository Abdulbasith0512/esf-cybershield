"""Slice 40 tests: threat-intel / IOC enrichment. No PG, no network."""

import copy
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.threatintel import (  # noqa: E402
    LocalThreatIntelProvider,
    ThreatIntelCache,
    ThreatIntelError,
    ThreatIntelProvider,
    enrich_incident,
    extract_observables,
    normalize_observable,
)
from app.services.threatintel.models import Observable  # noqa: E402
from app.services.persist.detections import upsert_detections  # noqa: E402
from app.services.persist.incidents import upsert_incidents  # noqa: E402
from test_correlate_rules import devt  # noqa: E402
from test_ueba_enrich import fit_model  # noqa: E402

NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)


def ns_event(event_id, timestamp="2026-09-03T09:00:00", **kw):
    base = {"event_id": event_id, "timestamp": timestamp, "source_ip": None,
            "destination_ip": None, "domain": None, "url": None, "file_hash": None}
    base.update(kw)
    return SimpleNamespace(**base)


def ns_det(detection_id, evidence):
    return SimpleNamespace(detection_id=detection_id, evidence_event_ids=list(evidence))


def obs(o_type="ipv4", value="198.51.100.23"):
    return Observable(type=o_type, value=value, normalized_value=value,
                      source="destination_ip", first_seen="t", last_seen="t",
                      event_count=1, event_ids=["e1"])


# 1. observable normalization
def test_normalization():
    assert normalize_observable("ip", "  192.168.1.20 ") == ("ipv4", "192.168.1.20")
    assert normalize_observable("ip", "2001:DB8::1") == ("ipv6", "2001:db8::1")
    assert normalize_observable("domain", "Example.COM.") == ("domain", "example.com")
    assert normalize_observable("url", "http://Example.COM/a") == ("url", "http://example.com/a")
    assert normalize_observable("file_hash", "E3B0" + "0" * 60) == (
        "file_hash", "e3b0" + "0" * 60)
    assert normalize_observable("ip", "198.51.100.23") == ("ipv4", "198.51.100.23")


# 2. malformed observable rejection
def test_malformed_rejected():
    for kind, bad in [("ip", "999.1.1.1"), ("ip", ""), ("ip", None),
                      ("ip", "not-an-ip"), ("domain", "no-dot-here"),
                      ("domain", "-bad.example"), ("domain", ""),
                      ("url", "ftp://example.com/x"), ("url", "no-scheme"),
                      ("url", ""), ("file_hash", "xyz"), ("file_hash", "ab" * 10),
                      ("file_hash", ""), ("email", "a@b.com"), ("", "1.2.3.4")]:
        assert normalize_observable(kind, bad) is None, (kind, bad)


# 3. deterministic IOC extraction
def test_extraction_deterministic():
    rows = [ns_event("e1", destination_ip="198.51.100.23", source_ip="10.0.0.5"),
            ns_event("e2", "2026-09-03T09:01:00", destination_ip="198.51.100.23",
                     domain="Malware-Test.INVALID")]
    first = extract_observables(rows)
    second = extract_observables(list(reversed(rows)))
    assert (json.dumps([o.model_dump() for o in first], sort_keys=True)
            == json.dumps([o.model_dump() for o in second], sort_keys=True))
    assert [(o.type, o.normalized_value) for o in first] == sorted(
        (o.type, o.normalized_value) for o in first)


# 4. deduplication
def test_extraction_dedup():
    rows = [ns_event(f"e{i}", source_ip="10.0.0.5") for i in range(5)]
    out = extract_observables(rows)
    assert len(out) == 1 and out[0].event_count == 5
    assert out[0].event_ids == sorted(f"e{i}" for i in range(5))


# 5. source attribution
def test_source_attribution():
    rows = [ns_event("e1", source_ip="10.0.0.5", destination_ip="10.0.0.5")]
    by_source = {(o.normalized_value, o.source) for o in extract_observables(rows)}
    assert ("10.0.0.5", "source_ip") in by_source
    assert ("10.0.0.5", "destination_ip") in by_source


# 6/7/8. local provider fixture results
def test_local_provider_fixtures():
    provider = LocalThreatIntelProvider()
    assert provider.name == "local-test"
    assert provider.lookup(obs("ipv4", "203.0.113.7")).classification == "benign"
    assert provider.lookup(obs("ipv4", "198.51.100.45")).classification == "suspicious"
    assert provider.lookup(obs("ipv4", "198.51.100.23")).classification == "malicious"
    assert provider.lookup(obs("domain", "malware-test.invalid")).classification == "malicious"
    assert provider.lookup(obs("file_hash",
                               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                           ).classification == "benign"
    for result in (provider.lookup(obs("ipv4", "203.0.113.7")),
                   provider.lookup(obs("ipv4", "198.51.100.23"))):
        assert result.provider == "local-test"
        assert result.metadata.get("fixture") is True
        assert 0.0 <= result.confidence <= 1.0


# 9. unknown observable
def test_unknown_observable():
    result = LocalThreatIntelProvider().lookup(obs("ipv4", "10.9.9.9"))
    assert result.classification == "unknown" and result.confidence == 0.0


class _FailingProvider(ThreatIntelProvider):
    name = "boom"

    def lookup(self, observable):
        raise ThreatIntelError("simulated outage")


# 10. provider failure behavior
def test_provider_failure_degrades():
    rows = [ns_event("e1", destination_ip="198.51.100.23")]
    out = enrich_incident("inc-1", rows, [ns_det("det-1", ["e1"])],
                          _FailingProvider(), now=NOW)
    assert len(out) == 1
    assert out[0].available is False and out[0].intelligence is None
    assert "boom" in (out[0].error or "")
    assert out[0].detection_ids == ["det-1"] and out[0].incident_id == "inc-1"


# 11. deterministic enrichment
def test_enrichment_deterministic():
    rows = [ns_event("e1", destination_ip="198.51.100.23"),
            ns_event("e2", source_ip="10.0.0.5")]
    dets = [ns_det("det-1", ["e1", "e2"])]
    provider = LocalThreatIntelProvider()
    first = enrich_incident("inc-1", rows, dets, provider,
                            cache=ThreatIntelCache(), now=NOW)
    second = enrich_incident("inc-1", rows, dets, provider,
                             cache=ThreatIntelCache(), now=NOW)
    assert (json.dumps([e.model_dump() for e in first], sort_keys=True, default=str)
            == json.dumps([e.model_dump() for e in second], sort_keys=True, default=str))


# 12. incident traceability
def test_traceability():
    rows = [ns_event("e1", destination_ip="198.51.100.23"),
            ns_event("e2", destination_ip="198.51.100.23")]
    out = enrich_incident("inc-9", rows, [ns_det("det-a", ["e1"]),
                                          ns_det("det-b", ["e2", "zzz"])],
                          LocalThreatIntelProvider(), now=NOW)
    assert len(out) == 1
    assert out[0].detection_ids == ["det-a", "det-b"]
    assert out[0].observable.event_count == 2
    assert out[0].observable.event_ids == ["e1", "e2"]
    assert out[0].intelligence.classification == "malicious"


# 15. no modification of detections/evidence
def test_enrichment_is_pure():
    rows = [ns_event("e1", destination_ip="198.51.100.23")]
    dets = [ns_det("det-1", ["e1"])]
    rows_snap = copy.deepcopy([(r.event_id, r.destination_ip) for r in rows])
    dets_snap = copy.deepcopy([(d.detection_id, d.evidence_event_ids) for d in dets])
    enrich_incident("inc-1", rows, dets, LocalThreatIntelProvider(),
                    cache=ThreatIntelCache(), now=NOW)
    assert [(r.event_id, r.destination_ip) for r in rows] == rows_snap
    assert [(d.detection_id, d.evidence_event_ids) for d in dets] == dets_snap


# 16. benchmark labels never used by enrichment
def test_labels_never_used():
    rows = [ns_event("e1", destination_ip="10.9.9.9",
                     evaluation_only="Attack", Label="DoS")]
    out = enrich_incident("inc-1", rows, [], LocalThreatIntelProvider(), now=NOW)
    assert len(out) == 1
    assert out[0].intelligence.classification == "unknown"


# 17. no external network dependency
def test_no_network_dependency(monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("network access is forbidden in Slice 40")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    rows = [ns_event("e1", destination_ip="198.51.100.23"),
            ns_event("e2", domain="example.com")]
    out = enrich_incident("inc-1", rows, [], LocalThreatIntelProvider(), now=NOW)
    assert {e.observable.normalized_value: e.intelligence.classification for e in out} == {
        "198.51.100.23": "malicious", "example.com": "benign"}


def test_cache_hit_avoids_relookup():
    calls = []
    provider = LocalThreatIntelProvider()
    original = provider.lookup

    def _counting(observable):
        calls.append(observable.normalized_value)
        return original(observable)

    provider.lookup = _counting
    cache = ThreatIntelCache(ttl_seconds=3600)
    rows = [ns_event("e1", destination_ip="198.51.100.23")]
    enrich_incident("inc-1", rows, [], provider, cache=cache, now=NOW)
    enrich_incident("inc-1", rows, [], provider, cache=cache, now=NOW)
    assert calls == ["198.51.100.23"]


def _seeded_via_db(client, db):
    from test_ueba_enrich import incident_for_dets

    from conftest import make_event

    evts = [make_event(event_id="ti-evt-1", user="alice",
                       destination_ip="198.51.100.23"),
            make_event(event_id="ti-evt-2", user="alice",
                       destination_ip="198.51.100.23")]
    for e in evts:
        assert client.post("/api/v1/events", json=e).status_code == 201
    dets = [devt("AUTH-001", user="alice", start_min=0,
                 evidence=["ti-evt-1"]).model_copy(
                     update={"bucket_event_ids": ["ti-evt-1", "ti-evt-2"]})]
    by_id = {e["event_id"]: e for e in evts}
    enr, _mp = incident_for_dets(dets, by_id)
    from app.services.ueba.attach import attach_ueba

    (wrapped,) = attach_ueba([enr], by_id, fit_model([]))
    assert upsert_detections(db, dets) == (1, 0)
    assert upsert_incidents(db, [wrapped]) == (1, 0)
    return wrapped


# 13/14. API 200/404
def test_endpoint_contract(client):
    from app.db.database import get_db

    gen = client.app.dependency_overrides[get_db]()
    try:
        db = next(gen)
        try:
            wrapped = _seeded_via_db(client, db)
            iid = wrapped.incident_id
            before = (wrapped.enriched.incident.severity
                      if hasattr(wrapped, "enriched") else wrapped.incident.severity)
        finally:
            gen.close()
    except StopIteration:
        raise AssertionError("db fixture failed")
    r = client.get(f"/api/v1/incidents/{iid}/threat-intelligence")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident_id"] == iid and body["provider"] == "local-test"
    by_value = {o["observable"]["normalized_value"]: o for o in body["observables"]}
    assert by_value["198.51.100.23"]["intelligence"]["classification"] == "malicious"
    assert by_value["198.51.100.23"]["detection_ids"]
    assert all({"observable", "available", "intelligence", "detection_ids",
                "incident_id"} <= set(o) for o in body["observables"])
    # Enrichment changed nothing about the incident itself.
    after = client.get(f"/api/v1/incidents/{iid}").json()
    assert after["severity"] == before
    assert client.get("/api/v1/incidents/nope/threat-intelligence").status_code == 404
