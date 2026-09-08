"""Network-aware FLOW correlation tests (Slice 14). Fixtures only."""

import sys
from datetime import datetime, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.correlate import correlate  # noqa: E402
from app.services.correlate.config import CorrelatorConfig  # noqa: E402
from app.services.correlate.rules import (  # noqa: E402
    _network_key,
    linked,
    resolve_entities,
    resolve_network,
)
from app.services.detect.models import DetectionResult, detection_id_for  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0)  # naive UTC, like engine timestamps
CFG = CorrelatorConfig()
_n = 0


def fdet(rule_id, evidence, bucket, meta, start_min=0, dur_min=1,
         severity="MEDIUM", conf=0.6):
    """FLOW-style detection with explicit bucket membership."""
    global _n
    _n += 1
    ev = sorted(evidence)
    return DetectionResult(
        detection_id=detection_id_for(rule_id, ev) + f"-n{_n}",
        rule_id=rule_id, rule_name=f"Rule {rule_id}", severity=severity,
        confidence=conf, reason=f"{rule_id} fired", evidence_event_ids=ev,
        bucket_event_ids=sorted(set(bucket)),
        first_seen=T0 + timedelta(minutes=start_min),
        last_seen=T0 + timedelta(minutes=start_min + dur_min),
        metadata=dict(meta))


def flink(a, b, config=CFG):
    ent = resolve_entities([a, b], None)
    return linked(a, b, ent, config)


def m001(ip="172.31.69.25"):
    return {"key": ip, "count": 9000}


def m004(ip="172.31.69.25"):
    return {"key": ip, "peak_byts": 5_000_000}


def m006(ip="172.31.69.25"):
    return {"key": ip, "flow_count": 600}


# A. same service + overlapping bucket links.
def test_flow001_004_overlap_links():
    a = fdet("FLOW-001", ["a1"], ["a1", "s1", "s2"], m001(), start_min=0)
    b = fdet("FLOW-004", ["b1"], ["b1", "s1", "s2"], m004(), start_min=5)
    ok, sig = flink(a, b)
    assert ok and sig["shared_bucket"] == ["s1", "s2"] and not sig["sequenced"]
    incs = correlate([a, b])
    assert len(incs) == 1 and len(incs[0].detection_ids) == 2
    assert incs[0].metadata["network_entities"] == [["host", "172.31.69.25"]]


# B/C. same IP, disjoint buckets, no sequence pair -> separate.
def test_flow001_004_disjoint_ports_no_link():
    a = fdet("FLOW-001", ["a1"], ["a1", "a2"], m001(), start_min=0)
    b = fdet("FLOW-004", ["b1"], ["b1", "b2"], m004(), start_min=5)
    ok, sig = flink(a, b)
    assert not ok and sig == {}
    assert len(correlate([a, b])) == 2


# D. scan + brute sequence links only with overlap satisfied.
def test_flow003_002_sequence_needs_overlap():
    scan = fdet("FLOW-003", ["s1"], ["s1", "s2"],
                {"source_ip": "10.1.2.3", "distinct_ports": 15}, start_min=0)
    brute = fdet("FLOW-002", ["r1"], ["r1", "s2"],
                 {"key": "172.31.69.25|22", "qualifying_count": 20}, start_min=10)
    ok, sig = flink(scan, brute)
    assert ok and sig["sequenced"]
    far = fdet("FLOW-002", ["r9"], ["r9", "r10"],
               {"key": "172.31.69.25|22", "qualifying_count": 20}, start_min=10)
    assert flink(scan, far) == (False, {})


# E. entropy fallback never bridges.
def test_flow003_entropy_no_bridge():
    e1 = fdet("FLOW-003", ["x1"], ["x1", "x2"],
              {"entropy_bits": 4.5, "flow_count": 30, "mode": "global-fallback"})
    e2 = fdet("FLOW-003", ["x1"], ["x1", "x3"],
              {"entropy_bits": 4.2, "flow_count": 28, "mode": "global-fallback"})
    a = fdet("FLOW-001", ["a1"], ["x1", "a2"], m001())
    assert flink(e1, e2) == (False, {})
    assert flink(e1, a) == (False, {})
    assert resolve_network([e1])[e1.detection_id] is None


# F. configured 001 -> 006 sequence links without overlap.
def test_flow001_006_sequence_links():
    a = fdet("FLOW-001", ["a1"], ["a1"], m001(), start_min=0)
    b = fdet("FLOW-006", ["b1"], ["b1"], m006(), start_min=10)
    ok, sig = flink(a, b)
    assert ok and sig["sequenced"] and sig["shared_bucket"] == []


# G. outside the network window -> separate.
def test_flow_outside_window_no_link():
    a = fdet("FLOW-001", ["a1"], ["a1", "s1"], m001(), start_min=0)
    b = fdet("FLOW-004", ["b1"], ["b1", "s1"], m004(), start_min=120)
    assert flink(a, b) == (False, {})


# H. benign shared service with disjoint buckets stays separate.
def test_flow_benign_service_no_merge():
    dets = [fdet("FLOW-001", [f"e{i}"], [f"e{i}", f"f{i}"], m001("172.31.0.2"),
                 start_min=i * 5) for i in range(3)]
    assert len(correlate(dets)) == 3


# I. overlap outside capped evidence still links.
def test_flow_bucket_overlap_ignores_evidence_cap():
    a = fdet("FLOW-001", ["only-a"], ["only-a", "shared-9"], m001())
    b = fdet("FLOW-004", ["only-b"], ["only-b", "shared-9"], m004())
    ok, sig = flink(a, b)
    assert ok and sig["shared_bucket"] == ["shared-9"]


# Cross-entity overlap without a sequence pair stays separate (conservative).
def test_flow_cross_entity_overlap_no_link():
    a = fdet("FLOW-001", ["a1"], ["a1", "s1"], m001("172.31.69.25"))
    b = fdet("FLOW-003", ["b1"], ["b1", "s1"],
             {"source_ip": "10.9.9.9", "distinct_ports": 15})
    assert flink(a, b) == (False, {})


# J. shuffle determinism.
def test_flow_shuffle_determinism():
    import random  # noqa: E402

    a = fdet("FLOW-001", ["a1"], ["a1", "s1"], m001(), start_min=0)
    b = fdet("FLOW-004", ["b1"], ["b1", "s1"], m004(), start_min=5)
    c = fdet("FLOW-001", ["c1"], ["c1"], m001("172.31.0.2"), start_min=0)
    d = fdet("FLOW-006", ["d1"], ["d1"], m006("172.31.0.2"), start_min=8)
    base = [(i.incident_id, i.fingerprint) for i in correlate([a, b, c, d])]
    rng = random.Random(14)
    for _ in range(3):
        order = [a, b, c, d]
        rng.shuffle(order)
        assert [(i.incident_id, i.fingerprint) for i in correlate(order)] == base


# L. FLOW never enters the old user+host branch.
def test_flow_never_old_branch():
    a = fdet("FLOW-001", ["same"], ["a1"], m001(), start_min=0)
    b = fdet("FLOW-004", ["same"], ["b1"], m004(), start_min=5)
    ok, sig = flink(a, b)
    assert not ok
    assert "same_user" not in sig and "same_host" not in sig


# M. duplicate fingerprints still dedupe.
def test_flow_duplicates_dedupe():
    a = fdet("FLOW-001", ["a1"], ["a1", "s1"], m001())
    b = fdet("FLOW-001", ["a1"], ["a1", "s9"], m001())
    assert a.fingerprint == b.fingerprint
    incs = correlate([a, b])
    assert len(incs) == 1 and incs[0].detection_ids == [a.detection_id]


# N. null identities never link.
def test_flow_null_identities_no_link():
    g = fdet("FLOW-001", ["a1"], ["a1", "s1"], {"key": "GLOBAL"})
    m = fdet("FLOW-001", ["b1"], ["b1", "s1"], {})
    q = fdet("FLOW-004", ["c1"], ["c1", "s1"], {"key": "?"})
    for x, y in ((g, m), (g, q), (m, q)):
        assert flink(x, y) == (False, {})
    net = resolve_network([g, m, q])
    assert set(net.values()) == {None}


def test_flow005_same_pair_overlap_links():
    a = fdet("FLOW-005", ["a1"], ["a1", "s1"],
             {"protocol": "TCP", "destination_port": 4443})
    b = fdet("FLOW-005", ["b1"], ["b1", "s1"],
             {"protocol": "TCP", "destination_port": 4443})
    ok, sig = flink(a, b)
    assert ok and not sig["sequenced"]
    other = fdet("FLOW-005", ["c1"], ["c1"],
                 {"protocol": "TCP", "destination_port": 443})
    assert flink(a, other) == (False, {})


def test_network_key_contract():
    assert _network_key("FLOW-001", {"key": "10.0.0.9"}) == ("host", "10.0.0.9")
    assert _network_key("FLOW-001", {"key": "GLOBAL"}) is None
    assert _network_key("FLOW-002", {"key": "10.0.0.9|22"}) == ("service", "10.0.0.9", "22")
    assert _network_key("FLOW-002", {"key": "GLOBAL|?"}) is None
    assert _network_key("FLOW-003", {"source_ip": "10.1.2.3"}) == ("scanner", "10.1.2.3")
    assert _network_key("FLOW-003", {"mode": "global-fallback"}) is None
    assert _network_key("FLOW-005", {"protocol": "TCP", "destination_port": 4443}) == (
        "ppsvc", "TCP", "4443")
    assert _network_key("AUTH-001", {"user": "alice"}) is None
