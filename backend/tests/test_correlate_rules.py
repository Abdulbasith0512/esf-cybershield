"""Correlation rule tests: linking, resolution, scoring, severity, text."""

import sys
from datetime import datetime, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.correlate.config import CorrelatorConfig  # noqa: E402
from app.services.correlate.rules import (  # noqa: E402
    build_incident,
    derive_severity,
    linked,
    resolve_entities,
    score_group,
)
from app.services.detect.models import DetectionResult, detection_id_for  # noqa: E402

T0 = datetime(2026, 9, 3, 9, 0, 0)  # naive UTC, like engine timestamps
CFG = CorrelatorConfig()
_n = 0


def devt(rule_id="AUTH-001", user="alice", host="WIN-001", start_min=0,
         dur_min=1, evidence=None, severity="HIGH", conf=0.8, extra_meta=None):
    global _n
    _n += 1
    ev = evidence or [f"evt-c{_n:04d}"]
    meta = {"user": user, "host": host}
    meta.update(extra_meta or {})
    return DetectionResult(
        detection_id=detection_id_for(rule_id, ev), rule_id=rule_id,
        rule_name=f"Rule {rule_id}", severity=severity, confidence=conf,
        reason=f"{rule_id} fired", evidence_event_ids=sorted(ev),
        first_seen=T0.replace(minute=0) + timedelta(minutes=start_min),
        last_seen=T0.replace(minute=0) + timedelta(minutes=start_min + dur_min),
        metadata=meta)


def evmap(*dets, user="alice", host="WIN-001"):
    m = {}
    for d in dets:
        for eid in d.evidence_event_ids:
            m[eid] = {"user": user, "host": host, "source_ip": "10.0.0.1"}
    return m


def link(a, b, emap=None, config=CFG):
    ent = resolve_entities([a, b], emap)
    return linked(a, b, ent, config)


def test_link_same_user_host_window_sequence():
    a = devt("AUTH-001", start_min=0)
    b = devt("PROC-001", start_min=5)
    ok, sig = link(a, b, evmap(a, b))
    assert ok and sig["sequenced"] and sig["same_user"] and sig["same_host"]


def test_no_link_different_user():
    a = devt("AUTH-001", user="alice")
    b = devt("PROC-001", user="bob")
    m = evmap(a, user="alice")
    m.update(evmap(b, user="bob"))
    ok, _ = link(a, b, m)
    assert not ok


def test_no_link_different_host():
    a = devt("AUTH-001", host="WIN-001")
    b = devt("PROC-001", host="WIN-002")
    m = evmap(a, host="WIN-001")
    m.update(evmap(b, host="WIN-002"))
    ok, _ = link(a, b, m)
    assert not ok


def test_no_link_outside_window():
    a = devt("AUTH-001", start_min=0)
    b = devt("PROC-001", start_min=360)  # 6h later
    ok, _ = link(a, b, evmap(a, b))
    assert not ok


def test_link_at_window_edge():
    a = devt("AUTH-001", start_min=0, dur_min=1)
    b = devt("PROC-001", start_min=31, dur_min=1)  # gap exactly 30 min
    ok, sig = link(a, b, evmap(a, b))
    assert ok and sig["gap_minutes"] == 30.0


def test_no_link_unrelated_pair():
    # Same user/host/window but no shared evidence and no sequence pair.
    a = devt("AUTH-002", start_min=0)
    b = devt("AUTH-003", start_min=5)
    ok, _ = link(a, b, evmap(a, b))
    assert not ok


def test_link_shared_evidence_without_sequence():
    # Same unrelated pair, but sharing one evidence event -> strong link.
    shared = ["evt-shared-1"]
    a = devt("AUTH-002", start_min=0, evidence=shared + ["evt-a2"], severity="MEDIUM")
    b = devt("AUTH-003", start_min=5, evidence=shared + ["evt-b2"], severity="MEDIUM")
    ok, sig = link(a, b, evmap(a, b))
    assert ok and sig["shared_evidence"] == shared and not sig["sequenced"]


def test_resolve_unknown_never_matches():
    a = devt("NET-002", start_min=0, extra_meta={"user": "unknown", "host": "unknown"})
    b = devt("NET-002", start_min=5, extra_meta={"user": "unknown", "host": "unknown"})
    ok, _ = link(a, b, None)
    assert not ok


def test_resolve_anchor_host_fallback():
    a = devt("AUTH-001", start_min=0, host=None,
             extra_meta={"user": "alice", "anchor": "host:WIN-007"})
    ent = resolve_entities([a], None)
    assert ent[a.detection_id] == ("alice", "WIN-007")


def test_resolve_split_evidence_no_match():
    a = devt("PROC-001", start_min=0, evidence=["e1", "e2"])
    m = {"e1": {"user": "alice", "host": "WIN-001"},
         "e2": {"user": "bob", "host": "WIN-001"}}
    ent = resolve_entities([a], m)
    assert ent[a.detection_id][0] is None  # ambiguous user -> no match


def test_severity_table():
    med = devt("AUTH-002", severity="MEDIUM")
    assert derive_severity([med], CFG) == "MEDIUM"
    hi = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    assert derive_severity(hi, CFG) == "HIGH"
    chain3 = hi + [devt("NET-001", start_min=9)]
    assert derive_severity(chain3, CFG) == "HIGH"
    chain4 = chain3 + [devt("DATA-001", start_min=12)]
    assert derive_severity(chain4, CFG) == "CRITICAL"


def test_score_range_and_ordering():
    weak = [devt("AUTH-002", severity="MEDIUM", conf=0.55)]
    strong = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
              devt("NET-001", start_min=9), devt("DATA-001", start_min=12)]
    s1 = score_group(weak, [], CFG)
    links = [{"shared_evidence": ["e1"], "sequenced": True}]
    s2 = score_group(strong, links, CFG)
    assert 0.0 <= s1 <= 1.0 and 0.0 <= s2 <= 1.0 and s2 > s1


def test_title_reason_content():
    members = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
               devt("NET-001", start_min=9), devt("DATA-001", start_min=12)]
    inc = build_incident(members, "alice", "WIN-001", [], CFG)
    assert inc.title == "Potential Credential Compromise with Suspicious Data Transfer"
    assert inc.incident_id not in inc.title
    assert "2026" not in inc.title
    for token in ("Confirmed attacker", "Confirmed breach", "Confirmed compromise"):
        assert token not in inc.reason
    assert "AUTH-001" in inc.reason and "alice" in inc.reason
    assert inc.evidence_event_ids == sorted(inc.evidence_event_ids)
    assert len(set(inc.evidence_event_ids)) == len(inc.evidence_event_ids)
