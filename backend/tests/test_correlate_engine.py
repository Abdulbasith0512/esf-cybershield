"""Correlation engine tests: grouping, determinism, contract, leakage guard."""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402

from app.services.correlate.config import CorrelatorConfig  # noqa: E402
from app.services.correlate.engine import correlate  # noqa: E402
from app.services.correlate.fingerprint import group_fingerprint  # noqa: E402
from app.services.correlate.models import Incident, incident_id_for  # noqa: E402
from test_correlate_rules import CFG, devt, evmap  # noqa: E402


def corr(dets, emap=None, config=CFG):
    if emap is None:
        emap = {}
        for d in dets:
            emap.update(evmap(d))
    return correlate(dets, events_by_id=emap, config=config)


def test_auth_proc_one_incident():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    incs = corr(dets)
    assert len(incs) == 1 and incs[0].severity == "HIGH"
    assert set(incs[0].metadata["rule_ids"]) == {"AUTH-001", "PROC-001"}


def test_three_chain_stronger():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
            devt("NET-001", start_min=9)]
    incs = corr(dets)
    assert len(incs) == 1
    assert incs[0].severity == "HIGH"
    assert "Credential Compromise" in incs[0].title


def test_four_chain_critical():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
            devt("NET-001", start_min=9), devt("DATA-001", start_min=12)]
    incs = corr(dets)
    assert len(incs) == 1 and incs[0].severity == "CRITICAL"


def test_same_user_host_in_window_eligible():
    dets = [devt("PROC-001", start_min=0), devt("NET-001", start_min=20)]
    assert len(corr(dets)) == 1


def test_same_user_different_host_separate():
    a = devt("AUTH-001", host="WIN-001", start_min=0)
    b = devt("PROC-001", host="WIN-002", start_min=5)
    m = evmap(a, host="WIN-001")
    m.update(evmap(b, host="WIN-002"))
    assert len(corr([a, b], m)) == 2


def test_outside_window_separate():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=120)]
    assert len(corr(dets)) == 2


def test_shared_evidence_merges():
    a = devt("AUTH-002", start_min=0, evidence=["shared-1", "a2"], severity="MEDIUM")
    b = devt("AUTH-003", start_min=5, evidence=["shared-1", "b2"], severity="MEDIUM")
    incs = corr([a, b])
    assert len(incs) == 1
    assert "shared-1" in incs[0].evidence_event_ids


def test_duplicate_detections_no_dup_incidents():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    assert len(corr(dets + list(dets))) == 1


def test_out_of_order_same_output():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
            devt("NET-001", start_min=9)]
    a = [(i.incident_id, i.fingerprint) for i in corr(dets)]
    b = [(i.incident_id, i.fingerprint) for i in corr(list(reversed(dets)))]
    assert a == b


def test_repeat_same_ids_content():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    a, b = corr(dets), corr([d.model_copy(deep=True) for d in dets])
    assert [i.incident_id for i in a] == [i.incident_id for i in b]
    assert a[0].model_dump() == b[0].model_dump()


def test_different_users_separate():
    a = devt("AUTH-001", user="alice", start_min=0)
    b = devt("AUTH-001", user="mallory", start_min=2)
    m = evmap(a, user="alice")
    m.update(evmap(b, user="mallory"))
    assert len(corr([a, b], m)) == 2


def test_empty_list():
    assert correlate([]) == []


def test_single_detection_incident():
    dets = [devt("AUTH-002", severity="MEDIUM")]
    incs = corr(dets)
    assert len(incs) == 1 and incs[0].severity == "MEDIUM"
    assert incs[0].detection_ids == [dets[0].detection_id]


def test_evidence_and_detection_ids_preserved():
    dets = [devt("AUTH-001", start_min=0, evidence=["e1", "e2"]),
            devt("PROC-001", start_min=5, evidence=["e2", "e3"])]
    incs = corr(dets)
    assert len(incs) == 1
    assert incs[0].evidence_event_ids == ["e1", "e2", "e3"]
    assert incs[0].detection_ids == sorted(d.detection_id for d in dets)


def test_score_range_and_id_stability():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    incs = corr(dets)
    assert 0.0 <= incs[0].confidence <= 1.0
    assert incs[0].metadata["correlation_score"] == incs[0].confidence
    assert incs[0].incident_id == incident_id_for(incs[0].detection_ids)
    assert incs[0].fingerprint == group_fingerprint(incs[0].detection_ids)


def test_status_enum():
    dets = [devt("AUTH-001", start_min=0)]
    assert corr(dets)[0].status == "OPEN"
    with pytest.raises(Exception):
        Incident(**corr(dets)[0].model_dump() | {"status": "BOGUS"})


def test_severity_enum_rejected():
    with pytest.raises(Exception):
        Incident(**corr([devt("AUTH-001")])[0].model_dump() | {"severity": "EXTREME"})


def test_ground_truth_irrelevant():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    base = corr(dets)
    relabeled = []
    for d in dets:
        c = d.model_copy(deep=True)
        c.metadata["scenario_id"] = "tampered"
        c.metadata["scenario_type"] = "tampered"
        relabeled.append(c)
    assert [i.fingerprint for i in corr(relabeled)] == [i.fingerprint for i in base]


def test_irrelevant_metadata_no_regroup():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    base = corr(dets)
    altered = []
    for d in dets:
        c = d.model_copy(deep=True)
        c.confidence, c.reason = 0.99, "rewritten"
        altered.append(c)
    assert [i.fingerprint for i in corr(altered)] == [i.fingerprint for i in base]


def test_inputs_not_mutated():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    before = [d.model_dump() for d in dets]
    corr(dets)
    assert [d.model_dump() for d in dets] == before


def test_no_ground_truth_in_correlate_code():
    import ast

    pkg = Path(__file__).resolve().parents[1] / "app" / "services" / "correlate"
    targets = {"scenario_id", "scenario_type", "synthetic", "raw_event"}
    hits = []
    for path in pkg.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"
