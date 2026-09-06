"""MITRE mapping tests: catalog, provenance, determinism, leakage guard."""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.correlate.engine import correlate  # noqa: E402
from app.services.correlate.models import Incident  # noqa: E402
from app.services.mitre.enrich import enrich  # noqa: E402
from app.services.mitre.mapper import map_incident  # noqa: E402
from app.services.mitre.mapping import CATALOG_VERSION, RULE_TO_MITRE  # noqa: E402
from test_correlate_rules import CFG, devt, evmap  # noqa: E402


def incident_for(dets, emap=None):
    if emap is None:
        emap = {}
        for d in dets:
            emap.update(evmap(d))
    return correlate(dets, events_by_id=emap, config=CFG)[0]


def by_id(*dets):
    return {d.detection_id: d for d in dets}


def test_known_rule_mapping():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5,
             extra_meta={"pattern_id": "P1-shell-from-service"})]
    inc = incident_for(dets)
    maps = map_incident(inc, by_id(*dets))
    tids = {(m.technique_id, m.source_rule_id) for m in maps}
    assert ("T1110", "AUTH-001") in tids
    assert ("T1059", "PROC-001") in tids
    assert all(m.catalog_version == CATALOG_VERSION for m in maps)


def test_unknown_rule_no_mapping():
    dets = [devt("AUTH-002", severity="MEDIUM", start_min=0)]
    inc = incident_for(dets)
    assert map_incident(inc, by_id(*dets)) == []
    dets = [devt("NET-002", severity="MEDIUM", start_min=0)]
    assert map_incident(incident_for(dets), by_id(*dets)) == []


def test_mapping_confidence_range_and_rationale():
    dets = [devt("NET-001", start_min=0,
             extra_meta={"matched_ioc": {"indicator": "203.0.113.200"}})]
    for m in map_incident(incident_for(dets), by_id(*dets)):
        assert 0.0 <= m.confidence <= 1.0
        assert m.rationale and m.technique_name and m.tactic


def test_catalog_version_present():
    assert CATALOG_VERSION == "project-static-v1"
    assert set(RULE_TO_MITRE) == {"AUTH-001", "AUTH-003", "PROC-001",
                                  "PROC-002", "NET-001", "DATA-001"}


def test_duplicate_technique_provenance():
    # PROC-001 + PROC-002 both map T1059: one entry per (technique, rule).
    # Shared evidence links them into one incident for the mapping check.
    dets = [devt("PROC-001", start_min=0, evidence=["shared-x"],
                 extra_meta={"pattern_id": "P1-shell-from-service"}),
            devt("PROC-002", start_min=5, evidence=["shared-x"])]
    maps = map_incident(incident_for(dets), by_id(*dets))
    t1059 = sorted(m.source_rule_id for m in maps if m.technique_id == "T1059")
    assert t1059 == ["PROC-001", "PROC-002"]


def test_pattern_gating():
    # P1 detection must not yield the P2-only T1140 mapping.
    dets = [devt("PROC-001", start_min=0, extra_meta={"pattern_id": "P1-shell-from-service"})]
    tids = {m.technique_id for m in map_incident(incident_for(dets), by_id(*dets))}
    assert tids == {"T1059"}


def test_deterministic_and_order_invariant():
    dets = [devt("AUTH-001", start_min=0), devt("NET-001", start_min=5)]
    inc = incident_for(dets)
    a = [(m.technique_id, m.source_rule_id, m.confidence)
         for m in map_incident(inc, by_id(*dets))]
    b = [(m.technique_id, m.source_rule_id, m.confidence)
         for m in map_incident(inc, by_id(*reversed(dets)))]
    assert a == b
    assert map_incident(inc, by_id(*dets)) == map_incident(inc, by_id(*dets))


def test_unmapped_gets_nothing_fabricated():
    dets = [devt("AUTH-002", severity="MEDIUM", start_min=0),
            devt("NET-002", severity="MEDIUM", start_min=5)]
    assert map_incident(incident_for(dets), by_id(*dets)) == []


def test_enrich_preserves_incident():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    inc = incident_for(dets)
    (enr,) = enrich([inc], by_id(*dets))
    assert enr.incident == inc
    assert enr.incident_id == inc.incident_id
    assert {m.source_rule_id for m in enr.mitre_techniques} <= {"AUTH-001", "PROC-001"}


def test_no_ground_truth_in_mitre_code():
    import ast

    pkg = Path(__file__).resolve().parents[1] / "app" / "services" / "mitre"
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


def test_incident_model_untouched():
    assert set(Incident.model_fields) == {
        "incident_id", "title", "severity", "status", "confidence", "reason",
        "detection_ids", "evidence_event_ids", "first_seen", "last_seen", "metadata"}
