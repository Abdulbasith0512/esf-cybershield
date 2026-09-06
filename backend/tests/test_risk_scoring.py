"""Risk scoring tests: formula, bands, duplicates, determinism, leakage."""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.correlate.engine import correlate  # noqa: E402
from app.services.mitre.config import RiskConfig  # noqa: E402
from app.services.mitre.enrich import enrich  # noqa: E402
from app.services.mitre.mapper import map_incident  # noqa: E402
from app.services.mitre.scorer import score_risk  # noqa: E402
from test_correlate_rules import CFG, devt, evmap  # noqa: E402


def incident_for(dets, emap=None):
    if emap is None:
        emap = {}
        for d in dets:
            emap.update(evmap(d))
    return correlate(dets, events_by_id=emap, config=CFG)[0]


def scored(dets, emap=None):
    inc = incident_for(dets, emap)
    mp = {d.detection_id: d for d in dets}
    return score_risk(inc, mp, map_incident(inc, mp)) + (inc,)


def test_weak_single_low_score():
    score, _, _ = scored([devt("AUTH-002", severity="MEDIUM", conf=0.55)])[:3]
    assert score < 50


def test_higher_severity_higher_score():
    lo, _, _ = scored([devt("AUTH-002", severity="MEDIUM", conf=0.6)])[:3]
    hi, _, _ = scored([devt("AUTH-001", conf=0.8)])[:3]
    assert hi > lo


def test_distinct_rules_increase_risk():
    one, _, _ = scored([devt("AUTH-001", start_min=0)])[:3]
    two, _, _ = scored([devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)])[:3]
    assert two > one


def test_confidence_increases_risk():
    a, _, _ = scored([devt("AUTH-001", conf=0.61)])[:3]
    b, _, _ = scored([devt("AUTH-001", conf=0.95)])[:3]
    assert b > a


def test_ioc_increases_risk():
    plain, _, _ = scored([devt("AUTH-001", conf=0.8)])[:3]
    ioc, _, _ = scored([devt("NET-001", start_min=0, conf=0.8,
                             extra_meta={"matched_ioc": {"indicator": "x"}})])[:3]
    assert ioc > plain


def test_data_transfer_increases_risk():
    base, _, _ = scored([devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)])[:3]
    full, _, _ = scored([devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
                         devt("DATA-001", start_min=9,
                              extra_meta={"bytes_sent": 4_000_000_000, "threshold": 1_000_000_000})])[:3]
    assert full > base


def test_sequence_increases_risk():
    lone, _, _ = scored([devt("NET-001", start_min=0,
                              extra_meta={"matched_ioc": {"indicator": "x"}})])[:3]
    seq, _, _ = scored([devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
                        devt("NET-001", start_min=9,
                             extra_meta={"matched_ioc": {"indicator": "x"}})])[:3]
    assert seq > lone


def test_score_bounded_and_band_matches():
    cfg = RiskConfig()
    for dets in ([devt("AUTH-002", severity="MEDIUM")],
                 [devt("AUTH-001"), devt("PROC-001"), devt("NET-001"), devt("DATA-001")]):
        score, breakdown, _ = scored(dets)[:3]
        assert 0 <= score <= 100
        assert breakdown.total == score
        band = next(b for upper, b in cfg.bands if score <= upper)
        (enr,) = enrich([incident_for(dets)], {d.detection_id: d for d in dets})
        assert enr.risk_band == band


def test_deterministic_and_order_invariant():
    dets = [devt("AUTH-001", start_min=0), devt("NET-001", start_min=5)]
    a = scored(dets)
    b = scored(list(reversed(dets)))
    assert a[:2] == b[:2]


def test_duplicates_dont_multiply():
    dets = [devt("NET-001", start_min=0, extra_meta={"matched_ioc": {"indicator": "x"}})]
    one = scored(dets)[0]
    # Same rule on 4 distinct events: evidence grows, score must not quadruple.
    four = [devt("NET-001", start_min=i, evidence=[f"dup-{i}"],
                 extra_meta={"matched_ioc": {"indicator": "x"}}) for i in range(4)]
    multi = scored(four)[0]
    assert multi < 4 * one
    assert multi - one < 20


def test_remove_data_decreases_risk():
    # Pair below the 100-cap so the DATA-001 contribution is visible.
    full = [devt("AUTH-001", start_min=0),
            devt("DATA-001", start_min=5,
                 extra_meta={"bytes_sent": 4_000_000_000, "threshold": 1_000_000_000})]
    part = [d for d in full if d.rule_id != "DATA-001"]
    assert scored(full)[0] > scored(part)[0]


def test_remove_sequence_decreases_risk():
    full = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5),
            devt("NET-001", start_min=9)]
    part = [d for d in full if d.rule_id != "PROC-001"]
    assert scored(full)[0] > scored(part)[0]


def test_breakdown_consistent():
    score, breakdown, explanation = scored(
        [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)])[:3]
    parts = (breakdown.severity_points + breakdown.diversity_points
             + breakdown.confidence_points + breakdown.evidence_points
             + breakdown.sequence_points + breakdown.mitre_points
             + breakdown.contextual_points)
    assert parts == breakdown.total == score
    assert "AUTH-001" in explanation or "detection rules" in explanation


def test_explanation_uses_real_evidence():
    score, _, explanation = scored(
        [devt("NET-001", start_min=0, extra_meta={"matched_ioc": {"indicator": "x"}})])[:3]
    assert "IOC" in explanation
    assert "T1071" in explanation  # mapped technique may be cited (it exists)
    assert "T1110" not in explanation  # unmapped technique must not be cited
    assert "scenario" not in explanation


def test_ground_truth_irrelevant_to_risk():
    dets = [devt("AUTH-001", start_min=0), devt("PROC-001", start_min=5)]
    base = scored(dets)[:2]
    relabeled = []
    for d in dets:
        c = d.model_copy(deep=True)
        c.metadata["scenario_id"] = "x"
        c.metadata["scenario_type"] = "y"
        c.metadata["synthetic"] = True
        relabeled.append(c)
    assert scored(relabeled)[:2] == base
