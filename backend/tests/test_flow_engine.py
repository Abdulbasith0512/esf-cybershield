"""Flow engine tests: determinism, ordering, leakage, robustness."""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.detect.flow import default_flow_rules, detect_flows  # noqa: E402
from app.services.detect.flow.config import FlowConfig  # noqa: E402
from app.services.detect.models import detection_id_for  # noqa: E402
from test_flow_rules import T0, flow, run  # noqa: E402
from datetime import timedelta  # noqa: E402


def test_engine_deterministic():
    evts = [flow(seconds=i) for i in range(55)]
    a = [(d.detection_id, d.fingerprint) for d in detect_flows(evts)]
    b = [(d.detection_id, d.fingerprint) for d in detect_flows(list(evts))]
    assert a == b and len(a) == 1


def test_out_of_order_same_result():
    evts = [flow(seconds=i * 10, sip="10.1.2.3", dport=1000 + i) for i in range(16)]
    fwd = [d.fingerprint for d in run("FLOW-003", evts)]
    back = [d.fingerprint for d in run("FLOW-003", list(reversed(evts)))]
    assert fwd == back


def test_inputs_not_mutated():
    evts = [flow(seconds=i) for i in range(55)]
    before = [dict(e) for e in evts]
    detect_flows(evts)
    assert all("_ts" not in e for e in evts)
    assert evts == before


def test_evidence_ids_are_real():
    evts = [flow(seconds=i) for i in range(55)]
    known = {e["event_id"] for e in evts}
    for d in detect_flows(evts):
        assert d.evidence_event_ids
        assert len(d.evidence_event_ids) <= 20
        assert set(d.evidence_event_ids) <= known
        assert d.detection_id == detection_id_for(d.rule_id, d.evidence_event_ids)
        assert 0.0 <= d.confidence <= 1.0
        assert d.first_seen <= d.last_seen


def test_equal_timestamps_deterministic():
    base = [flow(seconds=0) for _ in range(55)]
    a = [d.fingerprint for d in detect_flows(base)]
    b = [d.fingerprint for d in detect_flows(list(reversed(base)))]
    assert a == b


def test_boundary_timestamps():
    # Events exactly 60 s apart fall in adjacent buckets, never one window.
    evts = [flow(seconds=i * 60) for i in range(55)]
    assert run("FLOW-001", evts) == []


def test_duplicate_looking_flows_distinct():
    rows = [flow(seconds=10) for _ in range(5)]
    ids = [e["event_id"] for e in rows]
    assert len(set(ids)) == 5  # fixtures stay distinct; identity is per-row upstream
    assert run("FLOW-001", rows) == []  # but 5 flows are far below threshold


def test_malformed_telemetry_safe():
    evts = [flow(seconds=i) for i in range(55)]
    evts[3]["raw_event"] = None
    evts[7]["raw_event"] = {"flow": {"Flow Byts/s": "not-a-number", "SYN Flag Cnt": None}}
    evts[11].pop("raw_event")
    dets = detect_flows(evts)
    assert len(dets) == 1  # volume signal survives malformed rows


def test_missing_ips_skip_gracefully():
    # 40 distinct ports in 40 s, no source_ip: scan mode silent, honest fallback fires.
    evts = [flow(seconds=i, dport=2000 + i) for i in range(40)]
    dets = run("FLOW-003", evts)
    assert len(dets) == 1
    assert dets[0].rule_name == "Port Entropy Anomaly"
    assert "entropy" in dets[0].reason


def test_label_mutation_no_effect():
    a = [flow(seconds=i) for i in range(55)]
    b = [dict(e, raw_event={**(e["raw_event"] or {}), "evaluation_only": {"label": "X"}}) for e in a]
    fa = [(d.rule_id, d.evidence_event_ids, d.confidence) for d in detect_flows(a)]
    fb = [(d.rule_id, d.evidence_event_ids, d.confidence) for d in detect_flows(b)]
    assert fa == fb


def test_custom_config_threshold():
    cfg = FlowConfig(rate_min_count=200)
    assert run("FLOW-001", [flow(seconds=i) for i in range(55)], config=cfg) == []


def test_ground_truth_never_used_in_flow():
    """Flow rules must decide from telemetry only. Same AST bar as core rules,
    extended with dataset-label tokens. view.py is the single sanctioned
    projection point: it may touch raw_event to extract the allowlisted flow
    block, but no label token may appear anywhere."""
    import ast

    pkg = Path(__file__).resolve().parents[1] / "app" / "services" / "detect" / "flow"
    label_targets = {"scenario_id", "scenario_type", "synthetic", "seed",
                     "Label", "evaluation_only"}
    hits = []
    for path in pkg.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        targets = set(label_targets)
        if path.name != "view.py":
            targets.add("raw_event")
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"
