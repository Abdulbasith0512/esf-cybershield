"""Engine-level tests: determinism, dedupe, contract shape, ground-truth guard."""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.detect.config import DetectorConfig  # noqa: E402
from app.services.detect.engine import detect  # noqa: E402
from app.services.detect.models import (  # noqa: E402
    DetectionResult,
    detection_id_for,
    fingerprint,
)
from test_detect_rules import evt, run  # noqa: E402


def test_engine_deterministic():
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", seconds=200))
    a = [(d.detection_id, d.fingerprint) for d in detect(evts)]
    b = [(d.detection_id, d.fingerprint) for d in detect(list(reversed(evts)))]
    assert a == b


def test_no_duplicate_detections():
    # Same evidence twice in input -> single detection (fingerprint dedupe).
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", seconds=200))
    doubled = evts + [dict(e) for e in evts]
    assert len(detect(evts)) == len(detect(doubled))


def test_evidence_confidence_severity_contract():
    evts = [evt(status="failed", seconds=i * 20) for i in range(4)]
    evts.append(evt(status="success", seconds=300))
    for d in detect(evts):
        assert isinstance(d, DetectionResult)
        assert len(d.evidence_event_ids) >= 1
        assert 0.0 <= d.confidence <= 1.0
        assert d.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert d.first_seen <= d.last_seen
        assert d.detection_id == detection_id_for(d.rule_id, d.evidence_event_ids)
        assert d.fingerprint == fingerprint(d.rule_id, d.evidence_event_ids)


def test_inputs_not_mutated():
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    before = [dict(e) for e in evts]
    detect(evts)
    assert all("_ts" not in e for e in evts)
    assert evts == before


def test_ground_truth_never_used():
    """Rules must decide from telemetry only. Parse rule/engine ASTs and fail
    on real code references (attribute access, subscripts, string literals)
    to scenario_id / scenario_type / synthetic / raw_event. Docstrings and
    comments are ignored."""
    import ast

    pkg = Path(__file__).resolve().parents[1] / "app" / "services" / "detect"
    targets = {"scenario_id", "scenario_type", "synthetic", "raw_event"}
    hits = []
    for path in list((pkg / "rules").glob("*.py")) + [pkg / "engine.py", pkg / "common.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"


def test_custom_config_threshold():
    cfg = DetectorConfig(brute_min_fails=5)
    evts = [evt(status="failed", seconds=i * 20) for i in range(3)]
    evts.append(evt(status="success", seconds=200))
    assert run("AUTH-001", evts, config=cfg) == []
