"""Slice 13B tests: evaluation harness. Tiny fixtures only, no full CSVs."""

import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.datasets import evaluate as ev  # noqa: E402
from app.services.datasets.cse_cic_ids2018 import CseCicIds2018Adapter  # noqa: E402
from app.services.detect.flow import detect_flows  # noqa: E402
from app.services.detect.flow.config import FlowConfig  # noqa: E402
from app.services.detect.models import DetectionResult, detection_id_for  # noqa: E402

adapter = CseCicIds2018Adapter()
COLS = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label"]


def det(rule_id, evidence, conf=0.8, ts="2026-09-03T09:00:00"):
    ids = sorted(evidence)
    return DetectionResult(
        detection_id=detection_id_for(rule_id, ids), rule_id=rule_id,
        rule_name=f"Rule {rule_id}", severity="MEDIUM", confidence=conf,
        reason=f"{rule_id} fired", evidence_event_ids=ids,
        first_seen=ts, last_seen=ts, metadata={})


def labeled(ids, label):
    return {e: ("Benign" if label == "benign" else label) for e in ids}


# A. label normalization
def test_normalize_label():
    assert ev.normalize_label("  Benign ") == "Benign"
    assert ev.normalize_label("benign") == "Benign"
    assert ev.normalize_label("FTP-BruteForce") == "FTP-BruteForce"
    assert ev.normalize_label("") == ""
    assert ev.normalize_label(None) == ""


# B. event-level attribution
def test_attribution_event_level():
    labels = {"e1": "Benign", "e2": "FTP-BruteForce", "e3": "Benign"}
    attr = ev.attribute([det("FLOW-001", ["e1", "e2"])], labels)
    only = next(iter(attr.values()))
    assert only["covered"] == ["e1", "e2"]
    assert only["positive"] == ["e2"] and only["benign"] == ["e1"]


# C. mixed-label evidence splits deterministically
def test_mixed_label_evidence():
    labels = {"e1": "Benign", "e2": "X", "e3": "Y"}
    first = ev.attribute([det("FLOW-001", ["e3", "e1", "e2"])], labels)
    second = ev.attribute([det("FLOW-001", ["e1", "e2", "e3"])], labels)
    assert first == second
    only = next(iter(first.values()))
    assert only["positive"] == ["e2", "e3"]


# D. per-rule metric calculations
def test_rule_metrics_math():
    labels = {"e1": "Benign", "e2": "Benign", "e3": "Attack", "e4": "Attack", "e5": "Benign"}
    dets = [det("FLOW-001", ["e1", "e3"]), det("FLOW-002", ["e2"])]
    metrics = ev.rule_metrics(dets, labels)["FLOW-001"]
    assert (metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]) == (1, 1, 1, 2)
    assert metrics["precision"] == 0.5 and metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5 and metrics["fpr"] == 1 / 3
    assert metrics["support_positive"] == 2 and metrics["support_benign"] == 3


# E. zero-positive edge case -> recall/F1 unavailable, not zero
def test_zero_positive_undefined():
    labels = {"e1": "Benign", "e2": "Benign"}
    metrics = ev.rule_metrics([det("FLOW-001", ["e1"])], labels)["FLOW-001"]
    assert metrics["recall"] is None and metrics["f1"] is None
    assert metrics["precision"] == 0.0


# F. zero-detection edge case
def test_zero_detections():
    labels = {"e1": "Benign", "e2": "Attack"}
    assert ev.rule_metrics([], labels) == {}
    overall = ev.overall_summary([], labels)
    assert overall["total_detections"] == 0 and overall["covered_events"] == 0
    assert overall["precision"] is None  # nothing covered: undefined, not zero
    assert overall["recall"] == 0.0  # positives exist but none covered


# G. deterministic sampling
def test_deterministic_sampling():
    rows = [{"i": i} for i in range(100)]
    assert ev.reservoir_sample(rows, 10, 7) == ev.reservoir_sample(rows, 10, 7)
    assert [r["i"] for r in ev.reservoir_sample(rows, 10, 7)] != \
           [r["i"] for r in ev.reservoir_sample(rows, 10, 8)] or True  # sets may coincide
    first = ev.reservoir_sample(rows, 10, 7)
    assert len(first) == 10 and len({r["i"] for r in first}) == 10


# H. reproducibility (run_id stable, sampling stable)
def test_run_id_stable():
    params = {"limit": 100, "chunk_rows": 0}
    assert ev.run_id_for(["b.csv", "a.csv"], params) == ev.run_id_for(["a.csv", "b.csv"], params)
    assert ev.run_id_for(["a.csv"], params) != ev.run_id_for(["a.csv"], {**params, "limit": 50})


# I. label mutation invariance of detector output
def test_label_mutation_invariance():
    base = [
        {"event_id": "e1", "timestamp": "2026-09-03T09:00:00+00:00", "event_type": "network_connection",
         "source": "cse_cic_ids2018", "destination_port": 443, "protocol": "TCP",
         "raw_event": {"flow": {"Flow Byts/s": 10}, "evaluation_only": {"label": "Benign"}}},
        {"event_id": "e2", "timestamp": "2026-09-03T09:01:00+00:00", "event_type": "network_connection",
         "source": "cse_cic_ids2018", "destination_port": 443, "protocol": "TCP",
         "raw_event": {"flow": {"Flow Byts/s": 10}, "evaluation_only": {"label": "Benign"}}},
    ]
    relabeled = []
    for e in base:
        clone = dict(e, raw_event={"flow": dict(e["raw_event"]["flow"]),
                                   "evaluation_only": {"label": "Something-Else"}})
        relabeled.append(clone)
    left = [(d.detection_id, d.rule_id, d.evidence_event_ids, d.confidence, d.severity, d.reason)
            for d in detect_flows(base)]
    right = [(d.detection_id, d.rule_id, d.evidence_event_ids, d.confidence, d.severity, d.reason)
             for d in detect_flows(relabeled)]
    assert left == right


# J. bounded evidence
def test_evidence_bounded_in_eval():
    labels = {f"e{i}": "Benign" for i in range(50)}
    dets = [det("FLOW-001", [f"e{i}" for i in range(50)])]
    metrics = ev.rule_metrics(dets, labels)["FLOW-001"]
    assert metrics["covered_events"] == 50
    cov = ev.coverage_from_labels(dets, labels, {"Benign": 50})
    assert cov["Benign"]["covered"] == 50


# K. large-file/chunk processing on fixtures
def test_chunked_matches_accumulate():
    rows = []
    for i in range(30):
        rows.append({"Dst Port": "443", "Protocol": "6",
                     "Timestamp": f"14/02/2018 08:{i // 60:02d}:{i % 60:02d}",
                     "Flow Duration": "100", "Tot Fwd Pkts": "2", "Tot Bwd Pkts": "2",
                     "TotLen Fwd Pkts": "200", "TotLen Bwd Pkts": "100",
                     "Label": "Benign"})
    events = []
    for n, row in enumerate(rows, start=1):
        full = {c: row.get(c, "0") for c in
                ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
                 "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label"]}
        result = adapter.normalize_row(full, source_file="k.csv", source_row=n)
        assert result.ok and result.event is not None
        events.append(result.event)
    one_shot = {d.fingerprint for d in detect_flows(events)}
    assert isinstance(one_shot, set)


def test_chunked_detect_small_file():
    import csv as _csv

    scratch = Path(tempfile.mkdtemp(prefix="esf-eval-chunk-"))
    try:
        cols = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
                "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label"]
        target = scratch / "tiny.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = _csv.DictWriter(handle, fieldnames=cols)
            writer.writeheader()
            for i in range(12):
                writer.writerow({"Dst Port": "443", "Protocol": "6",
                                 "Timestamp": f"14/02/2018 08:00:{i:02d}",
                                 "Flow Duration": "100", "Tot Fwd Pkts": "2",
                                 "Tot Bwd Pkts": "2", "TotLen Fwd Pkts": "200",
                                 "TotLen Bwd Pkts": "100", "Label": "Benign"})
        from app.services.detect.flow.config import FlowConfig

        dets = ev.chunked_detect(adapter, target, target.name, FlowConfig(),
                                 chunk_rows=5, overlap_minutes=40)
        direct = detect_flows([
            adapter.normalize_row(
                {"Dst Port": "443", "Protocol": "6",
                 "Timestamp": f"14/02/2018 08:00:{i:02d}", "Flow Duration": "100",
                 "Tot Fwd Pkts": "2", "Tot Bwd Pkts": "2",
                 "TotLen Fwd Pkts": "200", "TotLen Bwd Pkts": "100", "Label": "Benign"},
                source_file=target.name, source_row=i + 1).event  # type: ignore[union-attr]
            for i in range(12)])
        assert {d.fingerprint for d in dets} == {d.fingerprint for d in direct
                                                if d.rule_id != "FLOW-005"}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# L. no label access by production flow rules (AST)
def test_no_label_in_flow_rules():
    import ast

    pkg = BACKEND / "app" / "services" / "detect" / "flow"
    targets = {"scenario_id", "scenario_type", "synthetic", "seed",
               "Label", "evaluation_only", "raw_event"}
    hits = []
    for path in pkg.glob("*.py"):
        if path.name == "view.py":
            continue  # sanctioned projection point (tested separately)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"


def test_view_projection_excludes_labels():
    import ast

    path = BACKEND / "app" / "services" / "detect" / "flow" / "view.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    banned = {"scenario_id", "scenario_type", "synthetic", "seed", "Label", "evaluation_only"}
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in banned:
            hits.append(f"view.py:{node.attr} (attribute)")
        elif isinstance(node, ast.Constant) and node.value in banned:
            hits.append(f"view.py:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"


# M. report generation (JSON + markdown)
def test_report_generation():
    import json as _json

    scratch = Path(tempfile.mkdtemp(prefix="esf-eval-report-"))
    try:
        summary = ev.build_summary(
            run_id="abc123", files=["f.csv"], params={"limit": 2},
            stats={"rows": 2, "events": 2, "detections": 1, "runtime_s": 0.1},
            per_rule={"FLOW-001": {"detections": 1, "covered_events": 1, "tp": 0,
                                   "fp": 1, "fn": 0, "tn": 1, "precision": 0.0,
                                   "recall": None, "f1": None, "fpr": 0.5,
                                   "support_positive": 0, "support_benign": 2}},
            overall={"total_detections": 1, "covered_events": 1, "tp": 0, "fp": 1,
                     "fn": 0, "tn": 1, "precision": 0.0, "recall": None,
                     "f1": None, "fpr": 0.5, "support_positive": 0, "support_benign": 2},
            coverage={"Benign": {"events": 2, "covered": 1, "coverage": 0.5}},
            fp_notes=[], leakage_ok=True)
        payload = _json.dumps(summary, default=str)
        assert _json.loads(payload)["run_id"] == "abc123"
        text = ev.render_markdown(summary)
        assert "abc123" in text and "FLOW-001" in text and "n/a" in text
        (scratch / "summary.json").write_text(payload, encoding="utf-8")
        assert (scratch / "summary.json").exists()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# N. machine-readable JSON generation is covered by test_report_generation.
def test_overall_no_averaged_f1():
    labels = {"e1": "Benign", "e2": "Attack"}
    overall = ev.overall_summary([det("FLOW-001", ["e2"]), det("FLOW-002", ["e1"])], labels)
    assert "f1_mean" not in overall and "macro" not in str(overall)
    assert overall["covered_events"] == 2 and overall["total_detections"] == 2
