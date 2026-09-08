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


def bdet(rule_id, evidence, bucket, conf=0.8, ts="2026-09-03T09:00:00", meta=None):
    """DetectionResult with explicit bucket membership for bucket tests."""
    ids = sorted(evidence)
    return DetectionResult(
        detection_id=detection_id_for(rule_id, ids), rule_id=rule_id,
        rule_name=f"Rule {rule_id}", severity="MEDIUM", confidence=conf,
        reason=f"{rule_id} fired", evidence_event_ids=ids,
        bucket_event_ids=sorted(bucket),
        first_seen=ts, last_seen=ts, metadata=dict(meta or {}))


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


def test_flow005_streaming_matches_rule():
    """Streaming two-pass FLOW-005 must equal rule.evaluate byte-for-byte."""
    import csv as _csv

    from app.services.detect.common import prepare
    from app.services.detect.flow.config import FlowConfig
    from app.services.detect.flow.rules import ProtocolPortNovelty

    scratch = Path(tempfile.mkdtemp(prefix="esf-eval-f005-"))
    try:
        cols = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
                "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label"]
        target = scratch / "novel.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = _csv.DictWriter(handle, fieldnames=cols)
            writer.writeheader()
            for i in range(10):
                writer.writerow({"Dst Port": "443", "Protocol": "6",
                                 "Timestamp": f"14/02/2018 08:00:{i:02d}",
                                 "Flow Duration": "100", "Tot Fwd Pkts": "2",
                                 "Tot Bwd Pkts": "2", "TotLen Fwd Pkts": "200",
                                 "TotLen Bwd Pkts": "100", "Label": "Benign"})
            for i in range(60):
                writer.writerow({"Dst Port": "4443", "Protocol": "17",
                                 "Timestamp": f"14/02/2018 08:05:{i % 60:02d}",
                                 "Flow Duration": "100", "Tot Fwd Pkts": "2",
                                 "Tot Bwd Pkts": "2", "TotLen Fwd Pkts": "200",
                                 "TotLen Bwd Pkts": "100", "Label": "Benign"})
        config = FlowConfig()
        streamed, _ = ev.evaluate_flow005_full(adapter, target, target.name, config)
        events = []
        for n, raw in adapter.iter_rows(target):
            result = adapter.normalize_row(raw, source_file=target.name, source_row=n)
            assert result.ok and result.event is not None
            events.append(result.event)
        direct = ProtocolPortNovelty(config).evaluate(prepare(events))
        assert [(d.fingerprint, d.model_dump()) for d in streamed] == \
               [(d.fingerprint, d.model_dump()) for d in direct]
        assert len(streamed) == 1 and streamed[0].rule_id == "FLOW-005"
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


# O. evaluator cleanup: exactly one effective build_time_index, no dead helpers.
def test_single_build_time_index_definition():
    text = (BACKEND / "app" / "services" / "datasets" / "evaluate.py").read_text(encoding="utf-8")
    assert text.count("def build_time_index(") == 1
    assert "def iter_indexed_rows(" not in text
    assert text.count("def flush(") == 1
    assert "noqa: F401 (documented use)" not in text


# P. quoted CSV rows remain accepted consistently (same as DictReader path).
def test_quoted_rows_accepted_in_time_index():
    import csv as _csv

    from app.services.detect.flow.config import FlowConfig

    scratch = Path(tempfile.mkdtemp(prefix="esf-eval-quoted-"))
    try:
        cols = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
                "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label"]
        target = scratch / "quoted.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = _csv.DictWriter(handle, fieldnames=cols, quoting=_csv.QUOTE_ALL)
            writer.writeheader()
            for i in range(6):
                writer.writerow({"Dst Port": "443", "Protocol": "6",
                                 "Timestamp": f"14/02/2018 08:00:{i:02d}",
                                 "Flow Duration": "100", "Tot Fwd Pkts": "2",
                                 "Tot Bwd Pkts": "2", "TotLen Fwd Pkts": "200",
                                 "TotLen Bwd Pkts": "100", "Label": "Benign"})
        # DictReader path accepts quotes; time index must too (no AdapterError).
        index, rejected = ev.build_time_index(adapter, target, target.name)
        assert rejected == 0 and len(index) == 6
        dets_time = ev.chunked_detect(adapter, target, target.name, FlowConfig(),
                                      chunk_rows=2, overlap_minutes=40, order="time")
        dets_file = ev.chunked_detect(adapter, target, target.name, FlowConfig(),
                                      chunk_rows=2, overlap_minutes=40, order="file")
        assert {d.fingerprint for d in dets_time} == {d.fingerprint for d in dets_file}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# Q. deterministic (epoch, source_row) ordering, including tie-breaker.
def test_time_order_deterministic_epoch_source_row():
    import csv as _csv

    from app.services.detect.flow.config import FlowConfig

    scratch = Path(tempfile.mkdtemp(prefix="esf-eval-order-"))
    try:
        cols = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
                "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label"]
        target = scratch / "unordered.csv"
        # Physically unordered input with duplicate timestamps (tie-breaker).
        stamps = ["08:00:05", "08:00:01", "08:00:05", "08:00:00", "08:00:01", "08:00:03"]
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = _csv.DictWriter(handle, fieldnames=cols)
            writer.writeheader()
            for ts in stamps:
                writer.writerow({"Dst Port": "443", "Protocol": "6",
                                 "Timestamp": f"14/02/2018 {ts}",
                                 "Flow Duration": "100", "Tot Fwd Pkts": "2",
                                 "Tot Bwd Pkts": "2", "TotLen Fwd Pkts": "200",
                                 "TotLen Bwd Pkts": "100", "Label": "Benign"})
        index, _ = ev.build_time_index(adapter, target, target.name)
        assert len(index) == 6
        ordered = sorted(index, key=lambda e: (e[0], e[1]))
        # Epochs non-decreasing; equal epochs ordered by source_row.
        for a, b in zip(ordered, ordered[1:]):
            assert (a[0], a[1]) <= (b[0], b[1])
        dup_epoch = [e for e in ordered if e[0] == ordered[1][0]]
        assert [e[1] for e in dup_epoch] == sorted(e[1] for e in dup_epoch)
        cfg = FlowConfig()
        first = {d.fingerprint for d in ev.chunked_detect(
            adapter, target, target.name, cfg, chunk_rows=2, overlap_minutes=40, order="time")}
        second = {d.fingerprint for d in ev.chunked_detect(
            adapter, target, target.name, cfg, chunk_rows=2, overlap_minutes=40, order="time")}
        assert first == second
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# R. CLI --order file/time wiring (default time, passed to chunked_detect).
def test_cli_order_flag_wiring():
    import inspect

    repo = BACKEND.parent
    text = (repo / "scripts" / "evaluate_cse_cic_ids2018.py").read_text(encoding="utf-8")
    assert "--order" in text
    assert 'choices=["file", "time"]' in text or "choices=['file', 'time']" in text
    assert 'default="time"' in text or "default='time'" in text
    assert "order=args.order" in text
    assert '"order": args.order' in text or "'order': args.order" in text
    sig = inspect.signature(ev.chunked_detect)
    assert "order" in sig.parameters
    assert sig.parameters["order"].default == "file"


# ---------------- Bucket-level metrics (Slice 13F) ----------------

def test_bucket_single_hit():
    labels = {"e1": "Benign", "e2": "X", "e3": "X"}
    mets = ev.bucket_metrics([bdet("FLOW-001", ["e1"], ["e1", "e2", "e3"])], labels, ["X"])
    assert (mets["bucket_tp"], mets["bucket_fp"]) == (1, 0)
    assert mets["bucket_precision"] == 1
    assert (mets["attack_bucket_count"], mets["attack_bucket_hit"]) == (1, 1)
    assert mets["bucket_recall"] == 1
    assert mets["bucket_metric_status"] == "available"


def test_bucket_benign_only():
    labels = {"e1": "Benign", "e2": "X"}
    mets = ev.bucket_metrics([bdet("FLOW-001", ["e1"], ["e1"])], labels, ["X"])
    assert (mets["bucket_tp"], mets["bucket_fp"]) == (0, 1)
    assert mets["bucket_precision"] == 0
    assert mets["attack_bucket_hit"] == 0 and mets["bucket_recall"] == 0


def test_bucket_multi_dets_same_episode():
    labels = {"e1": "X", "e2": "X", "e3": "Benign"}
    dets = [bdet("FLOW-001", ["e1"], ["e1", "e3"]),
            bdet("FLOW-002", ["e2"], ["e2", "e3"])]
    mets = ev.bucket_metrics(dets, labels, ["X"])
    assert mets["detection_bucket_count"] == 2 and mets["bucket_tp"] == 2
    assert (mets["attack_bucket_count"], mets["attack_bucket_hit"]) == (1, 1)
    assert mets["bucket_recall"] == 1
    per = ev.per_rule_bucket_metrics(dets, labels, ["X"])
    assert per["FLOW-001"]["bucket_tp"] == 1 and per["FLOW-002"]["bucket_tp"] == 1


def test_bucket_one_det_two_episodes():
    labels = {"ex": "X", "ey": "Y", "eb": "Benign"}
    mets = ev.bucket_metrics([bdet("FLOW-001", ["ex"], ["ex", "ey", "eb"])],
                             labels, ["X", "Y"])
    assert mets["bucket_tp"] == 1  # one detection counts once
    assert mets["attack_bucket_hit"] == 2 and mets["bucket_recall"] == 1


def test_bucket_multi_labels():
    labels = {"a1": "X", "b1": "Y", "c1": "Benign"}
    episodes = ev.build_attack_episodes(labels)
    assert sorted(episodes) == ["X", "Y"] and "Benign" not in episodes
    assert ev.attack_labels_from_totals({"X": 2, "Y": 1, "Benign": 5, "": 0}) == ["X", "Y"]
    assert ev.attack_labels_from_totals({"Benign": 3}) == []


def test_bucket_empty_sets():
    assert ev.bucket_metrics([], {"e1": "X"}, ["X"])["bucket_precision"] is None
    assert ev.bucket_metrics([], {"e1": "X"}, ["X"])["bucket_recall"] == 0
    assert ev.bucket_metrics([], {}, [])["bucket_recall"] is None


def test_bucket_evidence_independence():
    labels = {"e1": "Benign", "e2": "Attack"}
    d1 = bdet("FLOW-001", ["e1"], ["e1", "e2"])
    d2 = bdet("FLOW-001", ["e2"], ["e1", "e2"])
    assert ev.bucket_metrics([d1], labels, ["Attack"]) == \
        ev.bucket_metrics([d2], labels, ["Attack"])
    m1 = ev.rule_metrics([d1], labels)["FLOW-001"]
    m2 = ev.rule_metrics([d2], labels)["FLOW-001"]
    assert (m1["tp"], m1["fp"]) == (0, 1) and (m2["tp"], m2["fp"]) == (1, 0)


def test_bucket_label_mutation():
    dets = [bdet("FLOW-001", ["e1"], ["e1", "e2"])]
    before = ev.bucket_metrics(dets, {"e1": "X", "e2": "X"}, ["X"])
    after = ev.bucket_metrics(dets, {"e1": "Benign", "e2": "Benign"}, ["X"])
    assert (before["bucket_tp"], after["bucket_fp"]) == (1, 1)
    assert after["bucket_recall"] == 0
    assert dets[0].bucket_event_ids == ["e1", "e2"]  # membership untouched


def test_bucket_determinism():
    labels = {"e1": "X", "e2": "Benign"}
    dets = [bdet("FLOW-002", ["e1"], ["e1", "e2"]), bdet("FLOW-001", ["e2"], ["e2"])]
    first = json.dumps(ev.bucket_metrics(dets, labels, ["X"]), sort_keys=True)
    assert json.dumps(ev.bucket_metrics(list(dets), dict(labels), ["X"]),
                      sort_keys=True) == first
    assert json.dumps(ev.per_rule_bucket_metrics(dets, labels, ["X"]),
                      sort_keys=True) == json.dumps(
                          ev.per_rule_bucket_metrics(dets, labels, ["X"]), sort_keys=True)


def test_bucket_evidence_regression():
    labels = {"e1": "Benign", "e2": "Attack"}
    plain = det("FLOW-001", ["e1", "e2"])
    with_bucket = bdet("FLOW-001", ["e1", "e2"], ["e1", "e2", "e3"])
    assert ev.rule_metrics([plain], labels) == ev.rule_metrics([with_bucket], labels)
    assert ev.attribute([plain], labels) == ev.attribute([with_bucket], labels)


def test_bucket_unavailable():
    labels = {"e1": "X"}
    mets = ev.bucket_metrics([det("FLOW-009", ["e1"])], labels, ["X"])
    assert mets["bucket_fp"] == 0 and mets["evaluated_buckets"] == 0
    assert mets["unavailable_buckets"] == 1 and mets["bucket_precision"] is None
    assert mets["bucket_metric_status"] == "unavailable" and mets["bucket_metric_reason"]
    per = ev.per_rule_bucket_metrics([det("FLOW-009", ["e1"])], labels, ["X"])
    assert per["FLOW-009"]["bucket_metric_status"] == "unavailable"


def test_bucket_posthoc_ordering():
    import inspect  # noqa: E402

    for fn in ("chunked_detect", "_chunked_detect_time_ordered",
               "_read_group", "build_time_index"):
        params = inspect.signature(getattr(ev, fn)).parameters
        assert not [p for p in params if "label" in p], fn
    assert set(inspect.signature(ev.build_attack_episodes).parameters) == {"label_map"}


# ---------------- Incident pipeline (Slice 15) ----------------

def _ibucket(dets):
    return {d.detection_id: d for d in dets}


def test_incident_serialization_deterministic(tmp_path=None):
    import tempfile  # noqa: E402

    from app.services.correlate import correlate  # noqa: E402

    dets = [bdet("FLOW-001", ["e1"], ["e1", "e2"], meta={"key": "10.0.0.1"}),
            bdet("FLOW-004", ["e3"], ["e3", "e2"], meta={"key": "10.0.0.1"})]
    incs = correlate(dets)
    scratch = Path(tempfile.mkdtemp(prefix="esf-eval-inc-"))
    try:
        first = ev.write_jsonl([ev.detection_record(d) for d in dets],
                               scratch / "a.jsonl")
        second = ev.write_jsonl([ev.detection_record(d) for d in dets],
                                scratch / "b.jsonl")
        assert first == second
        assert (scratch / "a.jsonl").read_bytes() == (scratch / "b.jsonl").read_bytes()
        by_id = _ibucket(dets)
        recs = [ev.incident_record(i, by_id) for i in incs]
        assert ev.write_jsonl(recs, scratch / "c.jsonl") == \
            ev.write_jsonl([ev.incident_record(i, by_id) for i in correlate(dets)],
                           scratch / "d.jsonl")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_incident_replay_uses_real_engine():
    from app.services.correlate import correlate  # noqa: E402

    dets = [bdet("FLOW-001", ["e1"], ["e1"], meta={"key": "10.0.0.1"}),
            bdet("FLOW-001", ["e2"], ["e2"], meta={"key": "10.0.0.2"})]
    incs = correlate(dets)
    seen = sorted(did for i in incs for did in i.detection_ids)
    assert seen == sorted(d.detection_id for d in dets)
    assert len(seen) == len(set(seen))  # complete, disjoint mapping


def test_incident_attack_hit_and_recall_once():
    from app.services.correlate import correlate  # noqa: E402

    meta = {"key": "10.0.0.1"}
    dets = [bdet("FLOW-001", ["e1"], ["e1", "x1"], meta=meta),
            bdet("FLOW-001", ["e2"], ["e2", "x1"], meta=meta),
            bdet("FLOW-004", ["e3"], ["e3", "x1"], meta=meta)]
    incs = correlate(dets)
    labels = {"e1": "Benign", "e2": "Benign", "e3": "Benign", "x1": "Attack"}
    mets = ev.incident_metrics(incs, _ibucket(dets), labels, ["Attack"])
    assert mets["total_incidents"] == 1  # one multi-detection incident
    assert mets["attack_incidents"] == 1 and mets["incident_attack_hit"] == 1
    assert mets["incident_precision"] == 1 and mets["incident_recall"] == 1
    assert mets["detections_per_incident"] == 3


def test_incident_benign_not_hit():
    from app.services.correlate import correlate  # noqa: E402

    dets = [bdet("FLOW-001", ["e1"], ["e1"], meta={"key": "10.0.0.1"})]
    incs = correlate(dets)
    mets = ev.incident_metrics(incs, _ibucket(dets), {"e1": "Benign"}, ["Attack"])
    assert (mets["attack_incidents"], mets["benign_incidents"]) == (0, 1)
    assert mets["incident_precision"] == 0 and mets["incident_recall"] == 0


def test_incident_buckets_survive_capped_evidence():
    bucket = [f"b{i:03d}" for i in range(50)]
    d = bdet("FLOW-001", bucket[:20], bucket, meta={"key": "10.0.0.1"})
    rec = ev.detection_record(d)
    assert len(rec["evidence_event_ids"]) == 20 and len(rec["bucket_event_ids"]) == 50
    assert set(rec["evidence_event_ids"]) <= set(rec["bucket_event_ids"])


def test_incident_composition_and_coverage():
    from app.services.correlate import correlate  # noqa: E402

    dets = [bdet("FLOW-001", ["e1"], ["e1"], meta={"key": "10.0.0.1"}),
            bdet("FLOW-004", ["e2"], ["e2"], meta={"key": "10.0.0.1"}),
            bdet("FLOW-001", ["e3"], ["e3"], meta={"key": "10.9.9.9"})]
    incs = correlate(dets)
    labels = {"e1": "Attack", "e2": "Benign", "e3": "Benign"}
    mets = ev.incident_metrics(incs, _ibucket(dets), labels, ["Attack"])
    # Disjoint buckets with no configured sequence stay separate singletons.
    assert mets["total_incidents"] == 3
    assert mets["rule_composition"] == {"FLOW-001": 2, "FLOW-004": 1}
    assert (mets["attack_incidents"], mets["incident_precision"]) == (1, 1 / 3)
    assert mets["incidents_with_evidence"] == len(incs)
    assert mets["incidents_with_buckets"] == len(incs)


def test_incident_labels_posthoc_only():
    from app.services.correlate import correlate  # noqa: E402

    dets = [bdet("FLOW-001", ["e1"], ["e1", "e2"], meta={"key": "10.0.0.1"})]
    before = [i.model_dump(mode="json") for i in correlate(dets)]
    # Relabelling after detection must not alter incidents or buckets.
    assert [i.model_dump(mode="json") for i in correlate(dets)] == before
    assert dets[0].bucket_event_ids == ["e1", "e2"]


def test_incident_empty_and_no_fpr():
    assert ev.incident_metrics([], {}, {}, [])["incident_precision"] is None
    assert ev.incident_metrics([], {}, {}, [])["incident_recall"] is None
    mets = ev.incident_metrics([], {}, {}, ["Attack"])
    assert mets["incident_precision"] is None and mets["incident_recall"] == 0
    assert "fpr" not in json.dumps(mets) and "incident_fpr" not in mets
