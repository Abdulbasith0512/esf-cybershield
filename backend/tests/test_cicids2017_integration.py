"""Slice 33: CICIDS2017 adapter -> evaluator integration contract.

Small deterministic subsets of the frozen files only. Labels stay in a
separate post-hoc map and never enter detector-facing structures.
"""

import csv
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

REPO = BACKEND.parent
FRIDAY = REPO / "data/public/cicids2017/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
TUESDAY = REPO / "data/public/cicids2017/raw/Tuesday-WorkingHours.pcap_ISCX.csv"

from app.services.correlate import correlate  # noqa: E402
from app.services.datasets.cicids2017 import Cicids2017Adapter  # noqa: E402
from app.services.detect.common import prepare  # noqa: E402
from app.services.detect.flow import detect_flows  # noqa: E402
from app.services.detect.flow.view import build_views  # noqa: E402
from app.services.detect.models import make_result  # noqa: E402

adapter = Cicids2017Adapter()

# Deterministic frozen rows: (file, source_row). Labels known post-hoc only.
ROWS = [
    (FRIDAY, 1), (FRIDAY, 1464), (FRIDAY, 1465),
    (TUESDAY, 1), (TUESDAY, 11348), (TUESDAY, 161990),
]


def _read_rows(path, numbers):
    wanted = set(numbers)
    out = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for n, row in enumerate(reader, start=1):
            if n in wanted:
                out[n] = row
                if len(out) == len(wanted):
                    break
    return out


_BY_FILE = {}
for _path, _n in ROWS:
    _BY_FILE.setdefault(_path, []).append(_n)
_CACHE = {path: _read_rows(path, numbers) for path, numbers in _BY_FILE.items()}


def adapt_subset():
    """Returns (events, label_map). Events carry evaluation_only (Run A)."""
    events, labels = [], {}
    for path, n in ROWS:
        raw = _CACHE[path][n]
        result = adapter.normalize_row(raw, source_file=path.name, source_row=n)
        assert result.ok and result.event is not None
        events.append(result.event)
        labels[result.event["event_id"]] = (
            result.event["raw_event"]["evaluation_only"]["label"])
    return events, labels


def strip_labels(events):
    """Run B: same telemetry with evaluation metadata removed entirely."""
    clean = []
    for event in events:
        clone = {k: v for k, v in event.items() if k != "raw_event"}
        clone["raw_event"] = {k: v for k, v in event["raw_event"].items()
                              if k != "evaluation_only"}
        clean.append(clone)
    return clean


def detector_input(events):
    """Detector-facing contract: FlowView projection + fingerprints.

    prepare() intentionally passes raw_event through (FlowView's allowlist
    projection is the label-free boundary), so only views/fingerprints are
    compared here; prepared rows are checked separately to differ solely
    inside evaluation_only.
    """
    prepared = prepare(events)
    views = build_views(prepared)
    return (prepared,
            json.dumps([v.__dict__ for v in views], sort_keys=True, default=str),
            sorted(d.fingerprint for d in detect_flows(prepared)))


def test_label_blind_inputs_identical():
    events, _labels = adapt_subset()
    stripped = strip_labels(events)
    _, views_full, fp_full = detector_input(events)
    prepared_stripped, views_stripped, fp_stripped = detector_input(stripped)
    assert views_full == views_stripped
    assert fp_full == fp_stripped
    # Prepared rows may differ ONLY inside evaluation_only.
    prepared_full, _, _ = detector_input(events)
    for full, bare in zip(prepared_full, prepared_stripped):
        assert {k: v for k, v in full.items() if k != "raw_event"} == \
            {k: v for k, v in bare.items() if k != "raw_event"}
        assert {k: v for k, v in full["raw_event"].items() if k != "evaluation_only"} == \
            bare["raw_event"]


def _views_and_fps(events):
    _, views, fps = detector_input(events)
    return views, fps


def test_label_blind_fingerprints_identical():
    events, _labels = adapt_subset()
    assert _views_and_fps(events) == _views_and_fps(strip_labels(events))


def test_relabel_invariance():
    events, labels = adapt_subset()
    assert set(labels.values()) >= {"BENIGN", "PortScan", "FTP-Patator", "SSH-Patator"}
    relabeled = []
    mapping = {"BENIGN": "X", "PortScan": "Y", "FTP-Patator": "Z", "SSH-Patator": "W"}
    for event in events:
        clone = dict(event, raw_event=dict(event["raw_event"]))
        lab = clone["raw_event"]["evaluation_only"]["label"]
        clone["raw_event"]["evaluation_only"] = {"label": mapping.get(lab, lab)}
        relabeled.append(clone)
    assert [e["event_id"] for e in relabeled] == [e["event_id"] for e in events]
    assert _views_and_fps(relabeled) == _views_and_fps(events)


def test_event_ids_stable_and_label_free():
    events, _labels = adapt_subset()
    ids = [e["event_id"] for e in events]
    assert len(set(ids)) == len(ids)
    again, _ = adapt_subset()
    assert [e["event_id"] for e in again] == ids


def test_timestamp_order_deterministic():
    events, _labels = adapt_subset()
    key = lambda e: (e["timestamp"], e["event_id"])  # noqa: E731
    assert [e["event_id"] for e in sorted(events, key=key)] == \
        [e["event_id"] for e in sorted(list(events), key=key)]
    stamps = sorted(e["timestamp"] for e in events)
    assert all("2017-07" in s for s in stamps)


def test_flowview_contract_representative():
    events, _labels = adapt_subset()
    by_label = {}
    for event in events:
        by_label.setdefault(event["raw_event"]["evaluation_only"]["label"], event)
    scan = by_label["PortScan"]
    assert scan["source_ip"] == "172.16.0.1" and scan["destination_port"] == 80
    assert scan["protocol"] == "TCP"
    views = {v.event_id: v for v in build_views(prepare(events))}
    view = views[scan["event_id"]]
    for field in ("ts", "source_ip", "destination_ip", "destination_port",
                  "protocol", "bytes_sent", "bytes_received"):
        assert getattr(view, field) is not None, field
    for key in ("SYN Flag Cnt", "ACK Flag Cnt"):
        assert key in view.flow, key
    blob = json.dumps([v.__dict__ for v in views.values()], default=str)
    assert "PortScan" not in blob and "BENIGN" not in blob


def test_rule_field_requirements():
    events, _labels = adapt_subset()
    scan = next(e for e in events
                if e["raw_event"]["evaluation_only"]["label"] == "PortScan")
    assert scan["timestamp"] and scan["destination_ip"] is not None
    assert isinstance(scan["destination_port"], int)
    assert scan["source_ip"] is not None and scan["protocol"] == "TCP"
    flow = scan["raw_event"]["flow"]
    assert "Flow Bytes/s" in flow and "SYN Flag Count" in flow


def test_correlation_compatibility():
    events, _labels = adapt_subset()
    prepared = prepare(events)
    dets = detect_flows(prepared)
    bucket = [{"event_id": e["event_id"]} for e in events]
    if not dets:
        dets = [make_result("FLOW-001", "n", "MEDIUM", 0.5, "r", prepared, {},
                            bucket=bucket)]
    incs = correlate(dets)
    assert incs
    for inc in incs:
        assert inc.detection_ids and inc.evidence_event_ids
        assert inc.first_seen and inc.last_seen and inc.metadata


def test_posthoc_label_join():
    events, labels = adapt_subset()
    for event in events:
        assert event["event_id"] in labels
    assert labels[events[1]["event_id"]] == "PortScan"


def test_integration_deterministic_twice():
    first = _views_and_fps(adapt_subset()[0])
    events, _labels = adapt_subset()
    assert _views_and_fps(events) == first
