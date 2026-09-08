"""Slice 32 tests: CICIDS2017 adapter. No DB, no detection, tiny fixtures only."""

import ast
import csv
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.schemas.events import EventCreate  # noqa: E402
from app.services.datasets.base import AdapterError  # noqa: E402
from app.services.datasets.cicids2017 import (  # noqa: E402
    ADAPTER_VERSION,
    Cicids2017Adapter,
    SOURCE_ID,
    _parse_timestamp,
    session_for,
)

adapter = Cicids2017Adapter()

# Verbose TrafficLabelling-style headers (leading spaces included on purpose).
COLUMNS_2017 = [
    "Flow ID", " Source IP", " Source Port", " Destination IP",
    " Destination Port", " Protocol", " Timestamp", " Flow Duration",
    " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets",
    "Flow Bytes/s", " SYN Flag Count", " ACK Flag Count",
    " RST Flag Count", " FIN Flag Count", " Label",
]

FRIDAY = "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
TUESDAY = "Tuesday-WorkingHours.pcap_ISCX.csv"


def make_row(**overrides):
    row = {c: "0" for c in COLUMNS_2017}
    row.update({
        "Flow ID": "1-2-3",
        " Source IP": "192.168.10.8",
        " Source Port": "35396",
        " Destination IP": "192.168.10.50",
        " Destination Port": "22",
        " Protocol": "6",
        " Timestamp": "7/7/2017 2:53",
        " Flow Duration": "1000",
        " Total Fwd Packets": "10",
        " Total Backward Packets": "8",
        "Total Length of Fwd Pkts": "0",
        "Total Length of Fwd Packets": "5000",
        " Total Length of Bwd Packets": "3000",
        "Flow Bytes/s": "7595.1",
        " SYN Flag Count": "1",
        " ACK Flag Count": "0",
        " RST Flag Count": "0",
        " FIN Flag Count": "0",
        " Label": "PortScan",
    })
    row.update(overrides)
    return row


def norm(row, source_file=FRIDAY, source_row=1):
    return adapter.normalize_row(row, source_file=source_file, source_row=source_row)


def test_timestamp_parsing_friday_pm():
    result = norm(make_row(), source_file=FRIDAY)
    assert result.ok and result.event is not None
    assert result.event["timestamp"] == "2017-07-07T14:53:00+00:00"


def test_timestamp_tuesday_sessions():
    morning = norm(make_row(**{" Timestamp": "4/7/2017 9:20"}), source_file=TUESDAY)
    assert morning.event is not None
    assert morning.event["timestamp"] == "2017-07-04T09:20:00+00:00"
    afternoon = norm(make_row(**{" Timestamp": "4/7/2017 2:05"}), source_file=TUESDAY)
    assert afternoon.event is not None
    assert afternoon.event["timestamp"] == "2017-07-04T14:05:00+00:00"
    noon = norm(make_row(**{" Timestamp": "4/7/2017 12:00"}), source_file=TUESDAY)
    assert noon.event is not None
    assert noon.event["timestamp"] == "2017-07-04T12:00:00+00:00"


def test_timestamp_utc_aware():
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(norm(make_row()).event["timestamp"])  # type: ignore[union-attr]
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)


def test_malformed_timestamp_rejected():
    assert not norm(make_row(**{" Timestamp": "not-a-time"})).ok
    assert norm(make_row(**{" Timestamp": "not-a-time"})).rejected.code == "bad_timestamp"


def test_ambiguous_hour_rejected():
    assert not norm(make_row(**{" Timestamp": "4/7/2017 7:00"}), source_file=TUESDAY).ok
    assert not norm(make_row(**{" Timestamp": "4/7/2017 6:00"}), source_file=TUESDAY).ok
    # Noon is unambiguous and accepted on both sessions.
    assert norm(make_row(**{" Timestamp": "4/7/2017 12:00"}), source_file=TUESDAY).ok
    assert norm(make_row(**{" Timestamp": "7/7/2017 12:00"}), source_file=FRIDAY).ok


def test_unknown_session_fails_closed():
    try:
        session_for("Wednesday-workingHours.pcap_ISCX.csv")
    except AdapterError:
        pass
    else:
        raise AssertionError("unknown session must raise")
    result = norm(make_row(), source_file="Wednesday-workingHours.pcap_ISCX.csv")
    assert not result.ok and result.rejected is not None
    assert result.rejected.code == "bad_session"


def test_header_whitespace_lookup():
    result = norm({"  Timestamp  ": "7/7/2017 2:53", " Destination Port ": "80",
                   " Protocol ": "6", " Source IP ": "10.0.0.1",
                   " Destination IP ": "10.0.0.2", " Label ": "BENIGN",
                   " SYN Flag Count ": "0", " ACK Flag Count ": "0"},
                  source_file=FRIDAY)
    assert result.ok and result.event is not None
    assert result.event["destination_port"] == 80
    assert result.event["source_ip"] == "10.0.0.1"


def test_required_field_mapping():
    event = norm(make_row()).event or {}
    assert event["destination_port"] == 22
    assert event["protocol"] == "TCP"
    assert event["source_ip"] == "192.168.10.8"
    assert event["destination_ip"] == "192.168.10.50"
    assert event["bytes_sent"] == 5000 and event["bytes_received"] == 3000
    assert event["event_type"] == "network_connection" and event["source"] == SOURCE_ID
    assert event["host"] is None and event["user"] is None


def test_syn_ack_fin_rst_mapping():
    event = norm(make_row(**{" SYN Flag Count": "3", " ACK Flag Count": "1",
                             " RST Flag Count": "2", " FIN Flag Count": "4"})).event or {}
    flow = event["raw_event"]["flow"]
    assert flow["SYN Flag Cnt"] == 3 and flow["ACK Flag Cnt"] == 1
    assert flow["RST Flag Cnt"] == 2 and flow["FIN Flag Cnt"] == 4


def test_missing_flags_fail_safe():
    from app.services.detect.common import prepare  # noqa: E402
    from app.services.detect.flow.view import build_views  # noqa: E402

    event = norm(make_row(**{" SYN Flag Count": "", " ACK Flag Count": ""})).event or {}
    # Raw flow keeps the empty marker (CSE convention); FlowView drops it so
    # detector flag checks fall back to 0.0 instead of guessing.
    assert event["raw_event"]["flow"].get("SYN Flag Cnt") == ""
    prepared = dict(event, _ts=event["timestamp"])
    (view,) = build_views([prepared])
    assert "SYN Flag Cnt" not in view.flow and "ACK Flag Cnt" not in view.flow
    assert view.flow_value("SYN Flag Cnt") == 0.0


def test_malformed_numerics_safe():
    result = norm(make_row(**{"Total Length of Fwd Packets": "abc",
                              "Total Length of Bwd Packets": "-5"}))
    assert result.ok and result.event is not None
    assert result.event["bytes_sent"] is None
    assert result.event["bytes_received"] is None
    bad = norm(make_row(**{" Destination Port": "99999"}))
    assert not bad.ok and bad.rejected is not None and bad.rejected.code == "bad_port"


def test_benign_normalization_preserved_label():
    from app.services.datasets.evaluate import normalize_label  # noqa: E402

    event = norm(make_row(**{" Label": "BENIGN"})).event or {}
    assert event["raw_event"]["evaluation_only"]["label"] == "BENIGN"
    assert normalize_label("BENIGN") == "Benign"
    attack = norm(make_row(**{" Label": "PortScan"})).event or {}
    assert attack["raw_event"]["evaluation_only"]["label"] == "PortScan"


def test_label_isolation():
    event = norm(make_row(**{" Label": "FTP-Patator"})).event or {}
    top = {k: v for k, v in event.items() if k != "raw_event"}
    assert "FTP-Patator" not in str(top)
    assert "FTP-Patator" not in str(event.get("event_id"))
    renamed = norm(make_row(**{" Label": "Something-Else"})).event or {}
    assert {k: v for k, v in renamed.items() if k != "raw_event"} == top


def test_label_free_event_id_and_fingerprint():
    from app.services.detect.models import detection_id_for  # noqa: E402

    first = norm(make_row(**{" Label": "PortScan"})).event or {}
    second = norm(make_row(**{" Label": "BENIGN"})).event or {}
    assert first["event_id"] == second["event_id"]
    assert detection_id_for("FLOW-001", [first["event_id"]]) == \
        detection_id_for("FLOW-001", [second["event_id"]])


def test_deterministic_event_id():
    first = norm(make_row(), source_file=FRIDAY, source_row=7).event or {}
    second = norm(make_row(), source_file=FRIDAY, source_row=7).event or {}
    assert first["event_id"] == second["event_id"]
    other_row = norm(make_row(), source_file=FRIDAY, source_row=8).event or {}
    assert other_row["event_id"] != first["event_id"]
    other_file = norm(make_row(), source_file=TUESDAY, source_row=7).event or {}
    assert other_file["event_id"] != first["event_id"]


def test_no_label_in_flowview_projection():
    event = norm(make_row(**{" Label": "SSH-Patator"})).event or {}
    assert "SSH-Patator" not in str({k: v for k, v in event.items() if k != "raw_event"})


def test_representative_rows():
    friday = norm(make_row(), source_file=FRIDAY).event or {}
    assert friday["raw_event"]["evaluation_only"]["label"] == "PortScan"
    ftp = norm(make_row(**{" Destination Port": "21", " Label": "FTP-Patator"}),
               source_file=TUESDAY).event or {}
    assert ftp["destination_port"] == 21
    ssh = norm(make_row(**{" Destination Port": "22", " Label": "SSH-Patator"}),
               source_file=TUESDAY).event or {}
    assert ssh["protocol"] == "TCP"
    benign = norm(make_row(**{" Label": "BENIGN"}), source_file=TUESDAY).event or {}
    assert benign["raw_event"]["evaluation_only"]["label"] == "BENIGN"


def test_matches_event_create_contract():
    from app.schemas.events import EventCreate  # noqa: E402

    validated = EventCreate(**(norm(make_row()).event or {}))
    assert validated.source == SOURCE_ID
    assert validated.event_type == "network_connection"


def test_source_csv_never_modified():
    scratch = Path(tempfile.mkdtemp(prefix="esf-cic17-"))
    try:
        cols = ["Flow ID", " Source IP", " Destination IP", " Destination Port",
                " Protocol", " Timestamp", " SYN Flag Count", " ACK Flag Count",
                " Label"]
        target = scratch / "sample.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=cols)
            writer.writeheader()
            writer.writerow({"Flow ID": "1", " Source IP": "10.0.0.1",
                             " Destination IP": "10.0.0.2", " Destination Port": "80",
                             " Protocol": "6", " Timestamp": "7/7/2017 2:00",
                             " SYN Flag Count": "1", " ACK Flag Count": "1",
                             " Label": "BENIGN"})
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        rows = list(Cicids2017Adapter().iter_rows(target, limit=10))
        assert len(rows) == 1 and rows[0][0] == 1
        assert adapter.normalize_row(rows[0][1], source_file=FRIDAY, source_row=1).ok
        assert hashlib.sha256(target.read_bytes()).hexdigest() == before
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_no_ground_truth_in_adapter_code():
    pkg = Path(__file__).resolve().parents[1] / "app" / "services" / "datasets"
    targets = {"scenario_id", "scenario_type", "synthetic", "seed"}
    hits = []
    for path in sorted(pkg.glob("cicids2017*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"
