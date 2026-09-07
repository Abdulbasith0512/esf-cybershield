"""Slice 12A tests: CSE-CIC-IDS2018 adapter. No DB, no API, tiny fixtures only."""

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
from app.services.datasets.cse_cic_ids2018 import (  # noqa: E402
    ADAPTER_VERSION,
    CseCicIds2018Adapter,
    SOURCE_ID,
)

adapter = CseCicIds2018Adapter()

# The 80-column flow schema observed in 02-14-2018.csv (profiled, read-only).
COLUMNS_80 = [
    "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts",
    "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max",
    "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max",
    "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s",
    "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Len",
    "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min",
    "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt",
    "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
    "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg", "Bwd Blk Rate Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts",
    "Subflow Bwd Pkts", "Subflow Bwd Byts", "Init Fwd Win Byts",
    "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min", "Label",
]


def make_row(**overrides):
    row = {c: "0" for c in COLUMNS_80}
    row.update({
        "Dst Port": "443",
        "Protocol": "6",
        "Timestamp": "14/02/2018 08:31:01",
        "Flow Duration": "1000",
        "Tot Fwd Pkts": "10",
        "Tot Bwd Pkts": "8",
        "TotLen Fwd Pkts": "5000",
        "TotLen Bwd Pkts": "3000",
        "Label": "Benign",
    })
    row.update(overrides)
    return row


def norm(row, source_file="f.csv", source_row=1):
    return adapter.normalize_row(row, source_file=source_file, source_row=source_row)


def test_timestamp_parsing():
    result = norm(make_row(), source_file="02-14-2018.csv")
    assert result.ok
    assert result.event is not None
    assert result.event["timestamp"] == "2018-02-14T08:31:01+00:00"


def test_timestamp_utc_aware():
    from datetime import datetime, timezone

    result = norm(make_row(), source_file="02-14-2018.csv")
    assert result.event is not None
    parsed = datetime.fromisoformat(result.event["timestamp"])
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)


def test_malformed_timestamp_rejected():
    result = norm(make_row(Timestamp="not-a-time"))
    assert not result.ok
    assert result.rejected is not None and result.rejected.code == "bad_timestamp"
    result = norm(make_row(Timestamp=""))
    assert not result.ok and result.rejected is not None


def test_missing_endpoint_ips_null():
    result = norm(make_row(), source_file="02-14-2018.csv")
    assert result.event is not None
    assert result.event["source_ip"] is None
    assert result.event["destination_ip"] is None
    assert result.event["user"] is None
    assert result.event["host"] is None


def test_endpoint_rich_row_maps_real_ips():
    row = make_row(**{"Src IP": " 172.16.0.5 ", "Src Port": "52344",
                      "Dst IP": "192.168.10.50", "Dst Port": "80"})
    result = norm(row, source_file="02-20-2018.csv")
    assert result.ok and result.event is not None
    assert result.event["source_ip"] == "172.16.0.5"
    assert result.event["destination_ip"] == "192.168.10.50"
    assert result.event["destination_port"] == 80
    # Src Port has no canonical field: preserved inside flow, not top-level.
    assert result.event["raw_event"]["flow"]["Src Port"] == 52344


def test_invalid_ip_becomes_null_not_fabricated():
    row = make_row(**{"Src IP": "999.1.1.1", "Dst IP": "nope"})
    result = norm(row, source_file="02-20-2018.csv")
    assert result.ok and result.event is not None
    assert result.event["source_ip"] is None
    assert result.event["destination_ip"] is None


def test_label_evaluation_only():
    result = norm(make_row(Label="FTP-BruteForce"))
    assert result.event is not None
    evaluation = result.event["raw_event"]["evaluation_only"]
    assert evaluation == {"label": "FTP-BruteForce", "evaluation": True}


def test_label_cannot_influence_event_type():
    benign = norm(make_row(Label="Benign")).event or {}
    attack = norm(make_row(Label="SSH-Bruteforce")).event or {}
    assert benign["event_type"] == attack["event_type"] == "network_connection"
    assert benign["status"] == attack["status"] is None


def test_identical_flows_distinct_rows_distinct_ids():
    # A: two legitimate rows with byte-identical flow fields stay distinct.
    first = norm(make_row(), source_file="f.csv", source_row=7).event or {}
    second = norm(make_row(), source_file="f.csv", source_row=8).event or {}
    assert first["event_id"] != second["event_id"]


def test_same_source_row_same_id():
    # B: same dataset + file + source row -> same event_id, repeatedly.
    row = make_row()
    first = norm(dict(row), source_file="f.csv", source_row=41).event or {}
    second = norm(dict(row), source_file="f.csv", source_row=41).event or {}
    assert first["event_id"] == second["event_id"]
    assert first == second


def test_shuffled_processing_preserves_ids():
    # C: processing order never affects IDs; the row number travels with the row.
    numbered = [(i, make_row(Timestamp=f"14/02/2018 08:31:{i:02d}")) for i in range(1, 6)]
    forward = [norm(dict(r), source_file="f.csv", source_row=n).event or {}
               for n, r in numbered]
    backward = [norm(dict(r), source_file="f.csv", source_row=n).event or {}
                for n, r in reversed(numbered)]
    by_id_fwd = {e["event_id"]: e for e in forward}
    by_id_bwd = {e["event_id"]: e for e in backward}
    assert by_id_fwd == by_id_bwd


def test_source_file_contributes_to_identity():
    # D: same row number, different files -> different IDs.
    row = make_row()
    left = norm(dict(row), source_file="02-14-2018.csv", source_row=3).event or {}
    right = norm(dict(row), source_file="02-15-2018.csv", source_row=3).event or {}
    assert left["event_id"] != right["event_id"]


def test_source_row_contributes_to_identity():
    # E: same file, different row numbers -> different IDs.
    row = make_row()
    left = norm(dict(row), source_file="f.csv", source_row=3).event or {}
    right = norm(dict(row), source_file="f.csv", source_row=4).event or {}
    assert left["event_id"] != right["event_id"]


def test_source_file_provenance():
    result = norm(make_row(), source_file="02-14-2018.csv")
    assert result.event is not None
    raw = result.event["raw_event"]
    assert raw["source_file"] == "02-14-2018.csv"
    assert raw["dataset"] == "CSE-CIC-IDS2018"
    assert raw["adapter_version"] == ADAPTER_VERSION


def test_all_columns_mapped_or_preserved():
    result = norm(make_row())
    assert result.event is not None
    top_level_sources = {"Dst Port", "Protocol", "Timestamp"}
    flow = result.event["raw_event"]["flow"]
    for col in COLUMNS_80:
        if col == "Label":
            assert result.event["raw_event"]["evaluation_only"]["label"] == "Benign"
        elif col not in top_level_sources:
            assert col in flow, f"column lost: {col}"


def test_no_label_in_feature_structures():
    event = norm(make_row(Label="FTP-BruteForce")).event or {}
    top = {k: v for k, v in event.items() if k != "raw_event"}
    assert "FTP-BruteForce" not in str(top)
    assert "FTP-BruteForce" not in str(event.get("event_id"))
    # Renaming the label must not change any top-level field.
    renamed = norm(make_row(Label="Something-Else")).event or {}
    assert {k: v for k, v in renamed.items() if k != "raw_event"} == top


def test_malformed_numerics_safe():
    result = norm(make_row(**{"TotLen Fwd Pkts": "abc", "TotLen Bwd Pkts": "-5"}))
    assert result.ok and result.event is not None
    assert result.event["bytes_sent"] is None
    assert result.event["bytes_received"] is None
    bad_port = norm(make_row(**{"Dst Port": "99999"}))
    assert not bad_port.ok and bad_port.rejected is not None
    assert bad_port.rejected.code == "bad_port"


def test_source_csv_never_modified():
    # NOTE: pytest's tmp_path is unusable on machines where
    # %TEMP%\pytest-of-<user> is owned by another principal; use a fresh
    # mkdtemp directory instead (same semantics, no fixed dirname).
    scratch = Path(tempfile.mkdtemp(prefix="esf-cic-"))
    try:
        target = scratch / "sample.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS_80)
            writer.writeheader()
            writer.writerow(make_row())
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        rows = list(CseCicIds2018Adapter().iter_rows(target, limit=10))
        assert len(rows) == 1
        source_row, raw = rows[0]
        assert source_row == 1
        assert adapter.normalize_row(raw, source_file=target.name, source_row=source_row).ok
        assert hashlib.sha256(target.read_bytes()).hexdigest() == before
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_iter_rows_numbers_capture_order():
    scratch = Path(tempfile.mkdtemp(prefix="esf-cic-"))
    try:
        target = scratch / "numbered.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS_80)
            writer.writeheader()
            for i in range(3):
                writer.writerow(make_row(Timestamp=f"14/02/2018 08:31:{i:02d}"))
        numbered = list(CseCicIds2018Adapter().iter_rows(target))
        assert [n for n, _ in numbered] == [1, 2, 3]
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_matches_event_create_contract():
    event = norm(make_row()).event or {}
    validated = EventCreate(**event)
    assert validated.source == SOURCE_ID
    assert validated.event_type == "network_connection"


def test_no_ground_truth_in_adapter_code():
    pkg = Path(__file__).resolve().parents[1] / "app" / "services" / "datasets"
    targets = {"scenario_id", "scenario_type", "synthetic", "seed"}
    hits = []
    for path in pkg.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in targets:
                hits.append(f"{path.name}:{node.attr} (attribute)")
            elif isinstance(node, ast.Constant) and node.value in targets:
                hits.append(f"{path.name}:{node.value!r} (literal)")
    assert hits == [], f"ground-truth leakage: {hits}"
