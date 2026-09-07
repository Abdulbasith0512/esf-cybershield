"""CSE-CIC-IDS2018 flow-row adapter (Canadian Institute for Cybersecurity).

Converts CICFlowMeter CSV rows into EventCreate-compatible dicts without
inventing telemetry. Endpoint columns (Src IP/Port, Dst IP) exist only in
some files: when absent the canonical fields stay null. The dataset Label
is preserved solely as evaluation-only metadata inside raw_event and never
influences event_type, severity, features, or identity.
"""

import ipaddress
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from app.services.datasets.base import NormalizeResult, RejectReason, stream_csv_rows

DATASET_NAME = "CSE-CIC-IDS2018"
DATASET_SOURCE = "Canadian Institute for Cybersecurity (CIC) / Communications Security Establishment (CSE)"
SOURCE_ID = "cse_cic_ids2018"
ADAPTER_VERSION = "cse-cic-ids2018-v1"
EVENT_TYPE = "network_connection"
TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"
NAMESPACE = uuid.UUID("c7a2b4e1-3f5d-5a6b-8c9d-0e1f2a3b4c5d")

LABEL_COLUMN = "Label"
TIMESTAMP_COLUMN = "Timestamp"

# Canonical top-level mapping: CSV column -> (EventCreate field, parser).
# Everything else is preserved verbatim under raw_event.flow.
PROTOCOL_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP"}

# Deterministic event identity: dataset + adapter version + source file +
# ORIGINAL source row number (1-based data-row index, captured at read time
# before any sorting, filtering, or batching). Flow fields are deliberately
# NOT part of the identity — two legitimate rows may share every observable
# field and must still remain distinct events. Row processing order never
# affects IDs as long as the original row number travels with the row.


def _clean(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ("" if value is None else str(value).strip())


def _parse_int(value: str) -> int | None:
    try:
        return int(float(_clean(value)))
    except (ValueError, TypeError):
        return None


def _parse_float(value: str) -> float | None:
    try:
        return float(_clean(value).replace(",", ""))
    except (ValueError, TypeError):
        return None


def _parse_ip(value: str) -> str | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def _parse_timestamp(value: str) -> datetime | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    try:
        # Capture timestamps carry no zone info; interpret as UTC and say so.
        return datetime.strptime(cleaned, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _flow_number(value: str) -> int | float | str:
    """Preserve a CIC feature losslessly: int when integral, else float, else raw text."""
    cleaned = _clean(value).replace(",", "")
    if not cleaned:
        return ""
    try:
        num = float(cleaned)
    except ValueError:
        return _clean(value)
    return int(num) if num.is_integer() else num


class CseCicIds2018Adapter:
    """Stateless row normalizer for CSE-CIC-IDS2018 processed CSVs."""

    name: str = DATASET_NAME
    version: str = ADAPTER_VERSION

    def iter_rows(self, path: str | Path, *, limit: int | None = None) -> Iterator[tuple[int, dict[str, str]]]:
        """Yield (source_row, row) pairs. source_row is the 1-based data-row
        index in the file, captured here at read time before any downstream
        sorting, filtering, or batching can change the order."""
        for source_row, row in enumerate(stream_csv_rows(path, limit=limit), start=1):
            yield source_row, row

    @staticmethod
    def _norm_columns(row: Mapping[str, Any]) -> dict[str, str]:
        # CIC headers carry stray whitespace; normalize internally only.
        return {_clean(k): (v if isinstance(v, str) else _clean(v)) for k, v in row.items()}

    @classmethod
    def event_id_for(cls, source_file: str, source_row: int) -> str:
        identity = f"{SOURCE_ID}|{ADAPTER_VERSION}|{source_file}|{source_row}"
        return str(uuid.uuid5(NAMESPACE, identity))

    def normalize_row(self, row: Mapping[str, Any], *, source_file: str, source_row: int) -> NormalizeResult:
        cols = self._norm_columns(row)

        ts = _parse_timestamp(cols.get(TIMESTAMP_COLUMN, ""))
        if ts is None:
            return NormalizeResult(rejected=RejectReason(
                code="bad_timestamp",
                detail=f"unparseable {TIMESTAMP_COLUMN!r}: {cols.get(TIMESTAMP_COLUMN, '')[:64]!r}"))

        port_raw = _clean(cols.get("Dst Port", ""))
        dst_port: int | None = None
        if port_raw:
            dst_port = _parse_int(port_raw)
            if dst_port is None or not 0 <= dst_port <= 65535:
                return NormalizeResult(rejected=RejectReason(
                    code="bad_port", detail=f"invalid Dst Port: {port_raw[:32]!r}"))

        # Endpoint-aware only when the file actually carries these columns.
        # Src Port has no canonical top-level field; it stays inside flow.
        source_ip = _parse_ip(cols.get("Src IP", "")) if "Src IP" in cols else None
        destination_ip = _parse_ip(cols.get("Dst IP", "")) if "Dst IP" in cols else None

        proto_raw = _clean(cols.get("Protocol", ""))
        protocol = PROTOCOL_NAMES.get(proto_raw, proto_raw or None)

        bytes_sent = _parse_int(cols.get("TotLen Fwd Pkts", ""))
        if bytes_sent is not None and bytes_sent < 0:
            bytes_sent = None
        bytes_received = _parse_int(cols.get("TotLen Bwd Pkts", ""))
        if bytes_received is not None and bytes_received < 0:
            bytes_received = None

        label = _clean(cols.get(LABEL_COLUMN, ""))
        flow = {col: _flow_number(val) for col, val in cols.items() if col != LABEL_COLUMN}

        event = {
            "event_id": self.event_id_for(source_file, source_row),
            "timestamp": ts.isoformat(),
            "event_type": EVENT_TYPE,
            "source": SOURCE_ID,
            "host": None,
            "user": None,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": dst_port,
            "protocol": protocol,
            "process_name": None,
            "parent_process": None,
            "command_line": None,
            "file_hash": None,
            "domain": None,
            "url": None,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "status": None,
            "raw_event": {
                "dataset": DATASET_NAME,
                "dataset_source": DATASET_SOURCE,
                "source_file": source_file,
                "adapter_version": ADAPTER_VERSION,
                "evaluation_only": {
                    "label": label,
                    "evaluation": True,
                },
                "flow": flow,
            },
        }
        return NormalizeResult(event=event)