"""CICIDS2017 flow-row adapter (Canadian Institute for Cybersecurity).

Converts CICIDS2017 TrafficLabelling CSV rows into EventCreate-compatible
dicts without inventing telemetry. Mirrors the CSE-CIC-IDS2018 adapter
contract (identity, event shape, evaluation-only labels); only the header
vocabulary and timestamp convention differ and are mapped explicitly below.
The dataset Label is preserved solely as evaluation-only metadata inside
raw_event and never influences event_type, severity, features, or identity.
"""

import ipaddress
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from app.services.datasets.base import AdapterError, NormalizeResult, RejectReason, stream_csv_rows

DATASET_NAME = "CICIDS2017"
DATASET_SOURCE = "Canadian Institute for Cybersecurity (CIC), University of New Brunswick"
SOURCE_ID = "cicids2017"
ADAPTER_VERSION = "cicids2017-v1"
EVENT_TYPE = "network_connection"
# Deterministic namespace constant (derived, not random): uuid5(DNS, name).
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "esf-cybershield.cicids2017")

LABEL_COLUMN = "Label"
TIMESTAMP_COLUMN = "Timestamp"

# Canonical top-level mapping: CSV column -> (EventCreate field, parser).
# Everything else is preserved verbatim under raw_event.flow.
PROTOCOL_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP"}

# Verbose TrafficLabelling header (stripped) -> canonical CICFlowMeter key
# used by FlowView's numeric allowlist. Only existing columns are mapped;
# nothing is fabricated. Keys absent from a row simply stay absent, and
# FlowView's flow_value() defaults apply at the call site.
FIELD_ALIASES = {
    "Total Fwd Packets": "Tot Fwd Pkts",
    "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Avg Fwd Segment Size": "Fwd Seg Size Avg",
    "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "SYN Flag Count": "SYN Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "FIN Flag Count": "FIN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "Fwd Header Length": "Fwd Header Len",
    "Bwd Header Length": "Bwd Header Len",
    "Init_Win_bytes_forward": "Init Fwd Win Byts",
    "Init_Win_bytes_backward": "Init Bwd Win Byts",
}

# Day-first 12-hour clock without a meridian marker (e.g. "7/7/2017 2:53").
# Meridian is session context, fixed per frozen file and validated against
# the published capture chronology — never guessed per row:
# - "friday-pm": afternoon session file; hours 1-11 mean 13-23.
# - "tuesday-fullday": full-day file; hours 8-11 mean morning, 12 means noon,
#   hours 1-5 mean 13-17. Any other hour is rejected, never guessed.
SESSION_BY_FILENAME = (
    ("portscan", "friday-pm"),
    ("tuesday", "tuesday-fullday"),
)

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


def _parse_ip(value: str) -> str | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def session_for(source_file: str) -> str:
    """Meridian session for a source file. Unknown files fail closed."""
    lowered = _clean(source_file).lower()
    for marker, session in SESSION_BY_FILENAME:
        if marker in lowered:
            return session
    raise AdapterError(f"unknown CICIDS2017 session for meridian rule: {source_file}")


def _parse_timestamp(value: str, session: str) -> datetime | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    try:
        # Day-first 12-hour clock without a meridian marker (e.g. "7/7/2017
        # 2:53"). Parsed manually because strptime %I maps "12" to midnight
        # while these captures contain noon, never midnight.
        date_part, time_part = cleaned.split()
        day, month, year = (int(part) for part in date_part.split("/"))
        hour_token, minute = (int(part) for part in time_part.split(":"))
        if not 1 <= hour_token <= 12:
            return None
        hour = 12 if hour_token == 12 else hour_token
        naive = datetime(year, month, day, hour, minute)
    except (ValueError, AttributeError):
        return None
    if session == "friday-pm":
        if 1 <= hour_token <= 11:
            naive = naive.replace(hour=hour_token + 12)
    elif session == "tuesday-fullday":
        if hour_token == 12 or 8 <= hour_token <= 11:
            pass
        elif 1 <= hour_token <= 5:
            naive = naive.replace(hour=hour_token + 12)
        else:
            return None
    else:  # pragma: no cover - session_for only returns known sessions
        return None
    # Capture timestamps carry no zone info; interpret as UTC and say so.
    return naive.replace(tzinfo=timezone.utc)


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


class Cicids2017Adapter:
    """Stateless row normalizer for CICIDS2017 TrafficLabelling CSVs."""

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
        # Headers carry stray whitespace; normalize lookup keys only.
        cleaned = {_clean(k): (v if isinstance(v, str) else _clean(v)) for k, v in row.items()}
        for verbose, canonical in FIELD_ALIASES.items():
            if verbose in cleaned and canonical not in cleaned:
                cleaned[canonical] = cleaned[verbose]
        return cleaned

    @classmethod
    def event_id_for(cls, source_file: str, source_row: int) -> str:
        identity = f"{SOURCE_ID}|{ADAPTER_VERSION}|{source_file}|{source_row}"
        return str(uuid.uuid5(NAMESPACE, identity))

    def normalize_row(self, row: Mapping[str, Any], *, source_file: str, source_row: int) -> NormalizeResult:
        try:
            session = session_for(source_file)
        except AdapterError as exc:
            return NormalizeResult(rejected=RejectReason(code="bad_session", detail=str(exc)))
        cols = self._norm_columns(row)

        ts = _parse_timestamp(cols.get(TIMESTAMP_COLUMN, ""), session)
        if ts is None:
            return NormalizeResult(rejected=RejectReason(
                code="bad_timestamp",
                detail=f"unparseable {TIMESTAMP_COLUMN!r}: {cols.get(TIMESTAMP_COLUMN, '')[:64]!r}"))

        port_raw = _clean(cols.get("Destination Port", ""))
        dst_port: int | None = None
        if port_raw:
            dst_port = _parse_int(port_raw)
            if dst_port is None or not 0 <= dst_port <= 65535:
                return NormalizeResult(rejected=RejectReason(
                    code="bad_port", detail=f"invalid Destination Port: {port_raw[:32]!r}"))

        # Endpoint-aware only when the file actually carries these columns.
        source_ip = _parse_ip(cols.get("Source IP", "")) if "Source IP" in cols else None
        destination_ip = _parse_ip(cols.get("Destination IP", "")) if "Destination IP" in cols else None

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
