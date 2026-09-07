"""Typed flow telemetry projection.

FlowView exposes ONLY the telemetry flow detectors may use: canonical
network fields plus an allowlist of CICFlowMeter numerics. Dataset labels
(scenario_*, Label, evaluation_only, synthetic, seed) are structurally
unrepresentable here — the builder copies allowlisted keys and nothing else.
"""

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

# CICFlowMeter columns a flow detector may consume. Everything else stays
# behind the raw_event boundary and is invisible to rules.
FLOW_NUMERIC_KEYS = (
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Pkt Len Mean",
    "Bwd Pkt Len Mean",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "SYN Flag Cnt",
    "ACK Flag Cnt",
    "RST Flag Cnt",
    "Fwd Header Len",
    "Bwd Header Len",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
)


def _num(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).replace(",", "").strip())
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class FlowView:
    """One flow observation. No labels, no provenance, no raw payload."""

    event_id: str
    ts: datetime
    source_ip: str | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str | None
    bytes_sent: int | None
    bytes_received: int | None
    flow: Mapping[str, float] = field(default_factory=dict)

    def flow_value(self, key: str, default: float = 0.0) -> float:
        value = self.flow.get(key)
        return value if value is not None else default


def build_views(rows: list[dict[str, Any]]) -> list[FlowView]:
    """Project prepared event rows (with _ts) into FlowViews.

    Rows that are not network telemetry are skipped. Malformed numerics
    become absent keys (never fabricated zeros in ambiguous positions —
    use flow_value() defaults at the call site instead).
    """
    views = []
    for row in rows:
        if row.get("event_type") != "network_connection":
            continue
        raw_flow = (row.get("raw_event") or {}).get("flow", {})
        if not isinstance(raw_flow, dict):
            raw_flow = {}
        flow: dict[str, float] = {}
        for key in FLOW_NUMERIC_KEYS:
            parsed = _num(raw_flow.get(key))
            if parsed is not None and math.isfinite(parsed):
                flow[key] = parsed
        views.append(FlowView(
            event_id=row["event_id"],
            ts=row["_ts"],
            source_ip=row.get("source_ip"),
            destination_ip=row.get("destination_ip"),
            destination_port=row.get("destination_port"),
            protocol=row.get("protocol"),
            bytes_sent=row.get("bytes_sent"),
            bytes_received=row.get("bytes_received"),
            flow=flow,
        ))
    return views
