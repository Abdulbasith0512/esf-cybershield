"""Pure normalization: vendor JSON -> canonical fields. No DB access."""

import ipaddress
from datetime import datetime, timezone
from typing import Any


def _clean_str(v: Any, default: str = "unknown") -> str:
    if v is None:
        return default
    s = str(v).strip().lower()
    return s if s else default


def _clean_nullable_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _valid_ip(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return None


def normalize_payload(payload: dict, fallback_ts: datetime | None = None) -> dict:
    """Return canonical dict. Raises ValueError on invalid IPs (caller -> 422)."""
    raw_src = payload.get("src_ip", payload.get("srcIp", payload.get("source_ip")))
    raw_dst = payload.get("dst_ip", payload.get("dstIp", payload.get("dest_ip")))

    # Strict: reject malformed IPs that were explicitly provided.
    for label, raw in (("src_ip", raw_src), ("dst_ip", raw_dst)):
        if raw is not None and str(raw).strip() != "" and _valid_ip(str(raw)) is None:
            raise ValueError(f"invalid {label}: {raw!r}")

    ts = payload.get("timestamp", payload.get("ts", payload.get("time")))
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            ts = fallback_ts or datetime.utcnow()
    elif not isinstance(ts, datetime):
        ts = fallback_ts or datetime.utcnow()
    # Normalize to naive UTC (SQLite returns naive; PG handles naive as UTC).
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)

    raw_port = payload.get("dst_port", payload.get("dstPort", payload.get("dport")))
    dst_port = None
    if raw_port is not None:
        try:
            dst_port = int(raw_port)
        except (ValueError, TypeError):
            dst_port = None

    return {
        "ts": ts,
        "user_id": _clean_str(payload.get("user_id", payload.get("user", payload.get("username")))),
        "host": _clean_str(payload.get("host", payload.get("hostname", payload.get("computer")))),
        "src_ip": _valid_ip(str(raw_src)) if raw_src else None,
        "dst_ip": _valid_ip(str(raw_dst)) if raw_dst else None,
        "dst_port": dst_port,
        "event_type": _clean_str(payload.get("event_type", payload.get("type", "unknown"))),
        "action": _clean_str(payload.get("action", payload.get("event", "unknown"))),
        "status": _clean_str(payload.get("status", payload.get("result", "unknown"))),
    }
