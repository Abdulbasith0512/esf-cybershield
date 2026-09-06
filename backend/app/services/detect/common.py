"""Rule protocol + shared input coercion. Engine owns sorting, not rules."""

from datetime import datetime, timezone
from typing import Any, Protocol

from app.services.detect.models import DetectionResult


class Rule(Protocol):
    rule_id: str
    name: str
    description: str
    severity: str

    def evaluate(self, events: list[dict[str, Any]]) -> list[DetectionResult]:
        ...


def coerce_ts(value: Any) -> datetime:
    """Accept aware/naive datetime or ISO string -> naive UTC datetime."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def prepare(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy input, attach _ts (naive UTC), sort by timestamp.

    Input order is NEVER trusted (Slice 2 emits out-of-order delivery).
    Originals are never modified; raw_event is never read.
    """
    rows = []
    for e in events:
        row = dict(e)
        row["_ts"] = coerce_ts(e["timestamp"])
        rows.append(row)
    rows.sort(key=lambda r: (r["_ts"], r.get("event_id", "")))
    return rows
