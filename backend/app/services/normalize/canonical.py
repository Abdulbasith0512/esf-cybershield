"""Safe canonicalization for SecurityEvent fields.

Only: trim strings, empty -> NULL, lowercase event_type, uppercase protocol,
canonical IP string, port range already enforced by Pydantic, timestamps kept
timezone-aware (naive rejected at the contract layer).

raw_event is NEVER touched here — it is stored byte-identical as parsed.
No threat detection, no malicious/benign classification.
"""

from datetime import timezone
from typing import Any


def _norm_str(v: str | None, *, lower: bool = False, upper: bool = False) -> str | None:
    if v is None:
        return None
    s = v.strip()
    if not s:
        return None
    if lower:
        s = s.lower()
    if upper:
        s = s.upper()
    return s


def normalize_event(validated: dict[str, Any]) -> dict[str, Any]:
    """Take a validated EventCreate dict, return DB-ready column values."""
    out = dict(validated)
    out["event_id"] = validated["event_id"].strip()
    out["event_type"] = validated["event_type"].strip().lower()
    out["source"] = validated["source"].strip()
    out["host"] = _norm_str(validated.get("host"))
    out["user"] = _norm_str(validated.get("user"))
    out["source_ip"] = _norm_str(validated.get("source_ip"))
    out["destination_ip"] = _norm_str(validated.get("destination_ip"))
    out["protocol"] = _norm_str(validated.get("protocol"), upper=True)
    out["process_name"] = _norm_str(validated.get("process_name"))
    out["parent_process"] = _norm_str(validated.get("parent_process"))
    out["command_line"] = _norm_str(validated.get("command_line"))
    out["file_hash"] = _norm_str(validated.get("file_hash"), lower=True)
    out["domain"] = _norm_str(validated.get("domain"), lower=True)
    out["url"] = _norm_str(validated.get("url"))
    out["status"] = _norm_str(validated.get("status"), lower=True)
    ts = validated["timestamp"]
    if ts.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    out["timestamp"] = ts.astimezone(timezone.utc)
    out["raw_event"] = validated["raw_event"]
    return out
