"""Observable normalization and incident IOC extraction.

Read-only over stored event rows. Only SecurityEvent columns are read; never
benchmark labels (evaluation_only / Label-style fields are not even accessed).
Malformed values are rejected, never coerced into a lookup.
"""

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.services.threatintel.models import Observable

_MAX_EVENT_REFS = 25

_HASH_LENGTHS = {32, 40, 64}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# (column, observable type, source label) in deterministic extraction order.
_EXTRACT_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("source_ip", "ip", "source_ip"),
    ("destination_ip", "ip", "destination_ip"),
    ("domain", "domain", "domain"),
    ("url", "url", "url"),
    ("file_hash", "file_hash", "file_hash"),
)


def _normalize_ip(value: str) -> tuple[str, str] | None:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    kind = "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"
    return kind, str(addr)


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return None
    try:
        ascii_form = candidate.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if not all(_DOMAIN_LABEL_RE.match(part) for part in ascii_form.split(".")):
        return None
    return ascii_form


def _normalize_url(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    host = _normalize_domain(parsed.hostname)
    if host is None:
        return None
    rebuilt = parsed._replace(netloc=host if parsed.port is None
                              else f"{host}:{parsed.port}")
    return rebuilt.geturl()


def _normalize_hash(value: str) -> str | None:
    candidate = value.strip().lower()
    if len(candidate) not in _HASH_LENGTHS or not _HEX_RE.match(candidate):
        return None
    return candidate


def normalize_observable(observable_type: str, value: str | None) -> tuple[str, str] | None:
    """Return (concrete_type, normalized) or None when malformed/unsupported."""
    if not isinstance(value, str) or not value.strip():
        return None
    kind = (observable_type or "").strip().lower()
    if kind == "ip":
        return _normalize_ip(value)
    if kind == "ipv4":
        out = _normalize_ip(value)
        return out if out and out[0] == "ipv4" else None
    if kind == "ipv6":
        out = _normalize_ip(value)
        return out if out and out[0] == "ipv6" else None
    if kind == "domain":
        out = _normalize_domain(value)
        return ("domain", out) if out else None
    if kind == "url":
        out = _normalize_url(value)
        return ("url", out) if out else None
    if kind in ("file_hash", "hash"):
        out = _normalize_hash(value)
        return ("file_hash", out) if out else None
    return None


def _ts_key(value) -> str:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()
    return str(value)


def extract_observables(event_rows: list) -> list[Observable]:
    """Extract deduplicated observables from stored event rows.

    Accepts ORM rows (or duck-typed namespaces) exposing SecurityEvent column
    attributes. Input order does not affect output order: results sort by
    (type, normalized_value). Each observable keeps a bounded, sorted sample
    of source event IDs plus the total event count.
    """
    grouped: dict[tuple[str, str, str], dict] = {}
    for row in event_rows:
        event_id = str(getattr(row, "event_id", ""))
        seen = _ts_key(getattr(row, "timestamp", ""))
        for column, requested, source in _EXTRACT_FIELDS:
            raw = getattr(row, column, None)
            normalized = normalize_observable(requested, raw)
            if normalized is None:
                continue
            concrete, norm_value = normalized
            key = (concrete, norm_value, source)
            slot = grouped.get(key)
            if slot is None:
                grouped[key] = {
                    "type": concrete, "value": str(raw).strip(),
                    "normalized_value": norm_value, "source": source,
                    "first_seen": seen, "last_seen": seen,
                    "event_ids": {event_id} if event_id else set(),
                }
            else:
                if seen < slot["first_seen"]:
                    slot["first_seen"] = seen
                if seen > slot["last_seen"]:
                    slot["last_seen"] = seen
                if event_id:
                    slot["event_ids"].add(event_id)
    observables = []
    for key in sorted(grouped):
        slot = grouped[key]
        event_ids = sorted(slot["event_ids"])
        observables.append(Observable(
            type=slot["type"], value=slot["value"],
            normalized_value=slot["normalized_value"], source=slot["source"],
            first_seen=slot["first_seen"], last_seen=slot["last_seen"],
            event_count=len(event_ids), event_ids=event_ids[:_MAX_EVENT_REFS],
        ))
    return observables
