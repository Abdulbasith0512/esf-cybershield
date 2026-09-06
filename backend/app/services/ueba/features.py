"""Deterministic behavioral feature builder. Grain: (user, fixed UTC hour).

Only top-level telemetry columns are read. Identifiers group rows; they never
become features. raw_event and ground-truth labels are never read.
"""

import math
from datetime import datetime, timedelta, timezone

from app.services.detect.common import coerce_ts
from app.services.ueba.config import UebaConfig

AUTH = "authentication"


def _window_start(ts: datetime, hours: int) -> datetime:
    epoch = datetime(1970, 1, 1)
    n = int((ts - epoch).total_seconds()) // (hours * 3600)
    return epoch + timedelta(seconds=n * hours * 3600)


def build_observations(events: list[dict], config: UebaConfig | None = None) -> list[dict]:
    """Aggregate events into per-(user, window) numeric feature rows.

    Deduplicates by event_id, sorts by timestamp (order-invariant), uses only
    events at or before each window (no future leakage). Returns plain dicts:
    {entity_key, window_start, features{...12 cols...}, event_ids, event_count}.
    """
    config = config or UebaConfig()
    seen: set[str] = set()
    rows = []
    for e in events:
        eid = e.get("event_id")
        if not eid or eid in seen:
            continue
        seen.add(eid)
        user = e.get("user")
        if not user:
            continue
        row = dict(e)
        try:
            row["_ts"] = coerce_ts(e["timestamp"])
        except Exception:
            continue
        rows.append(row)
    rows.sort(key=lambda r: (r["_ts"], r.get("event_id", "")))

    groups: dict[tuple[str, datetime], list[dict]] = {}
    order: list[tuple[str, datetime]] = []
    for r in rows:
        key = (r["user"], _window_start(r["_ts"], config.window_hours))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)

    # Prior-window IP memory per user (causal: only earlier windows).
    user_ips: dict[str, set[str]] = {}
    observations = []
    for user, wstart in sorted(order, key=lambda k: (k[1], k[0])):
        members = groups[(user, wstart)]
        known = user_ips.setdefault(user, set())
        feats = _featurize(members, known, config)
        for m in members:
            if m.get("source_ip"):
                known.add(m["source_ip"])
        observations.append({
            "entity_key": user,
            "window_start": wstart,
            "features": feats,
            "event_ids": sorted(m["event_id"] for m in members),
            "event_count": len(members),
        })
    observations.sort(key=lambda o: (o["window_start"], o["entity_key"]))
    return observations


def _featurize(members: list[dict], known_ips: set[str], config: UebaConfig) -> dict[str, float]:
    auth = [m for m in members if m.get("event_type") == AUTH]
    fails = [m for m in auth if (m.get("status") or "").lower() in ("failed", "failure")]
    succs = [m for m in auth if (m.get("status") or "").lower() in ("success", "successful", "succeeded")]
    src_ips = {m["source_ip"] for m in members if m.get("source_ip")}
    dsts = {m.get("destination_ip") or m.get("domain") or "" for m in members}
    dsts.discard("")
    hour_of = lambda m: m["_ts"].hour  # noqa: E731 - naive UTC, same convention as rules
    unusual = sum(1 for m in members
                  if not (config.day_start_hour <= hour_of(m) < config.day_end_hour))
    out_bytes = sum(int(m.get("bytes_sent") or 0) for m in members)
    feats = {
        "event_count": float(len(members)),
        "auth_event_count": float(len(auth)),
        "failed_auth_count": float(len(fails)),
        "successful_auth_count": float(len(succs)),
        "failed_auth_ratio": (len(fails) / len(auth)) if auth else 0.0,
        "unique_source_ip_count": float(len(src_ips)),
        "new_source_ip_count": float(len(src_ips - known_ips)),
        "unique_destination_count": float(len(dsts)),
        "dns_event_count": float(sum(1 for m in members if m.get("event_type") == "dns_query")),
        "outbound_bytes_log1p": math.log1p(max(out_bytes, 0)),
        "process_event_count": float(sum(1 for m in members if m.get("event_type") == "process_creation")),
        "unusual_hour_event_count": float(unusual),
    }
    return {k: round(float(v), 6) for k, v in feats.items()}
