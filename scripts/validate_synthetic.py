"""Validate a generated telemetry file (JSONL or CSV).

Checks: event_id uniqueness, required fields, tz-aware non-future timestamps,
valid IPs/ports, controlled event-type vocabulary, scenario metadata presence
+ consistency, secret-pattern scan, and full EventCreate conformance.

Usage:
    python scripts/validate_synthetic.py data/synthetic/events.jsonl
    python scripts/validate_synthetic.py data/synthetic/events.csv --format csv
Exit 0 = valid, 1 = problems found.
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = ["event_id", "timestamp", "event_type", "source", "raw_event"]
VOCAB = {"authentication", "process_creation", "network_connection",
         "dns_query", "file_activity", "data_transfer"}
SECRET_PATTERNS = [re.compile(p, re.IGNORECASE) for p in
                   [r"password", r"passwd", r"api[_-]?key\s*[:=]", r"secret",
                    r"BEGIN [A-Z ]*PRIVATE KEY", r"aws_secret", r"client_secret"]]


def load(path: Path, fmt: str) -> list[dict]:
    if fmt == "csv":
        with open(path, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        for r in rows:
            for k in ("destination_port", "bytes_sent", "bytes_received"):
                if r.get(k) in (None, ""):
                    r[k] = None
                else:
                    r[k] = int(r[k])
            for k in list(r):
                if r[k] == "" and k not in ("raw_event",):
                    r[k] = None
            r["raw_event"] = json.loads(r["raw_event"])
        return rows
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate synthetic telemetry file.")
    ap.add_argument("path", help="JSONL or CSV file to validate")
    ap.add_argument("--format", choices=["jsonl", "csv"], default=None)
    ap.add_argument("--allow-future", action="store_true")
    args = ap.parse_args()

    path = Path(args.path)
    fmt = args.format or ("csv" if path.suffix == ".csv" else "jsonl")
    errors: list[str] = []
    try:
        events = load(path, fmt)
    except Exception as exc:  # noqa: BLE001
        print(f"LOAD FAILED: {exc}", file=sys.stderr)
        sys.exit(1)

    seen: set[str] = set()
    scenarios: dict[str, str] = {}
    now = datetime.now(timezone.utc)
    for i, e in enumerate(events):
        tag = f"record {i} ({e.get('event_id', '?')})"
        for field in REQUIRED:
            if not e.get(field):
                errors.append(f"{tag}: missing required {field}")
        eid = e.get("event_id")
        if eid:
            if eid in seen:
                errors.append(f"{tag}: duplicate event_id")
            seen.add(eid)
        try:
            ts = datetime.fromisoformat(str(e.get("timestamp", "")).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                errors.append(f"{tag}: naive timestamp")
            elif not args.allow_future and ts > now:
                errors.append(f"{tag}: future timestamp")
        except ValueError:
            errors.append(f"{tag}: bad timestamp {e.get('timestamp')!r}")
        if e.get("event_type") not in VOCAB:
            errors.append(f"{tag}: bad event_type {e.get('event_type')!r}")
        for f in ("source_ip", "destination_ip"):
            if e.get(f):
                try:
                    ipaddress.ip_address(e[f])
                except ValueError:
                    errors.append(f"{tag}: bad {f}")
        port = e.get("destination_port")
        if port is not None and not (0 <= port <= 65535):
            errors.append(f"{tag}: bad port {port}")
        raw = e.get("raw_event") or {}
        for k in ("generator", "scenario_id", "scenario_type"):
            if not raw.get(k):
                errors.append(f"{tag}: raw_event missing {k}")
        sid, stype = raw.get("scenario_id"), raw.get("scenario_type")
        if sid and stype:
            if sid in scenarios and scenarios[sid] != stype:
                errors.append(f"{tag}: scenario_id {sid} maps to two types")
            scenarios.setdefault(sid, stype)
        blob = json.dumps({"c": e.get("command_line"), "u": e.get("url"), "r": raw})
        for pat in SECRET_PATTERNS:
            if pat.search(blob):
                errors.append(f"{tag}: possible secret pattern {pat.pattern!r}")
                break

    # Full contract conformance via the real Pydantic schema.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    try:
        from app.schemas.events import EventCreate

        bad = 0
        for i, e in enumerate(events):
            try:
                EventCreate(**e)
            except Exception as exc:  # noqa: BLE001
                bad += 1
                if len(errors) < 50:
                    errors.append(f"record {i}: EventCreate: {exc}")
        contract = f"{len(events) - bad}/{len(events)} pass EventCreate"
    except ImportError as exc:
        contract = f"contract check skipped: {exc}"

    print(f"checked {len(events)} records, {len(scenarios)} scenario_ids, {contract}")
    if errors:
        print(f"INVALID: {len(errors)} problems (showing {min(len(errors), 20)}):", file=sys.stderr)
        for m in errors[:20]:
            print(f"  {m}", file=sys.stderr)
        sys.exit(1)
    print("VALID")


if __name__ == "__main__":
    main()
