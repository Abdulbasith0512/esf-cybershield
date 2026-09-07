"""Dry-run inspector for CSE-CIC-IDS2018 CSVs (dev/validation only).

Reads rows, normalizes via the adapter, prints statistics. Never writes to
PostgreSQL, never calls the ingestion API, never runs detection.

Usage:
    python scripts/inspect_cse_cic_ids2018.py --input data/public/cse_cic_ids2018/raw/02-14-2018.csv --limit 10000
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.datasets.cse_cic_ids2018 import CseCicIds2018Adapter  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect a CSE-CIC-IDS2018 CSV without persisting anything.")
    parser.add_argument("--input", required=True, help="Path to a source CSV file.")
    parser.add_argument("--limit", type=int, default=10000, help="Maximum rows to read.")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"ERROR: input is not a file: {input_path}", file=sys.stderr)
        sys.exit(2)

    adapter = CseCicIds2018Adapter()
    read = normalized = rejected = 0
    reasons: Counter[str] = Counter()
    event_types: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    missing_src_ip = missing_dst_ip = missing_user = missing_host = 0
    min_ts: str | None = None
    max_ts: str | None = None
    first_event: dict | None = None

    for source_row, raw in adapter.iter_rows(input_path, limit=args.limit):
        read += 1
        result = adapter.normalize_row(raw, source_file=input_path.name, source_row=source_row)
        if not result.ok:
            rejected += 1
            reasons[result.rejected.code if result.rejected else "unknown"] += 1
            continue
        normalized += 1
        event = result.event or {}
        assert event is not None
        event_types[event.get("event_type", "?")] += 1
        ts = str(event.get("timestamp", ""))
        min_ts = ts if min_ts is None or ts < min_ts else min_ts
        max_ts = ts if max_ts is None or ts > max_ts else max_ts
        if not event.get("source_ip"):
            missing_src_ip += 1
        if not event.get("destination_ip"):
            missing_dst_ip += 1
        if not event.get("user"):
            missing_user += 1
        if not event.get("host"):
            missing_host += 1
        label = (event.get("raw_event", {}) or {}).get("evaluation_only", {}).get("label", "")
        labels[label or "<empty>"] += 1
        if first_event is None:
            first_event = event

    # Deterministic ID check: same row normalized twice -> same event_id.
    det_ok = True
    for source_row, raw in adapter.iter_rows(input_path, limit=1):
        once = adapter.normalize_row(raw, source_file=input_path.name, source_row=source_row).event or {}
        twice = adapter.normalize_row(dict(raw), source_file=input_path.name, source_row=source_row).event or {}
        det_ok = once.get("event_id") == twice.get("event_id")

    print(f"rows read: {read}")
    print(f"rows normalized: {normalized}")
    print(f"rows rejected: {rejected}")
    print(f"rejection reasons: {dict(reasons) or 'none'}")
    print(f"event types: {dict(event_types)}")
    print(f"timestamp min/max: {min_ts} / {max_ts}")
    print(f"missing source_ip: {missing_src_ip}")
    print(f"missing destination_ip: {missing_dst_ip}")
    print(f"missing user: {missing_user}")
    print(f"missing host: {missing_host}")
    print(f"label distribution (evaluation-only, never a feature): {dict(labels)}")
    print(f"deterministic ID check: {'PASS' if det_ok else 'FAIL'}")
    if first_event is not None:
        summary = {k: first_event.get(k) for k in
                   ("event_id", "timestamp", "event_type", "source", "destination_port", "protocol")}
        summary["raw_keys"] = sorted((first_event.get("raw_event", {}) or {}).keys())
        print(f"sample event: {json.dumps(summary, default=str)[:400]}")
    if not det_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
