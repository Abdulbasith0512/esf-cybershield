"""Run the Slice 3 detection engine over a JSONL dataset (dev/validation only).

Not a public API. Reads events, runs engine.detect(), prints per-rule counts,
inspects credential_compromise_001 + benign_volume, and checks determinism
(second run must yield identical fingerprints).

Usage:
    python scripts/run_detection.py data/synthetic/events.jsonl
"""

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.detect.engine import detect  # noqa: E402


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/events.jsonl")
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    dets = detect(events)
    counts = Counter(d.rule_id for d in dets)
    print(f"{len(events)} events -> {len(dets)} detections")
    for rid, n in sorted(counts.items()):
        print(f"  {rid}: {n}")

    print("\ncredential_compromise_001:")
    by_id = {e["event_id"]: e for e in events}
    cc_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_id") == "credential_compromise_001"}
    for d in sorted(dets, key=lambda d: d.rule_id):
        if set(d.evidence_event_ids) & cc_ids:
            print(f"  {d.rule_id} conf={d.confidence} evidence={len(d.evidence_event_ids)}")

    print("\nbenign_volume DATA-001 check:")
    bv_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_type") == "benign_volume"}
    bv_data = [d for d in dets if d.rule_id == "DATA-001" and set(d.evidence_event_ids) & bv_ids]
    print(f"  benign_volume events implicated in DATA-001: {len(bv_data)} "
          f"(expected 0 at 1 GB threshold; <=300 MB per event)")

    again = detect(events)
    same = [d.fingerprint for d in dets] == [d.fingerprint for d in again]
    print(f"\ndeterminism: {'IDENTICAL' if same else 'MISMATCH'}")
    # Ground-truth hygiene: engine output must not embed labels as features.
    leaked = [d for d in dets if any("scenario" in str(v) for v in d.metadata.values())]
    print(f"label leakage in metadata: {len(leaked)}")
    if not same or leaked:
        sys.exit(1)


if __name__ == "__main__":
    main()
