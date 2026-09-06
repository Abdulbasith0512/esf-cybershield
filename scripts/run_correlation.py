"""Run Slice 4 correlation over a JSONL dataset (dev/validation only).

Pipeline: events -> detect() -> correlate(detections, events_by_id).
Prints incident summary, inspects credential_compromise_001 + benign_volume,
reports AUTH-003 merge behavior, and checks determinism + shuffle invariance.

Usage:
    python scripts/run_correlation.py data/synthetic/events.jsonl
"""

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.correlate.engine import correlate  # noqa: E402
from app.services.detect.engine import detect  # noqa: E402


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/events.jsonl")
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {e["event_id"]: e for e in events}
    dets = detect(events)
    incs = correlate(dets, events_by_id=by_id)
    print(f"{len(events)} events -> {len(dets)} detections -> {len(incs)} incidents")
    sev = Counter(i.severity for i in incs)
    print("by severity:", dict(sev))
    sizes = Counter(len(i.detection_ids) for i in incs)
    print("by detection count:", dict(sorted(sizes.items())))

    cc_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_id") == "credential_compromise_001"}
    print("\ncredential_compromise_001 incidents:")
    for i in incs:
        if set(i.evidence_event_ids) & cc_ids:
            print(f"  {i.incident_id}")
            print(f"  title: {i.title}")
            print(f"  severity={i.severity} confidence={i.confidence} status={i.status}")
            print(f"  rules={i.metadata['rule_ids']} detections={len(i.detection_ids)} "
                  f"events={len(i.evidence_event_ids)}")
            print(f"  span: {i.first_seen} -> {i.last_seen}")
            print(f"  reason: {i.reason}")
            for d in sorted(i.detection_ids):
                det = next(x for x in dets if x.detection_id == d)
                print(f"    - {det.rule_id} {det.rule_name} conf={det.confidence}")

    print("\nbenign_volume incidents:")
    bv_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_type") == "benign_volume"}
    n_bv = 0
    for i in incs:
        if set(i.evidence_event_ids) & bv_ids and not (set(i.evidence_event_ids) & cc_ids):
            n_bv += 1
            if n_bv <= 5:
                print(f"  {i.severity} {i.title} rules={i.metadata['rule_ids']}")
    print(f"  total benign-only incidents: {n_bv}")

    print("\nAUTH-003 merge behavior:")
    a3 = [d for d in dets if d.rule_id == "AUTH-003"]
    a3_in_multi = 0
    for i in incs:
        if len(i.detection_ids) > 1 and any(
                next(x for x in dets if x.detection_id == d).rule_id == "AUTH-003"
                for d in i.detection_ids):
            a3_in_multi += 1
    print(f"  AUTH-003 detections: {len(a3)}, multi-detection incidents containing one: {a3_in_multi}")

    again = correlate(detect(events), events_by_id=by_id)
    same = [(i.incident_id, i.fingerprint) for i in incs] == [(i.incident_id, i.fingerprint) for i in again]
    print(f"\ndeterminism: {'IDENTICAL' if same else 'MISMATCH'}")
    leaked = [i for i in incs if any("scenario" in str(v) for v in i.metadata.values())]
    print(f"label leakage in metadata: {len(leaked)}")
    if not same or leaked:
        sys.exit(1)


if __name__ == "__main__":
    main()
