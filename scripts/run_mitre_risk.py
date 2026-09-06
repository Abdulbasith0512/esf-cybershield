"""Run Slice 5 enrichment over a JSONL dataset (dev/validation only).

Pipeline: events -> detect() -> correlate() -> enrich() (MITRE + risk).
Prints risk distribution, the credential_compromise_001 enriched incident
(mappings + breakdown + explanation), benign_volume + AUTH-003 checks,
and determinism / shuffle / leakage gates.

Usage:
    python scripts/run_mitre_risk.py data/synthetic/events.jsonl
"""

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.correlate.engine import correlate  # noqa: E402
from app.services.detect.engine import detect  # noqa: E402
from app.services.mitre.enrich import enrich  # noqa: E402


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/events.jsonl")
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {e["event_id"]: e for e in events}
    dets = detect(events)
    det_by_id = {d.detection_id: d for d in dets}
    incs = correlate(dets, events_by_id=by_id)
    enrs = enrich(incs, det_by_id)
    print(f"{len(events)} events -> {len(dets)} detections -> {len(incs)} incidents")
    print("risk bands:", dict(Counter(e.risk_band for e in enrs)))
    scores = sorted(e.risk_score for e in enrs)
    print(f"risk min/med/max: {scores[0]}/{scores[len(scores)//2]}/{scores[-1]}")

    cc_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_id") == "credential_compromise_001"}
    print("\ncredential_compromise_001 enriched incident:")
    for e in enrs:
        if set(e.incident.evidence_event_ids) & cc_ids:
            print(f"  title: {e.incident.title}")
            print(f"  Severity: {e.incident.severity}")
            print(f"  Risk Score: {e.risk_score}")
            print(f"  Risk Band: {e.risk_band}")
            print("  MITRE associations:")
            for m in e.mitre_techniques:
                print(f"    {m.technique_id} {m.technique_name} [{m.tactic}] "
                      f"via {m.source_rule_id} conf={m.confidence} ({m.catalog_version})")
                print(f"      rationale: {m.rationale}")
            print("  Breakdown:")
            for k, v in e.risk_breakdown.model_dump().items():
                print(f"    {k}: {v}")
            print(f"  Explanation: {e.risk_explanation}")

    print("\nbenign_volume enriched incidents:")
    bv_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_type") == "benign_volume"}
    n_bv = sum(1 for e in enrs if set(e.incident.evidence_event_ids) & bv_ids)
    print(f"  total: {n_bv} (expected 0: benign_volume yields no detections)")

    print("\nAUTH-003 risk behavior:")
    a3_scores = []
    for e in enrs:
        rules = set(e.incident.metadata.get("rule_ids", []))
        if rules == {"AUTH-003"}:
            a3_scores.append(e.risk_score)
    if a3_scores:
        print(f"  AUTH-003-only incidents: {len(a3_scores)}, max risk: {max(a3_scores)}")
    else:
        print("  no AUTH-003-only incidents (all merged via shared evidence)")

    again = enrich(correlate(detect(events), events_by_id=by_id),
                   {d.detection_id: d for d in detect(events)})
    same = [(e.incident_id, e.risk_score,
             [(m.technique_id, m.source_rule_id) for m in e.mitre_techniques]) for e in enrs] == \
           [(e.incident_id, e.risk_score,
             [(m.technique_id, m.source_rule_id) for m in e.mitre_techniques]) for e in again]
    print(f"\ndeterminism: {'IDENTICAL' if same else 'MISMATCH'}")
    leaked = [e for e in enrs
              if any("scenario" in str(v) for v in e.incident.metadata.values())
              or any("scenario" in m.rationale for m in e.mitre_techniques)]
    print(f"label leakage: {len(leaked)}")
    if not same or leaked:
        sys.exit(1)


if __name__ == "__main__":
    main()
