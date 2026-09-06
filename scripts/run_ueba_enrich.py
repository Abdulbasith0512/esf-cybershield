"""Run Slice 7 UEBA incident enrichment over a JSONL dataset (dev only).

Pipeline: events -> detect -> correlate -> MITRE/risk -> attach UEBA.
Prints attach statistics, risk-distribution invariance check, the
credential_compromise_001 incident with UEBA context, benign_volume note,
and determinism / leakage gates.

Usage:
    python scripts/run_ueba_enrich.py data/synthetic/events.jsonl
"""

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.services.correlate.engine import correlate  # noqa: E402
from app.services.detect.engine import detect  # noqa: E402
from app.services.mitre.enrich import enrich  # noqa: E402
from app.services.ueba.attach import attach_ueba  # noqa: E402
from app.services.ueba.config import UebaConfig  # noqa: E402
from app.services.ueba.features import build_observations  # noqa: E402
from app.services.ueba.model import UebaModel  # noqa: E402
from app.services.ueba.scoring import score_observations  # noqa: E402
from app.services.ueba.serialization import load  # noqa: E402


def main() -> None:
    path = REPO / (sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/events.jsonl")
    model_dir = REPO / (sys.argv[2] if len(sys.argv) > 2 else "models/ueba")
    events = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_id = {e["event_id"]: e for e in events}
    config = UebaConfig()
    model = load(model_dir / "model.joblib")
    assert model.config.model_version == config.model_version, "model/config version skew"

    dets = detect(events)
    det_by_id = {d.detection_id: d for d in dets}
    incs = correlate(dets, events_by_id=by_id)
    enrs = enrich(incs, det_by_id)
    before = [(e.risk_score, e.risk_band, e.risk_breakdown.total) for e in enrs]
    wrapped = attach_ueba(enrs, by_id, model, config)
    after = [(w.enriched.risk_score, w.enriched.risk_band, w.enriched.risk_breakdown.total)
             for w in wrapped]
    print(f"{len(events)} events -> {len(dets)} detections -> {len(incs)} incidents")
    print(f"risk unchanged by UEBA: {before == after}")
    states = Counter((w.ueba.available, w.ueba.anomaly_flag) for w in wrapped)
    print(f"UEBA available+flagged: {states.get((True, True), 0)}, "
          f"available+clean: {states.get((True, False), 0)}, "
          f"unavailable: {states.get((False, None), 0)}")
    scores = sorted(w.ueba.anomaly_score for w in wrapped if w.ueba.anomaly_score is not None)
    if scores:
        print(f"anomaly-score min/med/max: {scores[0]:.3f}/{scores[len(scores)//2]:.3f}/{scores[-1]:.3f}")

    cc_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_id") == "credential_compromise_001"}
    print("\ncredential_compromise_001 with UEBA:")
    for w in wrapped:
        if set(w.enriched.incident.evidence_event_ids) & cc_ids:
            u = w.ueba
            print(f"  incident: {w.incident_id}")
            print(f"  severity={w.enriched.incident.severity} risk={w.enriched.risk_score} "
                  f"band={w.enriched.risk_band}")
            print(f"  UEBA available={u.available} score={u.anomaly_score} flag={u.anomaly_flag}")
            print(f"  model={u.model_version} window={u.feature_window_start} -> {u.feature_window_end}")
            for o in u.observations:
                print(f"    - {o.entity_key} {o.observation_time} score={o.anomaly_score} "
                      f"flag={o.anomaly_flag} baseline={o.baseline_status}")
                print(f"      context={o.feature_context}")
            print(f"  detections={sorted(w.enriched.incident.metadata.get('rule_ids', []))} "
                  f"events={len(w.enriched.incident.evidence_event_ids)}")

    bv_ids = {e["event_id"] for e in events
              if e.get("raw_event", {}).get("scenario_type") == "benign_volume"}
    print(f"\nbenign_volume incidents: "
          f"{sum(1 for w in wrapped if set(w.enriched.incident.evidence_event_ids) & bv_ids)}")

    again = attach_ueba(enrich(correlate(detect(events), events_by_id=by_id),
                               {d.detection_id: d for d in detect(events)}),
                        by_id, model, config)
    same = [w.ueba.model_dump() for w in wrapped] == [w.ueba.model_dump() for w in again]
    print(f"\ndeterminism: {'IDENTICAL' if same else 'MISMATCH'}")
    leaked = [w for w in wrapped
              if any("scenario" in str(v) for v in w.enriched.incident.metadata.values())]
    print(f"label leakage: {len(leaked)}")
    if before != after or not same or leaked:
        sys.exit(1)


if __name__ == "__main__":
    main()
