"""Evaluate the trained UEBA model (dev/validation only).

Transform-only: scaler/threshold come from training. Scenario labels are used
solely for post-hoc reporting, never as inputs.

Usage:
    python scripts/evaluate_ueba.py --data data/synthetic/events.jsonl --model models/ueba
"""

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.services.ueba.config import UebaConfig  # noqa: E402
from app.services.ueba.features import build_observations  # noqa: E402
from app.services.ueba.serialization import load  # noqa: E402
from app.services.ueba.scoring import score_observations  # noqa: E402

TRAIN_END = "2026-09-04T00:00:00+00:00"


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate UEBA model on held-out days.")
    ap.add_argument("--data", default="data/synthetic/events.jsonl")
    ap.add_argument("--model", default="models/ueba")
    args = ap.parse_args()

    def _resolve(p: str) -> Path:
        q = Path(p)
        return q if q.is_absolute() else REPO / q

    t0 = time.perf_counter()
    events = [json.loads(l) for l in _resolve(args.data).read_text(encoding="utf-8").splitlines()
              if l.strip()]
    by_id = {e["event_id"]: e for e in events}
    eval_evts = [e for e in events if e["timestamp"] >= TRAIN_END]
    t1 = time.perf_counter()
    config = UebaConfig()
    obs = build_observations(eval_evts, config)
    t2 = time.perf_counter()
    model = load(_resolve(args.model) / "model.joblib")
    results = score_observations(obs, model, config)
    t3 = time.perf_counter()

    scores = [r.anomaly_score for r in results]
    flags = sum(1 for r in results if r.anomaly_flag)
    print(f"eval rows: {len(results)} from {len(eval_evts)} events")
    print(f"anomaly rate: {flags}/{len(results)} ({flags/len(results):.1%})")
    print(f"score min/max/mean/median: {min(scores):.3f}/{max(scores):.3f}/"
          f"{sum(scores)/len(scores):.3f}/{sorted(scores)[len(scores)//2]:.3f}")

    obs_by_key = {(o["entity_key"], o["window_start"]): o for o in obs}
    per_type: dict[str, dict] = {}
    for r in results:
        o = obs_by_key[(r.entity_key, r.observation_time)]
        types = Counter(by_id[e].get("raw_event", {}).get("scenario_type", "?")
                        for e in o["event_ids"])
        dom, _ = types.most_common(1)[0]
        bucket = per_type.setdefault(dom, {"scores": [], "flags": 0})
        bucket["scores"].append(r.anomaly_score)
        bucket["flags"] += r.anomaly_flag
    print("per-scenario (dominant type per window) mean score / rows / flag rate:")
    for st, b in sorted(per_type.items()):
        print(f"  {st}: mean={sum(b['scores'])/len(b['scores']):.3f} "
              f"rows={len(b['scores'])} flagged={b['flags']}")

    print(f"timings: load={t1-t0:.2f}s features={t2-t1:.2f}s "
          f"load-model+score={t3-t2:.2f}s")
    print(f"model={model.config.model_version} features={model.config.feature_version}")


if __name__ == "__main__":
    main()
