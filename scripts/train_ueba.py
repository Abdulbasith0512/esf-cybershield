"""Train the UEBA IsolationForest (dev/validation only).

Split (harness-side, never a model feature): train on NORMAL-only rows from
2026-09-01..03; evaluation uses all rows from 2026-09-04 on. Writes artifact
+ manifest to models/ueba/ (git-ignored, regenerable).

Usage:
    python scripts/train_ueba.py --data data/synthetic/events.jsonl
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.services.ueba.config import UebaConfig  # noqa: E402
from app.services.ueba.features import build_observations  # noqa: E402
from app.services.ueba.model import UebaModel  # noqa: E402
from app.services.ueba.serialization import save  # noqa: E402

TRAIN_END = "2026-09-04T00:00:00+00:00"
EVAL_SPEC = "all rows with timestamp >= 2026-09-04 (held-out days 4-5)"


def load_events(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description="Train UEBA IsolationForest.")
    ap.add_argument("--data", default="data/synthetic/events.jsonl")
    ap.add_argument("--out", default="models/ueba")
    args = ap.parse_args()

    data_path = (REPO / args.data) if not Path(args.data).is_absolute() else Path(args.data)
    out_path = (REPO / args.out) if not Path(args.out).is_absolute() else Path(args.out)
    events = load_events(data_path)
    train_evts = [e for e in events
                  if e["timestamp"] < TRAIN_END
                  and e.get("raw_event", {}).get("scenario_type") == "normal"]
    config = UebaConfig()
    obs = build_observations(train_evts, config)
    model = UebaModel(config).fit(obs)
    manifest = save(model, str(data_path), len(obs), EVAL_SPEC, out_path)
    print(f"train rows: {len(obs)} from {len(train_evts)} normal events "
          f"({len(events)} total)")
    print(f"features: {len(config.feature_columns)} {list(config.feature_columns)}")
    print(f"threshold (top-{config.contamination}): {model.threshold:.4f}")
    print(f"manifest -> {manifest}")


if __name__ == "__main__":
    main()
