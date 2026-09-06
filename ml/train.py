"""Train IsolationForest on synthetic benign + attack features.

Usage:
  .\\.venv\\Scripts\\python.exe ..\\ml\\train.py
Artifact: ml/artifacts/model.pkl (+ meta.json)
"""

import json
from pathlib import Path

import numpy as np

OUT = Path(__file__).resolve().parent / "artifacts"
OUT.mkdir(parents=True, exist_ok=True)


def main():
    from sklearn.ensemble import IsolationForest
    import joblib

    rng = np.random.default_rng(42)
    benign = np.column_stack([
        rng.integers(7, 19, 800),          # hour: work hours
        rng.poisson(0.3, 800),             # fail_count_1h
        rng.integers(1, 3, 800),           # hosts_24h
        rng.poisson(1.0, 800),             # targets_1h
    ]).astype(float)
    attack = np.array([
        [3, 6, 1, 1], [2, 8, 2, 1], [14, 0, 1, 12], [15, 0, 2, 14],
        [4, 5, 3, 2], [1, 7, 1, 1], [13, 0, 5, 3], [16, 4, 4, 11],
    ] * 12, dtype=float)

    X = np.vstack([benign, attack])
    model = IsolationForest(n_estimators=200, contamination=0.12, random_state=42)
    model.fit(X)
    joblib.dump(model, OUT / "model.pkl")
    (OUT / "meta.json").write_text(json.dumps(
        {"model_version": "iforest-v1", "features": ["hour", "fail_count_1h", "distinct_hosts_24h", "target_count_1h"],
         "n_train": len(X), "contamination": 0.12}, indent=2))
    print(f"trained on {len(X)} rows -> {OUT / 'model.pkl'}")


if __name__ == "__main__":
    main()
