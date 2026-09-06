"""IsolationForest wrapper. sklearn imported lazily; versions pinned in config."""

import numpy as np

from app.services.ueba.config import UebaConfig


def _sklearn():
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    return IsolationForest, StandardScaler


class UebaModel:
    """Fitted scaler + IsolationForest + train-score normalization bounds.

    score_samples is negated and min-max normalized using TRAIN extremes, so
    0.0 = least anomalous, 1.0 = most anomalous, consistently across runs.
    """

    def __init__(self, config: UebaConfig | None = None):
        self.config = config or UebaConfig()
        self.scaler = None
        self.forest = None
        self.train_min = 0.0
        self.train_max = 1.0
        self.threshold = 0.5

    def _matrix(self, observations: list[dict]):
        cols = list(self.config.feature_columns)
        return np.array([[float(o["features"][c]) for c in cols] for o in observations],
                        dtype=float), cols

    def fit(self, observations: list[dict]) -> "UebaModel":
        IsolationForest, StandardScaler = _sklearn()
        X, _ = self._matrix(observations)
        self.scaler = StandardScaler().fit(X)
        self.forest = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            random_state=self.config.random_state)
        self.forest.fit(self.scaler.transform(X))
        raw = -self.forest.score_samples(self.scaler.transform(X))
        self.train_min, self.train_max = float(raw.min()), float(raw.max())
        if self.train_max <= self.train_min:
            self.train_max = self.train_min + 1e-9
        # Operational threshold: top-contamination share of train scores.
        import numpy as _np

        self.threshold = float(_np.quantile(raw, 1.0 - self.config.contamination))
        return self

    def raw_scores(self, observations: list[dict]):
        X, _ = self._matrix(observations)
        return -self.forest.score_samples(self.scaler.transform(X))

    def normalize(self, raw) -> list[float]:
        span = self.train_max - self.train_min
        return [round(max(0.0, min(1.0, (float(r) - self.train_min) / span)), 4)
                for r in raw]

    def state_dict(self) -> dict:
        return {"config": self.config, "scaler": self.scaler, "forest": self.forest,
                "train_min": self.train_min, "train_max": self.train_max,
                "threshold": self.threshold}
