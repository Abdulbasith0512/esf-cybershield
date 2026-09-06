"""UEBA behavioral anomaly layer. Complements deterministic rules; replaces nothing.

Pipeline: events -> features (user, 1h) -> baseline status -> IsolationForest
-> UebaAnomalyResult. Independent signal; incident integration comes later.
"""

from app.services.ueba.scoring import score_observations

__all__ = ["score_observations"]
