"""Scoring: observations + fitted model -> UebaAnomalyResult list."""

from app.services.ueba.baseline import assess
from app.services.ueba.config import UebaConfig
from app.services.ueba.model import UebaModel
from app.services.ueba.schemas import UebaAnomalyResult


def score_observations(observations: list[dict], model: UebaModel,
                       config: UebaConfig | None = None) -> list[UebaAnomalyResult]:
    """Deterministic scoring. Raw scores normalized with TRAIN bounds;
    flag = raw >= train threshold. Feature context echoes actual values only
    (deviations from zero), never causal claims."""
    config = config or model.config
    if not observations:
        return []
    raw = model.raw_scores(observations)
    normed = model.normalize(raw)
    statuses = assess(observations, config)
    results = []
    for obs, r, s in zip(observations, raw, normed):
        key = f"{obs['entity_key']}|{obs['window_start'].isoformat()}"
        ctx = {k: v for k, v in obs["features"].items() if v != 0}
        results.append(UebaAnomalyResult(
            entity_key=obs["entity_key"], observation_time=obs["window_start"],
            anomaly_score=s, anomaly_flag=bool(r >= model.threshold),
            model_version=config.model_version, feature_version=config.feature_version,
            metadata={"baseline_status": statuses[key]["status"],
                      "history_windows": statuses[key]["history_windows"],
                      "feature_context": ctx,
                      "event_count": obs["event_count"]}))
    results.sort(key=lambda x: (x.observation_time, x.entity_key))
    return results
