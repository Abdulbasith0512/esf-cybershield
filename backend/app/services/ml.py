"""ML anomaly scoring. IsolationForest when artifact exists, heuristic fallback."""

from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.normalized_event import NormalizedEvent
from app.db.models.signals import MlScore

MODEL_VERSION = "iforest-v1"
THRESHOLD = 0.7
ARTIFACT = Path(__file__).resolve().parents[2] / "ml" / "artifacts" / "model.pkl"

_model = None


def _load_model():
    global _model
    if _model is not None:
        return _model
    if not ARTIFACT.exists():
        return None
    try:
        import joblib

        _model = joblib.load(ARTIFACT)
        return _model
    except Exception:
        return None


def extract_features(db: Session, event: NormalizedEvent) -> dict:
    hour = event.ts.hour
    since_1h = event.ts - timedelta(hours=1)
    since_24h = event.ts - timedelta(hours=24)
    fail_1h = db.execute(
        select(func.count()).select_from(NormalizedEvent).where(
            NormalizedEvent.user_id == event.user_id,
            NormalizedEvent.status == "failure",
            NormalizedEvent.ts >= since_1h, NormalizedEvent.ts <= event.ts,
        )
    ).scalar_one() if event.user_id != "unknown" else 0
    hosts_24h = db.execute(
        select(func.count(func.distinct(NormalizedEvent.host))).where(
            NormalizedEvent.user_id == event.user_id,
            NormalizedEvent.ts >= since_24h, NormalizedEvent.ts <= event.ts,
        )
    ).scalar_one() if event.user_id != "unknown" else 0
    targets_1h = 0
    if event.src_ip:
        rows = db.execute(
            select(NormalizedEvent.dst_ip, NormalizedEvent.dst_port).where(
                NormalizedEvent.src_ip == event.src_ip,
                NormalizedEvent.ts >= since_1h, NormalizedEvent.ts <= event.ts,
            )
        ).all()
        targets_1h = len({(r[0], r[1]) for r in rows})
    return {
        "hour": float(hour),
        "fail_count_1h": float(fail_1h or 0),
        "distinct_hosts_24h": float(hosts_24h or 0),
        "target_count_1h": float(targets_1h),
    }


def score_ml(db: Session, event: NormalizedEvent) -> MlScore:
    features = extract_features(db, event)
    model = _load_model()
    if model is not None:
        try:
            import numpy as np

            vec = np.array([[features["hour"], features["fail_count_1h"],
                             features["distinct_hosts_24h"], features["target_count_1h"]]])
            raw = float(-model.decision_function(vec)[0])  # higher = more anomalous
            # Sigmoid-ish squash to 0..1
            score = round(float(1 / (1 + pow(2.71828, -raw * 2))), 3)
        except Exception:
            score = _heuristic(features, event)
    else:
        score = _heuristic(features, event)
    row = MlScore(
        normalized_event_id=event.id, model_version=MODEL_VERSION,
        score=score, threshold=THRESHOLD, is_anomaly=score >= THRESHOLD,
        features=features,
    )
    db.add(row)
    return row


def _heuristic(features: dict, event: NormalizedEvent) -> float:
    s = 0.0
    if features["fail_count_1h"] >= 5:
        s += 0.55
    elif features["fail_count_1h"] >= 3:
        s += 0.3
    if features["target_count_1h"] >= 10:
        s += 0.5
    if features["distinct_hosts_24h"] >= 4:
        s += 0.25
    if event.status == "failure" and features["fail_count_1h"] >= 2:
        s += 0.1
    return round(min(s, 0.95), 3)
