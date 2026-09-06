"""UEBA-lite: per-user baselines over last 30d, no ML library required."""

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.normalized_event import NormalizedEvent
from app.db.models.signals import UebaScore

BASELINE_REF = "30d-user"
BASELINE_DAYS = 30
MIN_HISTORY = 5


def score_ueba(db: Session, event: NormalizedEvent) -> UebaScore:
    since = event.ts - timedelta(days=BASELINE_DAYS)
    history = db.execute(
        select(NormalizedEvent).where(
            NormalizedEvent.user_id == event.user_id,
            NormalizedEvent.ts >= since,
            NormalizedEvent.ts < event.ts,
        ).order_by(NormalizedEvent.ts.desc()).limit(1000)
    ).scalars().all()

    score = 0.0
    reasons: list[str] = []
    features: dict = {"history_count": len(history)}

    if event.user_id in ("unknown", ""):
        ueba = UebaScore(
            normalized_event_id=event.id, user_id=event.user_id,
            baseline_ref=BASELINE_REF, score=0.0,
            features=features, reasons=["unknown-user-no-baseline"],
        )
        db.add(ueba)
        return ueba

    if len(history) < MIN_HISTORY:
        ueba = UebaScore(
            normalized_event_id=event.id, user_id=event.user_id,
            baseline_ref=BASELINE_REF, score=0.15,
            features=features, reasons=["insufficient-history"],
        )
        db.add(ueba)
        return ueba

    # 1. Unusual login hour: bucket share < 5% -> +0.5
    hour = event.ts.hour
    hour_counts = [0] * 24
    for h in history:
        hour_counts[h.ts.hour] += 1
    share = hour_counts[hour] / max(len(history), 1)
    features["hour"] = hour
    features["hour_share"] = round(share, 3)
    if share < 0.05:
        score += 0.5
        reasons.append(f"unusual-hour-{hour:02d} (share {share:.1%})")

    # 2. First-seen host -> +0.3
    hosts = {h.host for h in history}
    features["known_hosts"] = len(hosts)
    if event.host not in hosts:
        score += 0.3
        reasons.append(f"first-seen-host:{event.host}")

    # 3. First-seen src_ip -> +0.2
    ips = {h.src_ip for h in history if h.src_ip}
    if event.src_ip and event.src_ip not in ips:
        score += 0.2
        reasons.append(f"first-seen-ip:{event.src_ip}")

    # 4. Fail burst vs baseline fail ratio -> +0.25
    fails = sum(1 for h in history if h.status == "failure")
    fail_ratio = fails / len(history)
    features["baseline_fail_ratio"] = round(fail_ratio, 3)
    if event.status == "failure" and fail_ratio < 0.2:
        score += 0.25
        reasons.append("unexpected-failure-for-user")

    score = min(round(score, 3), 1.0)
    ueba = UebaScore(
        normalized_event_id=event.id, user_id=event.user_id,
        baseline_ref=BASELINE_REF, score=score,
        features=features, reasons=reasons,
    )
    db.add(ueba)
    return ueba
