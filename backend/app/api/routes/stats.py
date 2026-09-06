"""Dashboard summary stats, all derived from PostgreSQL."""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models.incident import Incident
from app.db.models.normalized_event import NormalizedEvent
from app.db.models.signals import Detection

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


@router.get("/summary", summary="Dashboard summary")
def summary(db: Session = Depends(get_db)) -> dict:
    since = datetime.utcnow() - timedelta(hours=24)
    events_24h = db.execute(
        select(func.count()).select_from(NormalizedEvent).where(NormalizedEvent.ts >= since)
    ).scalar_one()
    detections_24h = db.execute(
        select(func.count()).select_from(Detection).where(Detection.created_at >= since)
    ).scalar_one()
    open_incidents = db.execute(
        select(func.count()).select_from(Incident).where(Incident.status == "open")
    ).scalar_one()
    top_rules = db.execute(
        select(Detection.rule_id, func.count().label("n"))
        .group_by(Detection.rule_id).order_by(func.count().desc()).limit(5)
    ).all()
    top_techniques = db.execute(
        select(Detection.mitre_technique, func.count().label("n"))
        .where(Detection.mitre_technique.is_not(None))
        .group_by(Detection.mitre_technique).order_by(func.count().desc()).limit(8)
    ).all()
    return {
        "events_24h": events_24h, "detections_24h": detections_24h,
        "incidents_open": open_incidents,
        "top_rules": [{"rule_id": r[0], "count": r[1]} for r in top_rules],
        "top_techniques": [{"technique": r[0], "count": r[1]} for r in top_techniques],
    }
