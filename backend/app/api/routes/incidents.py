"""Incident read endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models.incident import Incident, IncidentEvent
from app.db.models.normalized_event import NormalizedEvent
from app.db.models.signals import Detection

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("", summary="List incidents")
def list_incidents(status: str | None = None, limit: int = 50, db: Session = Depends(get_db)) -> dict:
    limit = max(1, min(limit, 200))
    stmt = select(Incident).order_by(desc(Incident.last_seen)).limit(limit)
    if status:
        stmt = stmt.where(Incident.status == status)
    rows = db.execute(stmt).scalars().all()
    return {"count": len(rows), "incidents": [_summary(r) for r in rows]}


@router.get("/{incident_id}", summary="Incident detail with events + detections")
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="incident not found")
    norm_ids = db.execute(
        select(IncidentEvent.normalized_event_id).where(IncidentEvent.incident_id == incident_id)
    ).scalars().all()
    events = db.execute(select(NormalizedEvent).where(NormalizedEvent.id.in_(norm_ids))).scalars().all() if norm_ids else []
    dets = db.execute(select(Detection).where(Detection.normalized_event_id.in_(norm_ids))).scalars().all() if norm_ids else []
    return {
        "incident": _summary(inc),
        "events": [{"id": e.id, "ts": e.ts, "user_id": e.user_id, "host": e.host,
                    "src_ip": e.src_ip, "action": e.action, "status": e.status,
                    "event_type": e.event_type} for e in events],
        "detections": [{"rule_id": d.rule_id, "rule_name": d.rule_name, "severity": d.severity,
                        "mitre_technique": d.mitre_technique, "detail": d.detail} for d in dets],
    }


def _summary(r: Incident) -> dict:
    return {"id": r.id, "title": r.title, "status": r.status, "severity": r.severity,
            "risk_score": r.risk_score, "mitre_techniques": r.mitre_techniques,
            "principal": r.principal, "first_seen": r.first_seen, "last_seen": r.last_seen,
            "event_count": r.event_count}
