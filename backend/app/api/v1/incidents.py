"""Slice 9 incident read API. GETs only; persistence happens offline."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.database import get_db
from app.db.models.incident import Incident as IncidentRow
from app.schemas.incidents import IncidentListResponse, IncidentResponse, IncidentSummary

logger = logging.getLogger("esf.api")
router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_DT_KEYS = ("first_seen", "last_seen", "created_at", "updated_at")


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _to_summary(row: IncidentRow) -> IncidentSummary:
    ueba = row.ueba_evidence or {}
    return IncidentSummary(
        incident_id=row.incident_id, title=row.title, severity=row.severity,
        status=row.status, confidence=row.confidence, risk_score=row.risk_score,
        risk_band=row.risk_band,
        ueba_available=bool(ueba.get("available", False)),
        ueba_anomaly_score=ueba.get("anomaly_score"),
        ueba_anomaly_flag=ueba.get("anomaly_flag"),
        first_seen=_aware(row.first_seen), last_seen=_aware(row.last_seen),
    )


def _to_response(row: IncidentRow) -> IncidentResponse:
    ueba = row.ueba_evidence or {}
    # Nested ISO strings (observation datetimes) parse via Pydantic automatically.
    return IncidentResponse(
        incident_id=row.incident_id, title=row.title, severity=row.severity,
        status=row.status, confidence=row.confidence, reason=row.reason,
        risk_score=row.risk_score, risk_band=row.risk_band,
        risk_explanation=row.risk_explanation,
        first_seen=_aware(row.first_seen), last_seen=_aware(row.last_seen),
        detection_ids=list(row.detection_ids or []),
        evidence_event_ids=list(row.evidence_event_ids or []),
        incident_metadata=dict(row.incident_metadata or {}),
        mitre_techniques=list(row.mitre_techniques or []),
        risk_breakdown=row.risk_breakdown or None,
        ueba_evidence=row.ueba_evidence or None,
        created_at=_aware(row.created_at), updated_at=_aware(row.updated_at),
    )


@router.get("", response_model=IncidentListResponse, summary="Query persisted incidents")
def list_incidents(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1),
    severity: str | None = None,
    status: str | None = None,
    risk_band: str | None = None,
    min_risk_score: int | None = Query(default=None, ge=0, le=100),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> IncidentListResponse:
    max_page = get_settings().max_page_size
    if page_size > max_page:
        raise HTTPException(status_code=422, detail=f"page_size limit is {max_page}")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must be <= end_time")

    def _bound(v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return v.astimezone(timezone.utc).replace(tzinfo=None) if v.tzinfo else v

    stmt = select(IncidentRow)
    count_stmt = select(func.count()).select_from(IncidentRow)
    filters = []
    if severity:
        filters.append(IncidentRow.severity == severity.strip().upper())
    if status:
        filters.append(IncidentRow.status == status.strip().upper())
    if risk_band:
        filters.append(IncidentRow.risk_band == risk_band.strip().upper())
    if min_risk_score is not None:
        filters.append(IncidentRow.risk_score >= min_risk_score)
    if start_time:
        filters.append(IncidentRow.last_seen >= _bound(start_time))
    if end_time:
        filters.append(IncidentRow.last_seen <= _bound(end_time))
    for f in filters:
        stmt = stmt.where(f)
        count_stmt = count_stmt.where(f)

    total = db.execute(count_stmt).scalar_one()
    pages = max((total + page_size - 1) // page_size, 1)
    rows = db.execute(
        stmt.order_by(desc(IncidentRow.last_seen), IncidentRow.incident_id)
        .offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()
    return IncidentListResponse(
        items=[_to_summary(r) for r in rows], page=page, page_size=page_size,
        total=total, pages=pages,
    )


@router.get("/{incident_id}", response_model=IncidentResponse, summary="Get one incident by ID")
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> IncidentResponse:
    row = db.execute(
        select(IncidentRow).where(IncidentRow.incident_id == incident_id)
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return _to_response(row)
