"""Slice 11 detection read API. GETs only; rules never rerun here."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.database import get_db
from app.db.models.detection import Detection as DetectionRow
from app.schemas.detections import DetectionListResponse, DetectionResponse, DetectionSummary

logger = logging.getLogger("esf.api")
router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _to_summary(row: DetectionRow) -> DetectionSummary:
    return DetectionSummary(
        detection_id=row.detection_id, rule_id=row.rule_id, rule_name=row.rule_name,
        severity=row.severity, confidence=row.confidence,
        first_seen=_aware(row.first_seen), last_seen=_aware(row.last_seen),
        reason=row.reason,
    )


def _to_response(row: DetectionRow) -> DetectionResponse:
    return DetectionResponse(
        detection_id=row.detection_id, rule_id=row.rule_id, rule_name=row.rule_name,
        severity=row.severity, confidence=row.confidence, reason=row.reason,
        evidence_event_ids=list(row.evidence_event_ids or []),
        first_seen=_aware(row.first_seen), last_seen=_aware(row.last_seen),
        detection_metadata=dict(row.detection_metadata or {}),
        created_at=_aware(row.created_at), updated_at=_aware(row.updated_at),
    )


@router.get("", response_model=DetectionListResponse, summary="Query persisted detections")
def list_detections(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1),
    rule_id: str | None = None,
    severity: str | None = None,
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> DetectionListResponse:
    max_page = get_settings().max_page_size
    if page_size > max_page:
        raise HTTPException(status_code=422, detail=f"page_size limit is {max_page}")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must be <= end_time")

    def _bound(v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return v.astimezone(timezone.utc).replace(tzinfo=None) if v.tzinfo else v

    stmt = select(DetectionRow)
    count_stmt = select(func.count()).select_from(DetectionRow)
    filters = []
    if rule_id:
        filters.append(DetectionRow.rule_id == rule_id.strip().upper())
    if severity:
        filters.append(DetectionRow.severity == severity.strip().upper())
    if min_confidence is not None:
        filters.append(DetectionRow.confidence >= min_confidence)
    if start_time:
        filters.append(DetectionRow.last_seen >= _bound(start_time))
    if end_time:
        filters.append(DetectionRow.last_seen <= _bound(end_time))
    for f in filters:
        stmt = stmt.where(f)
        count_stmt = count_stmt.where(f)

    total = db.execute(count_stmt).scalar_one()
    pages = max((total + page_size - 1) // page_size, 1)
    rows = db.execute(
        stmt.order_by(desc(DetectionRow.last_seen), DetectionRow.detection_id)
        .offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()
    return DetectionListResponse(
        items=[_to_summary(r) for r in rows], page=page, page_size=page_size,
        total=total, pages=pages,
    )


@router.get("/{detection_id}", response_model=DetectionResponse, summary="Get one detection by ID")
def get_detection(detection_id: str, db: Session = Depends(get_db)) -> DetectionResponse:
    row = db.execute(
        select(DetectionRow).where(DetectionRow.detection_id == detection_id)
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="detection not found")
    return _to_response(row)
