"""Slice 1 event API: ingest (guarded) + query (open for local dev)."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import require_ingest_key
from app.core.config import get_settings
from app.db.database import get_db
from app.db.models.security_event import SecurityEvent
from app.schemas.event import (
    EventBatchCreate,
    EventBatchItemResult,
    EventBatchResponse,
    EventCreate,
    EventListResponse,
    EventResponse,
)
from app.services.ingest import store_event

logger = logging.getLogger("esf.api")
router = APIRouter(prefix="/api/v1/events", tags=["events"])


def _to_response(row: SecurityEvent) -> EventResponse:
    data = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    # Re-attach UTC: storage is naive UTC, API speaks aware UTC.
    for key in ("timestamp", "created_at"):
        v = data.get(key)
        if isinstance(v, datetime) and v.tzinfo is None:
            data[key] = v.replace(tzinfo=timezone.utc)
    return EventResponse(**data)


@router.post(
    "",
    response_model=EventResponse,
    status_code=201,
    summary="Ingest one security event",
    dependencies=[Depends(require_ingest_key)],
)
def post_event(body: EventCreate, db: Session = Depends(get_db)) -> EventResponse:
    logger.info("request received: POST /api/v1/events")
    row, deduped = store_event(db, body.model_dump())
    # Idempotent: same event_id returns the stored row, never a second row.
    return _to_response(row)


@router.post(
    "/batch",
    response_model=EventBatchResponse,
    summary="Ingest a bounded batch of events (partial success)",
    dependencies=[Depends(require_ingest_key)],
)
def post_batch(body: EventBatchCreate, db: Session = Depends(get_db)) -> EventBatchResponse:
    """Partial success: each event commits independently via savepoint.

    One bad/duplicate row never corrupts the rest. Response reports
    accepted/duplicates/rejected per event_id so shippers can retry safely.
    """
    logger.info("request received: POST /api/v1/events/batch")
    limit = get_settings().max_batch_size
    if len(body.events) > limit:
        raise HTTPException(status_code=422, detail=f"batch limit is {limit} events")
    results: list[EventBatchItemResult] = []
    accepted = duplicates = rejected = 0
    for item in body.events:
        try:
            row, deduped = store_event(db, item.model_dump())
        except ValueError as exc:
            rejected += 1
            results.append(EventBatchItemResult(event_id=item.event_id, status="rejected", error=str(exc)))
            continue
        if deduped:
            duplicates += 1
            results.append(EventBatchItemResult(event_id=item.event_id, status="duplicate", id=row.id))
        else:
            accepted += 1
            results.append(EventBatchItemResult(event_id=item.event_id, status="created", id=row.id))
    return EventBatchResponse(accepted=accepted, duplicates=duplicates, rejected=rejected, results=results)


@router.get("", response_model=EventListResponse, summary="Query events with filters")
def list_events(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1),
    event_type: str | None = None,
    source: str | None = None,
    host: str | None = None,
    user: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> EventListResponse:
    max_page = get_settings().max_page_size
    if page_size > max_page:
        raise HTTPException(status_code=422, detail=f"page_size limit is {max_page}")
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must be <= end_time")

    def _bound(v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return v.astimezone(timezone.utc).replace(tzinfo=None) if v.tzinfo else v

    stmt = select(SecurityEvent)
    count_stmt = select(func.count()).select_from(SecurityEvent)
    filters = []
    if event_type:
        filters.append(SecurityEvent.event_type == event_type.strip().lower())
    if source:
        filters.append(SecurityEvent.source == source.strip())
    if host:
        filters.append(SecurityEvent.host == host.strip())
    if user:
        filters.append(SecurityEvent.user == user.strip())
    if source_ip:
        filters.append(SecurityEvent.source_ip == source_ip.strip())
    if destination_ip:
        filters.append(SecurityEvent.destination_ip == destination_ip.strip())
    if start_time:
        filters.append(SecurityEvent.timestamp >= _bound(start_time))
    if end_time:
        filters.append(SecurityEvent.timestamp <= _bound(end_time))
    for f in filters:
        stmt = stmt.where(f)
        count_stmt = count_stmt.where(f)

    total = db.execute(count_stmt).scalar_one()
    pages = max((total + page_size - 1) // page_size, 1)
    rows = db.execute(
        stmt.order_by(SecurityEvent.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()
    return EventListResponse(
        items=[_to_response(r) for r in rows], page=page, page_size=page_size, total=total, pages=pages
    )


@router.get("/{event_id}", response_model=EventResponse, summary="Get one event by event_id")
def get_event(event_id: str, db: Session = Depends(get_db)) -> EventResponse:
    row = db.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="event not found")
    return _to_response(row)
