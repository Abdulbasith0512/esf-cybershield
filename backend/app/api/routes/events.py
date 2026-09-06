"""Event ingest + list endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models.normalized_event import NormalizedEvent
from app.schemas.event import EventIngest, EventIngestResponse
from app.services.pipeline import ingest_single

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", response_model=EventIngestResponse, status_code=201, summary="Ingest one event")
def post_event(body: EventIngest, db: Session = Depends(get_db)) -> EventIngestResponse:
    payload = body.model_dump(mode="json")
    # Merge free-form `raw` extras into top level for normalizer.
    if body.raw:
        for k, v in body.raw.items():
            payload.setdefault(k, v)
    try:
        result = ingest_single(db, payload, source=body.source, event_type=body.event_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return EventIngestResponse(
        raw_id=result["raw_id"], normalized_id=result["normalized_id"],
        event_id=result["event_id"], deduped=result["deduped"],
        incident_id=result.get("incident_id"),
    )


@router.post("/bulk", summary="Ingest up to 1000 events")
def post_bulk(bodies: list[EventIngest], db: Session = Depends(get_db)) -> dict:
    if len(bodies) > 1000:
        raise HTTPException(status_code=422, detail="bulk limit is 1000 events")
    results = []
    incidents = set()
    for body in bodies:
        payload = body.model_dump(mode="json")
        if body.raw:
            for k, v in body.raw.items():
                payload.setdefault(k, v)
        try:
            r = ingest_single(db, payload, source=body.source, event_type=body.event_type)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        results.append(r)
        if r.get("incident_id"):
            incidents.add(r["incident_id"])
    return {"ingested": len(results), "incidents": sorted(incidents), "results": results}


@router.get("", summary="List normalized events")
def list_events(
    limit: int = 50, user_id: str | None = None, event_type: str | None = None,
    db: Session = Depends(get_db),
) -> dict:
    limit = max(1, min(limit, 500))
    stmt = select(NormalizedEvent).order_by(desc(NormalizedEvent.ts)).limit(limit)
    if user_id:
        stmt = stmt.where(NormalizedEvent.user_id == user_id.lower())
    if event_type:
        stmt = stmt.where(NormalizedEvent.event_type == event_type.lower())
    rows = db.execute(stmt).scalars().all()
    return {
        "count": len(rows),
        "events": [
            {"id": r.id, "ts": r.ts, "user_id": r.user_id, "host": r.host,
             "src_ip": r.src_ip, "dst_ip": r.dst_ip, "event_type": r.event_type,
             "action": r.action, "status": r.status}
            for r in rows
        ],
    }
