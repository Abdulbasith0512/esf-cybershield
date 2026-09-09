"""Slice 9 incident read API. GETs only; persistence happens offline."""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.database import get_db
from app.db.models.detection import Detection as DetectionRow
from app.db.models.incident import Incident as IncidentRow
from app.db.models.security_event import SecurityEvent as SecurityEventRow
from app.schemas.incidents import (
    CaseUpdate,
    IncidentActivityResponse,
    IncidentListResponse,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentSummary,
    InvestigationResponse,
    NoteCreate,
)
from app.services.investigate import EVIDENCE_SAMPLE_LIMIT, build_investigation
from app.services.persist import cases as case_store

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
        assignee=row.assignee,
        assigned_at=_aware(row.assigned_at) if row.assigned_at else None,
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


@router.get("/{incident_id}/investigation", response_model=InvestigationResponse,
            summary="Get the SOC investigation view for one incident")
def get_investigation(incident_id: str, db: Session = Depends(get_db)) -> InvestigationResponse:
    incident = db.execute(
        select(IncidentRow).where(IncidentRow.incident_id == incident_id)
    ).scalars().first()
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    det_ids = list(incident.detection_ids or [])
    det_rows = db.execute(
        select(DetectionRow).where(DetectionRow.detection_id.in_(det_ids))
    ).scalars().all() if det_ids else []
    sample_ids = sorted(set(incident.evidence_event_ids or []))[:EVIDENCE_SAMPLE_LIMIT]
    ev_rows = db.execute(
        select(SecurityEventRow).where(SecurityEventRow.event_id.in_(sample_ids))
    ).scalars().all() if sample_ids else []
    investigation = build_investigation(incident, list(det_rows), list(ev_rows),
                                        expected_detection_ids=det_ids)
    from app.services.case import allowed_transitions

    notes = case_store.list_notes(db, incident_id)
    activity = case_store.list_activity(db, incident_id)
    investigation["case"] = {
        "status": incident.status,
        "assignee": incident.assignee,
        "assigned_at": _aware(incident.assigned_at) if incident.assigned_at else None,
        "allowed_transitions": allowed_transitions(incident.status),
        "notes": [{"note_id": n.note_id, "author": n.author, "body": n.body,
                   "created_at": _aware(n.created_at)} for n in notes],
        "activity": [{"activity_id": a.activity_id, "action": a.action, "actor": a.actor,
                      "created_at": _aware(a.created_at),
                      "metadata": dict(a.activity_metadata or {})} for a in activity],
    }
    return investigation


def _to_note(row) -> IncidentNoteResponse:
    return IncidentNoteResponse(
        note_id=row.note_id, incident_id=row.incident_id, author=row.author,
        body=row.body, created_at=_aware(row.created_at),
    )


def _to_activity(row) -> IncidentActivityResponse:
    return IncidentActivityResponse(
        activity_id=row.activity_id, incident_id=row.incident_id, action=row.action,
        actor=row.actor, created_at=_aware(row.created_at),
        metadata=dict(row.activity_metadata or {}),
    )


@router.patch("/{incident_id}", response_model=IncidentResponse,
              summary="Update incident case fields (status, assignee)")
def update_case(incident_id: str, body: CaseUpdate,
                db: Session = Depends(get_db)) -> IncidentResponse:
    try:
        kwargs: dict = {"actor": body.actor}
        if body.has_status:
            kwargs["status"] = body.status
        if body.has_assignee:
            kwargs["assignee"] = body.assignee
        row = case_store.update_case(db, incident_id, **kwargs)
    except LookupError:
        raise HTTPException(status_code=404, detail="incident not found")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _to_response(row)


@router.get("/{incident_id}/notes", response_model=list[IncidentNoteResponse],
            summary="List incident analyst notes in deterministic order")
def list_notes(incident_id: str, db: Session = Depends(get_db)) -> list[IncidentNoteResponse]:
    if case_store.get_incident(db, incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return [_to_note(row) for row in case_store.list_notes(db, incident_id)]


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=201,
             summary="Append an analyst note to an incident")
def create_note(incident_id: str, body: NoteCreate,
                db: Session = Depends(get_db)) -> IncidentNoteResponse:
    try:
        row = case_store.add_note(db, incident_id, body=body.body, author=body.author)
    except LookupError:
        raise HTTPException(status_code=404, detail="incident not found")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _to_note(row)


@router.get("/{incident_id}/activity", response_model=list[IncidentActivityResponse],
            summary="List incident activity history in deterministic order")
def list_activity(incident_id: str, db: Session = Depends(get_db)) -> list[IncidentActivityResponse]:
    if case_store.get_incident(db, incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return [_to_activity(row) for row in case_store.list_activity(db, incident_id)]
