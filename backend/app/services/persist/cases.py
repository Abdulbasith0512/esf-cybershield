"""Case-management persistence. Metadata only; detection/evidence untouched.

Each mutation commits independently and appends exactly one activity row.
Same incident_id twice for notes/activity never duplicates (unique IDs).
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.case import IncidentActivity, IncidentNote
from app.db.models.incident import Incident as IncidentRow
from app.services import case as case_domain

logger = logging.getLogger("esf.persist")


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


def _log_activity(db: Session, *, incident_id: str, action: str,
                  actor: str | None, metadata: dict[str, Any] | None = None) -> None:
    db.add(IncidentActivity(
        activity_id=case_domain.new_activity_id(),
        incident_id=incident_id,
        action=action,
        actor=actor,
        metadata=dict(metadata or {}),
    ))


def get_incident(db: Session, incident_id: str) -> IncidentRow | None:
    return db.execute(
        select(IncidentRow).where(IncidentRow.incident_id == incident_id)
    ).scalars().first()


_UNSET: Any = object()


def update_case(db: Session, incident_id: str, *,
                status: Any = _UNSET, assignee: Any = _UNSET,
                actor: Any = None) -> IncidentRow:
    """Apply status/assignment changes with transition validation.

    Raises LookupError for unknown incidents, ValueError for invalid input.
    Appends one activity row per changed field. Commits once.
    """
    row = get_incident(db, incident_id)
    if row is None:
        raise LookupError(f"incident not found: {incident_id}")
    actor_id = case_domain.normalize_identifier(actor, "actor") if actor is not None else None
    if status is not _UNSET:
        target = case_domain.validate_transition(row.status, status)
        if target != row.status:
            previous = row.status
            row.status = target
            row.updated_at = _utcnow_naive()
            _log_activity(db, incident_id=incident_id, action="STATUS_CHANGED",
                          actor=actor_id,
                          metadata={"from_status": previous, "to_status": target})
    if assignee is not _UNSET:
        assignee_id = case_domain.normalize_identifier(assignee, "assignee")
        if assignee_id != row.assignee:
            row.assignee = assignee_id
            row.assigned_at = _utcnow_naive() if assignee_id else None
            row.updated_at = _utcnow_naive()
            if assignee_id is None:
                _log_activity(db, incident_id=incident_id, action="UNASSIGNED", actor=actor_id)
            else:
                _log_activity(db, incident_id=incident_id, action="ASSIGNED", actor=actor_id,
                              metadata={"assignee": assignee_id})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise
    logger.info("case updated: %s", incident_id)
    return row


def add_note(db: Session, incident_id: str, *, body: object,
             author: object = None) -> IncidentNote:
    """Append one note plus its activity row. Raises LookupError/ValueError."""
    row = get_incident(db, incident_id)
    if row is None:
        raise LookupError(f"incident not found: {incident_id}")
    text = case_domain.normalize_note_body(body)
    author_id = case_domain.normalize_identifier(author, "author") if author is not None else None
    note = IncidentNote(
        note_id=case_domain.new_note_id(),
        incident_id=incident_id,
        author=author_id,
        body=text,
    )
    db.add(note)
    _log_activity(db, incident_id=incident_id, action="NOTE_ADDED", actor=author_id,
                  metadata={"note_id": note.note_id})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise
    return note


def list_notes(db: Session, incident_id: str) -> list[IncidentNote]:
    rows = db.execute(
        select(IncidentNote).where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at, IncidentNote.note_id)
    ).scalars().all()
    return list(rows)


def list_activity(db: Session, incident_id: str) -> list[IncidentActivity]:
    rows = db.execute(
        select(IncidentActivity).where(IncidentActivity.incident_id == incident_id)
        .order_by(IncidentActivity.created_at, IncidentActivity.activity_id)
    ).scalars().all()
    return list(rows)
