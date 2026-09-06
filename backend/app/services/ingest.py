"""Store-only ingestion. Validate -> normalize -> store. No detection."""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.security_event import SecurityEvent
from app.services.normalize import normalize_event

logger = logging.getLogger("esf.ingest")


def _naive_utc(dt: datetime) -> datetime:
    # Storage convention: naive UTC (SQLite returns naive; PG TIMESTAMPTZ
    # treats naive as UTC). API layer always speaks aware UTC.
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def store_event(db: Session, validated: dict[str, Any]) -> tuple[SecurityEvent, bool]:
    """Insert one normalized event.

    Returns (row, deduped). Idempotent: existing event_id returns the stored
    row with deduped=True instead of raising. Race-safe via UNIQUE catch.
    """
    fields = normalize_event(validated)
    event_id = fields["event_id"]

    existing = db.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    ).scalars().first()
    if existing is not None:
        logger.info("duplicate event", extra={"event_id": event_id})
        return existing, True

    row = SecurityEvent(
        event_id=event_id,
        timestamp=_naive_utc(fields["timestamp"]),
        event_type=fields["event_type"],
        source=fields["source"],
        host=fields.get("host"),
        user=fields.get("user"),
        source_ip=fields.get("source_ip"),
        destination_ip=fields.get("destination_ip"),
        destination_port=fields.get("destination_port"),
        protocol=fields.get("protocol"),
        process_name=fields.get("process_name"),
        parent_process=fields.get("parent_process"),
        command_line=fields.get("command_line"),
        file_hash=fields.get("file_hash"),
        domain=fields.get("domain"),
        url=fields.get("url"),
        bytes_sent=fields.get("bytes_sent"),
        bytes_received=fields.get("bytes_received"),
        status=fields.get("status"),
        raw_event=fields["raw_event"],
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        # Lost a race with a concurrent insert of the same event_id.
        db.rollback()
        existing = db.execute(
            select(SecurityEvent).where(SecurityEvent.event_id == event_id)
        ).scalars().first()
        if existing is None:
            raise
        logger.info("duplicate event", extra={"event_id": event_id})
        return existing, True
    db.refresh(row)
    logger.info("event accepted", extra={"event_id": event_id})
    return row, False
