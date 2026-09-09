"""Idempotent detection persistence. Mirror of generated content, nothing more.

Semantics: same detection_id twice -> exactly one row (full overwrite of
derived fields, detection_id and created_at preserved). Uses
select-then-insert + IntegrityError catch (SQLite-safe; no PG-only
ON CONFLICT). Timestamps stored naive UTC, matching the events table.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.detection import Detection as DetectionRow
from app.services.detect.models import DetectionResult

logger = logging.getLogger("esf.persist")


def _naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


def _payload(det: DetectionResult) -> dict[str, Any]:
    return {
        "detection_id": det.detection_id,
        "rule_id": det.rule_id,
        "rule_name": det.rule_name,
        "severity": det.severity,
        "confidence": det.confidence,
        "reason": det.reason,
        "evidence_event_ids": sorted(set(det.evidence_event_ids)),
        "bucket_event_ids": sorted(set(det.bucket_event_ids)),
        "detection_metadata": dict(det.metadata or {}),
        "first_seen": _naive_utc(det.first_seen),
        "last_seen": _naive_utc(det.last_seen),
    }


def _apply(existing: DetectionRow, fields: dict[str, Any]) -> None:
    for key, value in fields.items():
        if key == "detection_id":
            continue
        setattr(existing, key, value)
    existing.updated_at = _utcnow_naive()


def upsert_detections(db: Session, items: list[DetectionResult]) -> tuple[int, int]:
    """Persist detections idempotently. Returns (created, updated).

    Each item commits independently: one bad row rolls back only itself,
    never the batch. Failed persistence leaves no partial rows.
    """
    created = updated = 0
    for det in items:
        fields = _payload(det)
        try:
            with db.begin_nested():
                existing = db.execute(
                    select(DetectionRow).where(
                        DetectionRow.detection_id == fields["detection_id"])
                ).scalars().first()
                if existing is None:
                    db.add(DetectionRow(**fields))
                    created += 1
                else:
                    _apply(existing, fields)
                    updated += 1
            db.commit()
        except IntegrityError:
            # Lost a race with a concurrent insert of the same detection_id.
            db.rollback()
            with db.begin_nested():
                existing = db.execute(
                    select(DetectionRow).where(
                        DetectionRow.detection_id == fields["detection_id"])
                ).scalars().first()
                if existing is None:
                    raise
                _apply(existing, fields)
                updated += 1
            db.commit()
            logger.info("detection race resolved", extra={"detection_id": fields["detection_id"]})
    logger.info("persist run: %d detections created, %d updated", created, updated)
    return created, updated
