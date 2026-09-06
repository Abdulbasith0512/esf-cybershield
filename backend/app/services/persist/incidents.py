"""Idempotent incident persistence. Mirror of generated content, nothing more.

Semantics: same incident_id twice -> exactly one row (full overwrite of
derived fields, incident_id and created_at preserved). Uses
select-then-insert + IntegrityError catch (SQLite-safe; no PG-only
ON CONFLICT). Timestamps stored naive UTC, matching the events table.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.incident import Incident as IncidentRow
from app.services.ueba.evidence import IncidentWithUeba

logger = logging.getLogger("esf.persist")


def _naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


def _payload(item: IncidentWithUeba) -> dict[str, Any]:
    inc = item.enriched.incident
    return {
        "incident_id": inc.incident_id,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "confidence": inc.confidence,
        "reason": inc.reason,
        "risk_score": item.enriched.risk_score,
        "risk_band": item.enriched.risk_band,
        "risk_explanation": item.enriched.risk_explanation,
        "first_seen": _naive_utc(inc.first_seen),
        "last_seen": _naive_utc(inc.last_seen),
        "detection_ids": sorted(inc.detection_ids),
        "evidence_event_ids": sorted(set(inc.evidence_event_ids)),
        "incident_metadata": dict(inc.metadata or {}),
        "mitre_techniques": [m.model_dump(mode="json") for m in item.enriched.mitre_techniques],
        "risk_breakdown": item.enriched.risk_breakdown.model_dump(mode="json"),
        "ueba_evidence": item.ueba.model_dump(mode="json"),
    }


def upsert_incidents(db: Session, items: list[IncidentWithUeba]) -> tuple[int, int]:
    """Persist incidents idempotently. Returns (created, updated).

    Each item commits independently: one bad row rolls back only itself,
    never the batch. Failed persistence leaves no partial rows.
    """
    created = updated = 0
    for item in items:
        fields = _payload(item)
        try:
            with db.begin_nested():
                existing = db.execute(
                    select(IncidentRow).where(
                        IncidentRow.incident_id == fields["incident_id"])
                ).scalars().first()
                if existing is None:
                    db.add(IncidentRow(**fields))
                    created += 1
                else:
                    for key, value in fields.items():
                        if key == "incident_id":
                            continue
                        setattr(existing, key, value)
                    existing.updated_at = _utcnow_naive()
                    updated += 1
            db.commit()
        except IntegrityError:
            # Lost a race with a concurrent insert of the same incident_id.
            db.rollback()
            with db.begin_nested():
                existing = db.execute(
                    select(IncidentRow).where(
                        IncidentRow.incident_id == fields["incident_id"])
                ).scalars().first()
                if existing is None:
                    raise
                for key, value in fields.items():
                    if key == "incident_id":
                        continue
                    setattr(existing, key, value)
                existing.updated_at = _utcnow_naive()
                updated += 1
            db.commit()
            logger.info("incident race resolved", extra={"incident_id": fields["incident_id"]})
    logger.info("persist run: %d created, %d updated", created, updated)
    return created, updated
