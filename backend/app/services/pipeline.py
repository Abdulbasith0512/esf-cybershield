"""Synchronous pipeline: raw -> normalize -> rules -> UEBA -> ML -> correlate."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.incident import Incident
from app.db.models.normalized_event import NormalizedEvent
from app.db.models.raw_event import RawEvent
from app.db.models.signals import Detection, MlScore, UebaScore
from app.services.correlation import correlate
from app.services.ml import score_ml
from app.services.normalize import normalize_payload
from app.services.rules import run_rules
from app.services.ueba import score_ueba


def _utc(ts: datetime | None) -> datetime:
    # Naive UTC everywhere for SQLite/PG portability.
    if ts is None:
        return datetime.utcnow()
    if ts.tzinfo is not None:
        return ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts


def _json_safe(obj):
    """Recursively convert datetimes etc. so payload fits in JSON column."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def ingest_single(db: Session, payload: dict, source: str = "unknown", event_type: str = "unknown") -> dict:
    """Store raw + normalized, run full detection chain, commit. Returns summary."""
    client_event_id = str(payload.get("event_id") or payload.get("id") or uuid.uuid4())

    # Idempotency: same event_id returns prior result without duplicating.
    existing_raw = db.execute(select(RawEvent).where(RawEvent.event_id == client_event_id)).scalars().first()
    if existing_raw is not None:
        norm = db.execute(
            select(NormalizedEvent).where(NormalizedEvent.raw_event_id == existing_raw.id)
        ).scalars().first()
        return {
            "raw_id": existing_raw.id, "normalized_id": norm.id if norm else "",
            "event_id": client_event_id, "deduped": True, "incident_id": None,
            "detections": 0, "ueba_score": 0.0, "ml_score": 0.0, "ml_anomaly": False,
        }

    ts_hint = payload.get("timestamp")
    if isinstance(ts_hint, str):
        try:
            ts_hint = datetime.fromisoformat(ts_hint.replace("Z", "+00:00"))
        except ValueError:
            ts_hint = None
    if not isinstance(ts_hint, datetime):
        ts_hint = datetime.utcnow()

    raw = RawEvent(
        event_id=client_event_id,
        source=str(payload.get("source", source) or source),
        event_type=str(payload.get("event_type", event_type) or event_type),
        received_at=datetime.utcnow(),
        payload=_json_safe(payload),
    )
    db.add(raw)
    db.flush()

    try:
        norm_fields = normalize_payload(payload, fallback_ts=ts_hint)
    except ValueError as exc:
        db.rollback()
        raise exc

    norm = NormalizedEvent(
        raw_event_id=raw.id, ts=_utc(norm_fields["ts"]),
        user_id=norm_fields["user_id"], host=norm_fields["host"],
        src_ip=norm_fields["src_ip"], dst_ip=norm_fields["dst_ip"],
        dst_port=norm_fields["dst_port"], event_type=norm_fields["event_type"],
        action=norm_fields["action"], status=norm_fields["status"],
        event_meta={k: v for k, v in payload.items() if k not in norm_fields},
    )
    db.add(norm)
    db.flush()

    detections: list[Detection] = run_rules(db, norm)
    db.flush()
    ueba: UebaScore = score_ueba(db, norm)
    db.flush()
    ml: MlScore = score_ml(db, norm)
    db.flush()
    incident: Incident | None = correlate(db, norm, detections, ueba, ml)
    db.flush()
    db.commit()

    return {
        "raw_id": raw.id, "normalized_id": norm.id, "event_id": client_event_id,
        "deduped": False,
        "incident_id": incident.id if incident else None,
        "detections": len(detections),
        "ueba_score": ueba.score, "ml_score": ml.score, "ml_anomaly": ml.is_anomaly,
    }
