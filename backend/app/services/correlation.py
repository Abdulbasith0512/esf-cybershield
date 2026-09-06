"""Correlation: group signals into incidents by principal + 1h window."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.incident import Incident, IncidentEvent
from app.db.models.normalized_event import NormalizedEvent
from app.db.models.signals import Detection, MlScore, UebaScore
from app.services.risk import calculate_risk

WINDOW = timedelta(hours=1)
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _naive(dt: datetime) -> datetime:
    # PG returns aware datetimes, SQLite returns naive. Compare naive UTC.
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _principal(event: NormalizedEvent) -> str:
    if event.user_id not in ("unknown", ""):
        return f"user:{event.user_id}"
    if event.src_ip:
        return f"ip:{event.src_ip}"
    return f"host:{event.host}"


def correlate(
    db: Session,
    event: NormalizedEvent,
    detections: list[Detection],
    ueba: UebaScore | None,
    ml: MlScore | None,
) -> Incident | None:
    signals = len(detections)
    ml_anomaly = bool(ml and ml.is_anomaly)
    ueba_high = bool(ueba and ueba.score >= 0.8)
    if ml_anomaly:
        signals += 1
    if ueba_high:
        signals += 1

    # Any fired rule already encodes a threshold (e.g. 5 fails, 10 targets),
    # so one detection is enough to open an incident. Without rules we
    # require 2 independent signals (ML + UEBA) to avoid false positives.
    has_detection = len(detections) > 0
    if has_detection:
        pass
    elif not (ml_anomaly and ueba_high):
        return None

    principal = _principal(event)
    since = event.ts - WINDOW
    existing = db.execute(
        select(Incident).where(
            Incident.principal == principal,
            Incident.status == "open",
            Incident.last_seen >= since,
        ).order_by(Incident.last_seen.desc()).limit(1)
    ).scalars().first()

    techniques = sorted({d.mitre_technique for d in detections if d.mitre_technique})
    severities = [d.severity for d in detections]

    if existing is None:
        title_bits = []
        if detections:
            title_bits.append(detections[0].rule_name)
        if ml_anomaly:
            title_bits.append("ml-anomaly")
        if ueba_high:
            title_bits.append("behavioral-deviation")
        title = f"{principal} — {' + '.join(title_bits) or 'suspicious activity'}"
        incident = Incident(
            title=title,
            status="open",
            severity=max(severities, key=lambda s: SEVERITY_RANK.get(s, 0)) if severities else "medium",
            mitre_techniques=techniques,
            principal=principal,
            first_seen=event.ts,
            last_seen=event.ts,
            event_count=1,
        )
        db.add(incident)
        db.flush()  # assign id
        db.add(IncidentEvent(incident_id=incident.id, normalized_event_id=event.id))
        calculate_risk(db, incident, severities or ["medium"], ml_anomaly, ueba_high, len(techniques))
        return incident

    # Attach to existing open incident.
    already = db.get(IncidentEvent, (existing.id, event.id))
    if already is None:
        db.add(IncidentEvent(incident_id=existing.id, normalized_event_id=event.id))
        existing.event_count += 1
    ets, efirst, elast = _naive(event.ts), _naive(existing.first_seen), _naive(existing.last_seen)
    if ets < efirst:
        existing.first_seen = event.ts
    if ets > elast:
        existing.last_seen = event.ts
    merged = sorted(set(existing.mitre_techniques or []) | set(techniques))
    existing.mitre_techniques = merged
    if severities and SEVERITY_RANK.get(max(severities, key=lambda s: SEVERITY_RANK.get(s, 0)), 0) > SEVERITY_RANK.get(existing.severity, 0):
        existing.severity = max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))
    calculate_risk(db, existing, severities or [existing.severity], ml_anomaly, ueba_high, len(merged))
    from app.db.models._base import utcnow

    existing.updated_at = utcnow()
    return existing
