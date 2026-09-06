"""Deterministic risk scoring with an audit trail."""

from sqlalchemy.orm import Session

from app.db.models.incident import Incident, RiskEvent

SEVERITY_BASE = {"low": 20, "medium": 40, "high": 70, "critical": 90}


def calculate_risk(
    db: Session,
    incident: Incident,
    severities: list[str],
    ml_anomaly: bool,
    ueba_high: bool,
    technique_count: int,
) -> int:
    base = max([SEVERITY_BASE.get(s, 40) for s in severities], default=40)
    score = base
    factors: dict = {"base_severity": base, "severities": severities}
    if ml_anomaly:
        score += 20
        factors["ml_anomaly"] = True
    if ueba_high:
        score += 15
        factors["ueba_high"] = True
    if technique_count > 1:
        bonus = min(10 * (technique_count - 1), 20)
        score += bonus
        factors["technique_bonus"] = bonus
    if incident.event_count >= 5:
        score += 5
        factors["volume_bonus"] = 5
    score = max(0, min(int(score), 100))
    factors["final"] = score
    db.add(RiskEvent(incident_id=incident.id, score=score, factors=factors))
    incident.risk_score = score
    return score
