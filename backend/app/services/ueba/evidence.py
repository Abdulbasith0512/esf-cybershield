"""UEBA incident-evidence contracts. Read-only attachment; risk untouched."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.services.mitre.models import EnrichedIncident


class UebaObservationRef(BaseModel):
    entity_key: str
    observation_time: datetime
    anomaly_score: float = Field(ge=0.0, le=1.0)
    anomaly_flag: bool
    baseline_status: str
    feature_context: dict[str, float] = Field(default_factory=dict)
    event_overlap: list[str] = Field(default_factory=list)


class UEBAIncidentEvidence(BaseModel):
    """Behavioral-anomaly context for one incident. Three explicit states:
    available=False (no model/context), available clean, available anomalous.
    Never a risk score, never proof of compromise."""

    incident_id: str
    incident_fingerprint: str
    available: bool
    anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)
    anomaly_flag: bool | None = None
    model_version: str | None = None
    feature_version: str | None = None
    feature_window_start: datetime | None = None
    feature_window_end: datetime | None = None
    observations: list[UebaObservationRef] = Field(default_factory=list)
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentWithUeba(BaseModel):
    enriched: EnrichedIncident
    ueba: UEBAIncidentEvidence

    @property
    def fingerprint(self) -> str:
        return self.enriched.fingerprint

    @property
    def incident_id(self) -> str:
        return self.enriched.incident_id
