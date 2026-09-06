"""Pydantic contracts for the Slice 9 incident read API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.services.mitre.models import MitreMapping, RiskBreakdown
from app.services.ueba.evidence import UEBAIncidentEvidence


class IncidentResponse(BaseModel):
    """Full persisted incident. ORM objects are never returned directly."""

    model_config = {"from_attributes": True}

    incident_id: str
    title: str
    severity: str
    status: str
    confidence: float
    reason: str
    risk_score: int
    risk_band: str
    risk_explanation: str
    first_seen: datetime
    last_seen: datetime
    detection_ids: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str] = Field(default_factory=list)
    incident_metadata: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)
    risk_breakdown: RiskBreakdown | None = None
    ueba_evidence: UEBAIncidentEvidence | None = None
    created_at: datetime
    updated_at: datetime


class IncidentSummary(BaseModel):
    """Lightweight queue row. No raw payloads, UEBA as flag/score only."""

    model_config = {"from_attributes": True}

    incident_id: str
    title: str
    severity: str
    status: str
    confidence: float
    risk_score: int
    risk_band: str
    ueba_available: bool = False
    ueba_anomaly_score: float | None = None
    ueba_anomaly_flag: bool | None = None
    first_seen: datetime
    last_seen: datetime


class IncidentListResponse(BaseModel):
    items: list[IncidentSummary]
    page: int
    page_size: int
    total: int
    pages: int
