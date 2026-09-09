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
    assignee: str | None = None
    assigned_at: datetime | None = None
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


class CaseUpdate(BaseModel):
    """Controlled mutation: omitted fields untouched, null assignee unassigns."""

    model_config = {"extra": "forbid"}

    status: str | None = None
    assignee: str | None = None
    actor: str | None = None

    @property
    def has_status(self) -> bool:
        return "status" in self.model_fields_set

    @property
    def has_assignee(self) -> bool:
        return "assignee" in self.model_fields_set


class NoteCreate(BaseModel):
    model_config = {"extra": "forbid"}

    body: str
    author: str | None = None


class IncidentNoteResponse(BaseModel):
    note_id: str
    incident_id: str
    author: str | None = None
    body: str
    created_at: datetime


class IncidentActivityResponse(BaseModel):
    activity_id: str
    incident_id: str
    action: str
    actor: str | None = None
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    evidence_count: int
    bucket_count: int
    bucket_available: bool
    mitre_technique_ids: list[str] = Field(default_factory=list)


class EntitySummary(BaseModel):
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)


class DetectionTrace(BaseModel):
    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    reason: str
    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    evidence_event_ids: list[str] = Field(default_factory=list)
    bucket_event_ids: list[str] = Field(default_factory=list)
    bucket_available: bool = False
    mitre_technique_ids: list[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    factor: str
    points: int


class ExplanationMitreContext(BaseModel):
    technique_id: str
    rule_ids: list[str] = Field(default_factory=list)


class InvestigationExplanation(BaseModel):
    summary: str
    trigger_detections: list[str] = Field(default_factory=list)
    correlation_reason: str
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    mitre_context: list[ExplanationMitreContext] = Field(default_factory=list)
    ueba_context: dict[str, Any] = Field(default_factory=dict)
    unavailable: list[str] = Field(default_factory=list)


class InvestigationIncident(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    confidence: float
    risk_score: int
    risk_band: str
    risk_explanation: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    detection_count: int
    evidence_count: int


class InvestigationRisk(BaseModel):
    score: int
    band: str
    explanation: str
    breakdown: dict[str, Any] = Field(default_factory=dict)
    factors: list[RiskFactor] = Field(default_factory=list)


class InvestigationCaseNote(BaseModel):
    note_id: str
    author: str | None = None
    body: str
    created_at: datetime


class InvestigationCaseActivity(BaseModel):
    activity_id: str
    action: str
    actor: str | None = None
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationCase(BaseModel):
    status: str
    assignee: str | None = None
    assigned_at: datetime | None = None
    allowed_transitions: list[str] = Field(default_factory=list)
    notes: list[InvestigationCaseNote] = Field(default_factory=list)
    activity: list[InvestigationCaseActivity] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    incident: InvestigationIncident
    explanation: InvestigationExplanation
    timeline: list[TimelineEntry] = Field(default_factory=list)
    entities: EntitySummary = Field(default_factory=EntitySummary)
    detections: list[DetectionTrace] = Field(default_factory=list)
    evidence_sample: list[dict[str, Any]] = Field(default_factory=list)
    evidence_total: int = 0
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)
    ueba: dict[str, Any] = Field(default_factory=dict)
    risk: InvestigationRisk
    missing_detections: list[str] = Field(default_factory=list)
    case: InvestigationCase | None = None


class RecommendationEvidenceRefs(BaseModel):
    detection_ids: list[str] = Field(default_factory=list)
    detection_count: int = 0
    evidence_event_ids: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    technique_id: str | None = None


class Recommendation(BaseModel):
    id: str
    priority: str
    category: str
    title: str
    reason: str
    actions: list[str] = Field(default_factory=list)
    evidence_refs: RecommendationEvidenceRefs = Field(
        default_factory=RecommendationEvidenceRefs)


class RecommendationsResponse(BaseModel):
    incident_id: str
    recommendations: list[Recommendation] = Field(default_factory=list)
