"""Enrichment contracts. Incident itself is never modified."""

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.services.correlate.models import Incident

RiskBand = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    source_rule_id: str
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    catalog_version: str


class RiskBreakdown(BaseModel):
    severity_points: int = 0
    diversity_points: int = 0
    confidence_points: int = 0
    evidence_points: int = 0
    sequence_points: int = 0
    mitre_points: int = 0
    contextual_points: int = 0
    total: int = Field(ge=0, le=100)


class EnrichedIncident(BaseModel):
    incident: Incident
    mitre_techniques: list[MitreMapping] = Field(default_factory=list)
    risk_score: int = Field(ge=0, le=100)
    risk_band: RiskBand
    risk_breakdown: RiskBreakdown
    risk_explanation: str

    @property
    def fingerprint(self) -> str:
        return self.incident.fingerprint

    @property
    def incident_id(self) -> str:
        return self.incident.incident_id
