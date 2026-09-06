"""Incident contract + deterministic identity helpers."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Status = Literal["OPEN", "INVESTIGATING", "RESOLVED"]
NAMESPACE = uuid.UUID("3f6b2c8d-9a1e-5d4b-8c7f-2e5a9d3c6b11")


class Incident(BaseModel):
    """Correlated security story. Built from detections, never from raw truth."""

    incident_id: str
    title: str
    severity: Severity
    status: Status = "OPEN"
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    detection_ids: list[str] = Field(min_length=1)
    evidence_event_ids: list[str] = Field(min_length=1)
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return f"incident:{','.join(sorted(self.detection_ids))}"


def incident_id_for(detection_ids: list[str]) -> str:
    """Deterministic ID: same detection membership always yields same ID."""
    return str(uuid.uuid5(NAMESPACE, f"incident:{','.join(sorted(detection_ids))}"))
