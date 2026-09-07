"""Pydantic contracts for the Slice 11 detection read API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DetectionSummary(BaseModel):
    """Lightweight list row. No metadata payload."""

    model_config = {"from_attributes": True}

    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    reason: str


class DetectionResponse(BaseModel):
    """Full persisted detection. ORM objects are never returned directly."""

    model_config = {"from_attributes": True}

    detection_id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    reason: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    detection_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class DetectionListResponse(BaseModel):
    items: list[DetectionSummary]
    page: int
    page_size: int
    total: int
    pages: int
