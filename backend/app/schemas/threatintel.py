"""Pydantic contracts for the Slice 40 threat-intelligence read API."""

from pydantic import BaseModel, Field

from app.services.threatintel.models import EnrichedObservable


class ThreatIntelResponse(BaseModel):
    incident_id: str
    provider: str
    available: bool = True
    error: str | None = None
    observables: list[EnrichedObservable] = Field(default_factory=list)
