"""Pydantic contracts for threat-intelligence enrichment.

Observable types mirror SecurityEvent columns that actually exist; extraction
only yields types present in stored telemetry. Classification is a closed set
so the UI can never invent a verdict the provider did not return.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ObservableType = Literal["ipv4", "ipv6", "domain", "url", "file_hash"]

ObservableSource = Literal[
    "source_ip", "destination_ip", "domain", "url", "file_hash",
]

Classification = Literal["benign", "suspicious", "malicious", "unknown"]


class Observable(BaseModel):
    """One deduplicated observable with traceability to source events."""

    model_config = {"extra": "forbid"}

    type: ObservableType
    value: str
    normalized_value: str
    source: ObservableSource
    first_seen: str
    last_seen: str
    event_count: int
    event_ids: list[str] = Field(default_factory=list)


class ThreatIntelResult(BaseModel):
    """Structured provider answer. Never an arbitrary provider payload."""

    model_config = {"extra": "forbid"}

    provider: str
    observable_type: str
    observable_value: str
    classification: Classification
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    reference: str | None = None
    retrieved_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnrichedObservable(BaseModel):
    """Observable + provider result + incident traceability."""

    model_config = {"extra": "forbid"}

    observable: Observable
    available: bool = True
    intelligence: ThreatIntelResult | None = None
    error: str | None = None
    detection_ids: list[str] = Field(default_factory=list)
    incident_id: str = ""
