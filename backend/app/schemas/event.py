"""Pydantic schemas for event ingest and reads."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventIngest(BaseModel):
    event_id: str | None = Field(default=None, description="Client idempotency key")
    source: str = Field(default="unknown")
    event_type: str = Field(default="unknown")
    timestamp: datetime | None = None
    user_id: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    action: str | None = None
    status: str | None = None
    raw: dict[str, Any] | None = None


class EventIngestResponse(BaseModel):
    raw_id: str
    normalized_id: str
    event_id: str
    deduped: bool = False
    incident_id: str | None = None


class NormalizedEventOut(BaseModel):
    id: str
    ts: datetime
    user_id: str
    host: str
    src_ip: str | None
    dst_ip: str | None
    event_type: str
    action: str
    status: str
