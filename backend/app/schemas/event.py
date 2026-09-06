"""Pydantic contracts for the Slice 1 event API."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

REQUIRED_MSG = "field required"


class EventCreate(BaseModel):
    """Single security event submission. Field names follow the spec exactly."""

    model_config = {"extra": "forbid", "str_strip_whitespace": True}

    event_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    host: str | None = Field(default=None, max_length=256)
    user: str | None = Field(default=None, max_length=256)
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    process_name: str | None = Field(default=None, max_length=512)
    parent_process: str | None = Field(default=None, max_length=512)
    command_line: str | None = None
    file_hash: str | None = Field(default=None, max_length=256)
    domain: str | None = Field(default=None, max_length=512)
    url: str | None = None
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)
    status: str | None = Field(default=None, max_length=64)
    raw_event: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def _require_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (include Z or offset)")
        return v

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        import ipaddress

        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"invalid IP address: {v!r}")

    @field_validator("event_id", "event_type", "source", mode="before")
    @classmethod
    def _non_empty(cls, v: Any) -> Any:
        if isinstance(v, str) and not v.strip():
            raise ValueError(REQUIRED_MSG)
        return v


class EventResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    event_id: str
    timestamp: datetime
    event_type: str
    source: str
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    status: str | None = None
    raw_event: dict[str, Any]
    created_at: datetime


class EventBatchCreate(BaseModel):
    model_config = {"extra": "forbid"}

    events: list[EventCreate] = Field(min_length=1)


class EventBatchItemResult(BaseModel):
    event_id: str | None = None
    status: Literal["created", "duplicate", "rejected"]
    id: uuid.UUID | None = None
    error: str | None = None


class EventBatchResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    results: list[EventBatchItemResult]


class EventListResponse(BaseModel):
    items: list[EventResponse]
    page: int
    page_size: int
    total: int
    pages: int
