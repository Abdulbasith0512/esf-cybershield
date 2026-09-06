"""Incident — persisted correlated security story (Slice 9).

PostgreSQL is the system of record. One row per deterministic incident_id.
This table stores already-generated analysis (detections, correlation, MITRE,
risk, UEBA); persistence never recalculates anything.

Portability: JSONB on PostgreSQL, generic JSON on SQLite (tests/offline).
Timestamps are stored as naive UTC (SQLite returns naive datetimes);
the API layer always speaks timezone-aware UTC.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Index, Integer, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    # Deterministic correlation ID. UNIQUE = re-persisting never duplicates.
    incident_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="OPEN")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_band: Mapped[str] = mapped_column(Text, nullable=False, default="LOW")
    risk_explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detection_ids: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    evidence_event_ids: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    incident_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    mitre_techniques: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    ueba_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )

    __table_args__ = (
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_risk_score", "risk_score"),
        Index("ix_incidents_risk_band", "risk_band"),
        Index("ix_incidents_first_seen", "first_seen"),
        Index("ix_incidents_last_seen", "last_seen"),
        # Composite: the SOC queue's dominant query is band-filtered recency
        # (?risk_band=X ordered by last_seen DESC). No user/host composites:
        # entity lives inside JSON metadata, not a column, in this slice.
        Index("ix_incidents_band_last_seen", "risk_band", "last_seen"),
    )
