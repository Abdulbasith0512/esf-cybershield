"""Detection — persisted deterministic DetectionResult (Slice 11).

One row per deterministic detection_id. Stores already-generated analysis;
persistence never reruns rules. Incidents reference these rows by ID.

Portability: JSONB on PostgreSQL, generic JSON on SQLite (tests/offline).
Timestamps are stored as naive UTC (SQLite returns naive datetimes);
the API layer always speaks timezone-aware UTC.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Index, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    # Deterministic engine ID (UUIDv5 over rule + evidence). UNIQUE =
    # re-persisting never duplicates.
    detection_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_event_ids: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    # Complete qualifying bucket membership (Slice 13E+). Absent ([]) for rows
    # persisted before bucket capture; investigation treats those as unknown,
    # never as empty evidence.
    bucket_event_ids: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    detection_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )

    __table_args__ = (
        Index("ix_detections_rule_id", "rule_id"),
        Index("ix_detections_severity", "severity"),
        Index("ix_detections_first_seen", "first_seen"),
        Index("ix_detections_last_seen", "last_seen"),
        # Composite: the common queue query is rule-filtered recency
        # (?rule_id=X ordered by last_seen DESC).
        Index("ix_detections_rule_last_seen", "rule_id", "last_seen"),
    )
