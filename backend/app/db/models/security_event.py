"""SecurityEvent — the single system-of-record table (Slice 1).

PostgreSQL is the system of record. One row per external telemetry event.
`raw_event` holds the original telemetry byte-identical (as parsed JSON);
all other columns are safe canonicalizations produced by the normalize
service. No detection, classification, or verdict columns live here.

Portability: JSONB on PostgreSQL, generic JSON on SQLite (tests/offline).
Timestamps are stored as naive UTC (SQLite returns naive datetimes);
the API layer always speaks timezone-aware UTC.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, Index, SmallInteger, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _utcnow_naive() -> datetime:
    return datetime.utcnow()


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    # External idempotency key. UNIQUE = duplicate POSTs never create 2 rows.
    event_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str | None] = mapped_column(Text, nullable=True)
    user: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)
    process_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_process: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_received: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_event: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )

    __table_args__ = (
        Index("ix_security_events_timestamp", "timestamp"),
        Index("ix_security_events_event_type", "event_type"),
        Index("ix_security_events_host", "host"),
        Index("ix_security_events_user", "user"),
        Index("ix_security_events_source_ip", "source_ip"),
        Index("ix_security_events_destination_ip", "destination_ip"),
        Index("ix_security_events_file_hash", "file_hash"),
        # Composite: time-range-per-entity is the dominant query pattern
        # (?user=X&start&end, ?host=Y&start&end). Composite avoids a sort
        # and supports index-ordered pagination. No composites on IPs:
        # lower selectivity benefit than write cost at this scale.
        Index("ix_security_events_user_timestamp", "user", "timestamp"),
        Index("ix_security_events_host_timestamp", "host", "timestamp"),
    )
