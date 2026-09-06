"""Raw (immutable) ingested event. System-of-record intake table."""

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.db.models._base import new_uuid, utcnow


class RawEvent(Base):
    __tablename__ = "raw_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    # Client-supplied idempotency key. Server generates one when missing.
    event_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    received_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_raw_events_event_type", "event_type"),
        Index("ix_raw_events_received_at", "received_at"),
    )
