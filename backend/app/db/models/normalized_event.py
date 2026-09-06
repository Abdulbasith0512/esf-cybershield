"""Canonical normalized event. Decouples vendor formats from detection."""

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.db.models._base import new_uuid


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    raw_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("raw_events.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    ts: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    host: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    action: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    event_meta: Mapped[dict] = mapped_column("meta", JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_norm_user_ts", "user_id", "ts"),
        Index("ix_norm_host_ts", "host", "ts"),
        Index("ix_norm_src_ip_ts", "src_ip", "ts"),
        Index("ix_norm_event_type_ts", "event_type", "ts"),
    )
