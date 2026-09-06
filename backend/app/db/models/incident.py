"""Incident, incident-event link, and risk audit trail."""

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.db.models._base import new_uuid, utcnow


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # JSON list of technique IDs, e.g. ["T1110", "T1078"]. JSON keeps PG+SQLite portable.
    mitre_techniques: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    principal: Mapped[str] = mapped_column(String(256), nullable=False, default="unknown")
    first_seen: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_principal", "principal"),
        Index("ix_incidents_last_seen", "last_seen"),
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    normalized_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("normalized_events.id", ondelete="CASCADE"), primary_key=True
    )
    added_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    factors: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    calculated_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (Index("ix_risk_events_incident", "incident_id"),)
