"""Rule-based detections, UEBA scores, and ML scores (kept separate)."""

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base
from app.db.models._base import new_uuid, utcnow


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    normalized_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    mitre_technique: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_detections_norm_id", "normalized_event_id"),
        Index("ix_detections_rule_id", "rule_id"),
    )


class UebaScore(Base):
    __tablename__ = "ueba_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    normalized_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    baseline_ref: Mapped[str] = mapped_column(String(64), nullable=False, default="30d-user")
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    features: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class MlScore(Base):
    __tablename__ = "ml_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    normalized_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    model_version: Mapped[str] = mapped_column(String(64), nullable=False, default="iforest-v1")
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.7)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    features: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
