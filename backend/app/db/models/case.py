"""Case-management tables: analyst notes + activity history (Slice 38).

Append-only case metadata around incidents. Detection/evidence rows are
never written from this layer. Tables are created via Base.metadata like
all other models (no migration framework in this project stage).
"""

import threading
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


_last_stamp = datetime.min.replace(tzinfo=None)
_stamp_lock = threading.Lock()


def _utcnow_naive() -> datetime:
    """Monotonic naive-UTC clock for case created_at defaults.

    Platform wall clocks can be coarser than the request rate (successive
    utcnow() calls returning identical values), which used to tie created_at
    across activity/note rows and leave ORDER BY (created_at, random_id) to
    a random tiebreak. The guard bumps forward by 1us on ties so insertion
    order is always recoverable. Real time never moves backwards here.
    """
    global _last_stamp
    with _stamp_lock:
        now = datetime.utcnow()
        if now <= _last_stamp:
            now = _last_stamp + timedelta(microseconds=1)
        _last_stamp = now
        return now


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    note_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    author: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )

    __table_args__ = (
        Index("ix_incident_notes_incident_created", "incident_id", "created_at"),
    )


class IncidentActivity(Base):
    __tablename__ = "incident_activity"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    activity_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow_naive
    )
    activity_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=dict
    )

    __table_args__ = (
        Index("ix_incident_activity_incident_created", "incident_id", "created_at"),
    )
