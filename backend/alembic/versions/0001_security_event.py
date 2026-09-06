"""0001 security event foundation

Revision ID: 0001_security_event
Revises: None

Slice 1: single security_events table. PostgreSQL is the system of record.
event_id UNIQUE = idempotency. raw_event JSONB preserves original telemetry.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_security_event"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("event_id", sa.Text, unique=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("host", sa.Text, nullable=True),
        sa.Column("user", sa.Text, nullable=True),
        sa.Column("source_ip", sa.Text, nullable=True),
        sa.Column("destination_ip", sa.Text, nullable=True),
        sa.Column("destination_port", sa.SmallInteger, nullable=True),
        sa.Column("protocol", sa.Text, nullable=True),
        sa.Column("process_name", sa.Text, nullable=True),
        sa.Column("parent_process", sa.Text, nullable=True),
        sa.Column("command_line", sa.Text, nullable=True),
        sa.Column("file_hash", sa.Text, nullable=True),
        sa.Column("domain", sa.Text, nullable=True),
        sa.Column("url", sa.Text, nullable=True),
        sa.Column("bytes_sent", sa.BigInteger, nullable=True),
        sa.Column("bytes_received", sa.BigInteger, nullable=True),
        sa.Column("status", sa.Text, nullable=True),
        sa.Column("raw_event", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_security_events_timestamp", "security_events", ["timestamp"])
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_host", "security_events", ["host"])
    op.create_index("ix_security_events_user", "security_events", ["user"])
    op.create_index("ix_security_events_source_ip", "security_events", ["source_ip"])
    op.create_index("ix_security_events_destination_ip", "security_events", ["destination_ip"])
    op.create_index("ix_security_events_file_hash", "security_events", ["file_hash"])
    op.create_index("ix_security_events_user_timestamp", "security_events", ["user", "timestamp"])
    op.create_index("ix_security_events_host_timestamp", "security_events", ["host", "timestamp"])


def downgrade() -> None:
    op.drop_index("ix_security_events_host_timestamp", table_name="security_events")
    op.drop_index("ix_security_events_user_timestamp", table_name="security_events")
    op.drop_index("ix_security_events_file_hash", table_name="security_events")
    op.drop_index("ix_security_events_destination_ip", table_name="security_events")
    op.drop_index("ix_security_events_source_ip", table_name="security_events")
    op.drop_index("ix_security_events_user", table_name="security_events")
    op.drop_index("ix_security_events_host", table_name="security_events")
    op.drop_index("ix_security_events_event_type", table_name="security_events")
    op.drop_index("ix_security_events_timestamp", table_name="security_events")
    op.drop_table("security_events")
