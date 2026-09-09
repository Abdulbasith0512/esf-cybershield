"""0004 case-management schema

Revision ID: 0004_case_management
Revises: 0003_detections

Covers everything the SQLAlchemy models added after 0003 (Slice 38 case
management plus Slice 13E+ detection buckets) so `alembic upgrade head`
produces exactly the schema `Base.metadata.create_all` produces:

- incidents.assignee / incidents.assigned_at (nullable; existing rows keep NULL)
- detections.bucket_event_ids (NOT NULL, backfilled to [] which the
  investigation layer already treats as "unknown, never empty evidence")
- incident_notes + incident_activity tables with their indexes

Data-preserving: only ADD COLUMN (nullable or server-defaulted) and
CREATE TABLE. Downgrade drops the additions in reverse order.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_case_management"
down_revision: str | None = "0003_detections"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("assignee", sa.Text(), nullable=True))
    op.add_column("incidents",
                  sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "detections",
        sa.Column("bucket_event_ids",
                  postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False, server_default="[]"),
    )
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("note_id", sa.Text, unique=True, nullable=False),
        sa.Column("incident_id", sa.Text, nullable=False),
        sa.Column("author", sa.Text, nullable=True),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])
    op.create_index("ix_incident_notes_incident_created", "incident_notes",
                    ["incident_id", "created_at"])
    op.create_table(
        "incident_activity",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("activity_id", sa.Text, unique=True, nullable=False),
        sa.Column("incident_id", sa.Text, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("actor", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
    )
    op.create_index("ix_incident_activity_incident_id", "incident_activity", ["incident_id"])
    op.create_index("ix_incident_activity_incident_created", "incident_activity",
                    ["incident_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_incident_activity_incident_created", table_name="incident_activity")
    op.drop_index("ix_incident_activity_incident_id", table_name="incident_activity")
    op.drop_table("incident_activity")
    op.drop_index("ix_incident_notes_incident_created", table_name="incident_notes")
    op.drop_index("ix_incident_notes_incident_id", table_name="incident_notes")
    op.drop_table("incident_notes")
    op.drop_column("detections", "bucket_event_ids")
    op.drop_column("incidents", "assigned_at")
    op.drop_column("incidents", "assignee")
