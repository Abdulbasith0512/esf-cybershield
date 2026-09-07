"""0003 detection persistence

Revision ID: 0003_detections
Revises: 0002_incidents

Slice 11: detections table. One row per deterministic detection_id (UNIQUE =
idempotent re-persistence). Stores already-generated DetectionResults;
persistence never reruns rules.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_detections"
down_revision: str | None = "0002_incidents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detections",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("detection_id", sa.Text, unique=True, nullable=False),
        sa.Column("rule_id", sa.Text, nullable=False),
        sa.Column("rule_name", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("evidence_event_ids", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("metadata", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detections_rule_id", "detections", ["rule_id"])
    op.create_index("ix_detections_severity", "detections", ["severity"])
    op.create_index("ix_detections_first_seen", "detections", ["first_seen"])
    op.create_index("ix_detections_last_seen", "detections", ["last_seen"])
    op.create_index("ix_detections_rule_last_seen", "detections", ["rule_id", "last_seen"])


def downgrade() -> None:
    op.drop_index("ix_detections_rule_last_seen", table_name="detections")
    op.drop_index("ix_detections_last_seen", table_name="detections")
    op.drop_index("ix_detections_first_seen", table_name="detections")
    op.drop_index("ix_detections_severity", table_name="detections")
    op.drop_index("ix_detections_rule_id", table_name="detections")
    op.drop_table("detections")
