"""0002 incident persistence

Revision ID: 0002_incidents
Revises: 0001_security_event

Slice 9: incidents table. One row per deterministic incident_id (UNIQUE =
idempotent re-persistence). Stores already-generated analysis only;
persistence never recalculates detection, correlation, MITRE, risk, or UEBA.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_incidents"
down_revision: str | None = "0001_security_event"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("incident_id", sa.Text, unique=True, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("risk_band", sa.Text, nullable=False),
        sa.Column("risk_explanation", sa.Text, nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_ids", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("evidence_event_ids", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("metadata", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("mitre_techniques", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("risk_breakdown", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("ueba_evidence", postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
                  nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_risk_score", "incidents", ["risk_score"])
    op.create_index("ix_incidents_risk_band", "incidents", ["risk_band"])
    op.create_index("ix_incidents_first_seen", "incidents", ["first_seen"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])
    op.create_index("ix_incidents_band_last_seen", "incidents", ["risk_band", "last_seen"])


def downgrade() -> None:
    op.drop_index("ix_incidents_band_last_seen", table_name="incidents")
    op.drop_index("ix_incidents_last_seen", table_name="incidents")
    op.drop_index("ix_incidents_first_seen", table_name="incidents")
    op.drop_index("ix_incidents_risk_band", table_name="incidents")
    op.drop_index("ix_incidents_risk_score", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_table("incidents")
