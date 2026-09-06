"""0001 core pipeline

Revision ID: 0001_core
Revises:
Create Date: 2026-09-06

PostgreSQL system of record: raw_events -> normalized_events -> detections /
ueba_scores / ml_scores -> incidents -> incident_events + risk_events.
Portable types (String/JSON/DateTime) so the same DDL runs on PG and SQLite.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0001_core"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "raw_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_id", sa.String(128), unique=True, nullable=False),
        sa.Column("source", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("event_type", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    op.create_index("ix_raw_events_event_type", "raw_events", ["event_type"])
    op.create_index("ix_raw_events_received_at", "raw_events", ["received_at"])

    op.create_table(
        "normalized_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("raw_event_id", sa.String(36), sa.ForeignKey("raw_events.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.String(128), nullable=False, server_default="unknown"),
        sa.Column("host", sa.String(128), nullable=False, server_default="unknown"),
        sa.Column("src_ip", sa.String(64), nullable=True),
        sa.Column("dst_ip", sa.String(64), nullable=True),
        sa.Column("dst_port", sa.Integer, nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("action", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("meta", sa.JSON, nullable=False, server_default="{}"),
    )
    op.create_index("ix_norm_user_ts", "normalized_events", ["user_id", "ts"])
    op.create_index("ix_norm_host_ts", "normalized_events", ["host", "ts"])
    op.create_index("ix_norm_src_ip_ts", "normalized_events", ["src_ip", "ts"])
    op.create_index("ix_norm_event_type_ts", "normalized_events", ["event_type", "ts"])

    op.create_table(
        "detections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("normalized_event_id", sa.String(36), sa.ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_name", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("mitre_technique", sa.String(16), nullable=True),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detections_norm_id", "detections", ["normalized_event_id"])
    op.create_index("ix_detections_rule_id", "detections", ["rule_id"])

    op.create_table(
        "ueba_scores",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("normalized_event_id", sa.String(36), sa.ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("user_id", sa.String(128), nullable=False),
        sa.Column("baseline_ref", sa.String(64), nullable=False, server_default="30d-user"),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("features", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("reasons", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "ml_scores",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("normalized_event_id", sa.String(36), sa.ForeignKey("normalized_events.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("model_version", sa.String(64), nullable=False, server_default="iforest-v1"),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("threshold", sa.Float, nullable=False, server_default="0.7"),
        sa.Column("is_anomaly", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("features", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("mitre_techniques", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("principal", sa.String(256), nullable=False, server_default="unknown"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_principal", "incidents", ["principal"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])

    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("normalized_event_id", sa.String(36), sa.ForeignKey("normalized_events.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "risk_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score", sa.Integer, nullable=False),
        sa.Column("factors", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_risk_events_incident", "risk_events", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_risk_events_incident", table_name="risk_events")
    op.drop_table("risk_events")
    op.drop_table("incident_events")
    op.drop_index("ix_incidents_last_seen", table_name="incidents")
    op.drop_index("ix_incidents_principal", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_table("incidents")
    op.drop_table("ml_scores")
    op.drop_table("ueba_scores")
    op.drop_index("ix_detections_rule_id", table_name="detections")
    op.drop_index("ix_detections_norm_id", table_name="detections")
    op.drop_table("detections")
    op.drop_index("ix_norm_event_type_ts", table_name="normalized_events")
    op.drop_index("ix_norm_src_ip_ts", table_name="normalized_events")
    op.drop_index("ix_norm_host_ts", table_name="normalized_events")
    op.drop_index("ix_norm_user_ts", table_name="normalized_events")
    op.drop_table("normalized_events")
    op.drop_index("ix_raw_events_received_at", table_name="raw_events")
    op.drop_index("ix_raw_events_event_type", table_name="raw_events")
    op.drop_table("raw_events")
