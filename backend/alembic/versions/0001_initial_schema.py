"""Initial ThreatLens normalized SIEM schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-09 19:55:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=128), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"], unique=False)

    # 2. security_events
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("destination_ip", sa.String(length=64), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("hostname", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("event_category", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("raw_log", sa.Text(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_security_events_event_id", "security_events", ["event_id"], unique=True)
    op.create_index("ix_security_events_timestamp", "security_events", ["timestamp"], unique=False)
    op.create_index("ix_security_events_source_ip", "security_events", ["source_ip"], unique=False)
    op.create_index("ix_security_events_username", "security_events", ["username"], unique=False)
    op.create_index("ix_security_events_hostname", "security_events", ["hostname"], unique=False)
    op.create_index("ix_security_events_event_category", "security_events", ["event_category"], unique=False)
    op.create_index("ix_security_events_severity", "security_events", ["severity"], unique=False)
    op.create_index("ix_security_events_cat_ts", "security_events", ["event_category", "timestamp"], unique=False)
    op.create_index(
        "ix_security_events_src_user_ts",
        "security_events",
        ["source_ip", "username", "timestamp"],
        unique=False,
    )

    # 3. detection_rules
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("rule_key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("detection_logic", sa.Text(), nullable=False),
        sa.Column("event_category", sa.String(length=64), nullable=False),
        sa.Column("threshold_count", sa.Integer(), nullable=False),
        sa.Column("time_window_seconds", sa.Integer(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("mitre_tactic", sa.String(length=128), nullable=True),
        sa.Column("mitre_technique_id", sa.String(length=32), nullable=True),
        sa.Column("mitre_technique_name", sa.String(length=160), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"], unique=True)
    op.create_index("ix_detection_rules_rule_key", "detection_rules", ["rule_key"], unique=True)

    # 4. alerts
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "rule_id_fk",
            sa.Integer(),
            sa.ForeignKey("detection_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("rule_code", sa.String(length=32), nullable=False),
        sa.Column("rule_name", sa.String(length=160), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("hostname", sa.String(length=128), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("dedup_key", sa.String(length=255), nullable=False),
        sa.Column("mitre_tactic", sa.String(length=128), nullable=True),
        sa.Column("mitre_technique_id", sa.String(length=32), nullable=True),
        sa.Column("mitre_technique_name", sa.String(length=160), nullable=True),
        sa.Column("evidence_summary", sa.JSON(), nullable=False),
        sa.Column("assigned_to", sa.String(length=64), nullable=True),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_alert_id", "alerts", ["alert_id"], unique=True)
    op.create_index("ix_alerts_status_sev", "alerts", ["status", "severity"], unique=False)
    op.create_index("ix_alerts_rule_dedup", "alerts", ["rule_code", "dedup_key"], unique=False)

    # 5. alert_evidence
    op.create_table(
        "alert_evidence",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.Integer(),
            sa.ForeignKey("security_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("evidence_role", sa.String(length=64), nullable=False),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_id", "event_id", name="uq_alert_evidence_pair"),
    )
    op.create_index("ix_alert_evidence_alert_id", "alert_evidence", ["alert_id"], unique=False)
    op.create_index("ix_alert_evidence_event_id", "alert_evidence", ["event_id"], unique=False)

    # 6. alert_status_history
    op.create_table(
        "alert_status_history",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("previous_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("changed_by", sa.String(length=64), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alert_status_history_alert_id", "alert_status_history", ["alert_id"], unique=False)

    # 7. incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("assigned_analyst", sa.String(length=64), nullable=True),
        sa.Column("timeline_events", sa.JSON(), nullable=False),
        sa.Column("evidence_references", sa.JSON(), nullable=False),
        sa.Column("resolution_summary", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_incident_id", "incidents", ["incident_id"], unique=True)

    # 8. incident_alerts
    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            sa.Integer(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("linked_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert_pair"),
    )

    # 9. investigation_notes
    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            sa.Integer(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("author", sa.String(length=64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("note_type", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 10. threat_indicators
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("indicator_value", sa.String(length=255), nullable=False),
        sa.Column("threat_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_indicators_indicator_value", "threat_indicators", ["indicator_value"], unique=True)

    # 11. audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("actor_username", sa.String(length=64), nullable=False),
        sa.Column("actor_role", sa.String(length=32), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("threat_indicators")
    op.drop_table("investigation_notes")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
    op.drop_table("alert_status_history")
    op.drop_table("alert_evidence")
    op.drop_table("alerts")
    op.drop_table("detection_rules")
    op.drop_table("security_events")
    op.drop_table("users")

