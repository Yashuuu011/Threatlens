from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="analyst", index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)


class SecurityEvent(Base, TimestampMixin):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True, index=True)
    username = Column(String(128), nullable=True, index=True)
    hostname = Column(String(128), nullable=True, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    event_category = Column(String(64), nullable=False, index=True)
    action = Column(String(128), nullable=False, index=True)
    status = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    raw_log = Column(Text, nullable=False)
    event_metadata = Column("metadata", JSON, nullable=False, default=dict)
    is_synthetic = Column(Boolean, default=False, nullable=False, index=True)

    evidence_links = relationship(
        "AlertEvidence",
        back_populates="event",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_security_events_cat_ts", "event_category", "timestamp"),
        Index("ix_security_events_src_user_ts", "source_ip", "username", "timestamp"),
        Index("ix_security_events_sev_ts", "severity", "timestamp"),
    )

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        return self.event_metadata or {}


class DetectionRule(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(32), unique=True, nullable=False, index=True)
    rule_key = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(160), unique=True, nullable=False)
    description = Column(Text, nullable=False)
    detection_logic = Column(Text, nullable=False)
    event_category = Column(String(64), nullable=False, index=True)
    threshold_count = Column(Integer, nullable=False, default=5)
    time_window_seconds = Column(Integer, nullable=False, default=300)
    parameters = Column(JSON, nullable=False, default=dict)
    severity = Column(String(32), nullable=False, default="high", index=True)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    mitre_tactic = Column(String(128), nullable=True, index=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(160), nullable=True)

    alerts = relationship("Alert", back_populates="rule")


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="New", index=True)

    rule_id_fk = Column(Integer, ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_code = Column(String(32), nullable=False, index=True)
    rule_name = Column(String(160), nullable=False)

    source_ip = Column(String(64), nullable=True, index=True)
    username = Column(String(128), nullable=True, index=True)
    hostname = Column(String(128), nullable=True, index=True)

    first_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False, index=True)
    event_count = Column(Integer, nullable=False, default=1)
    dedup_key = Column(String(255), nullable=False, index=True)

    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(160), nullable=True)

    evidence_summary = Column(JSON, nullable=False, default=dict)
    assigned_to = Column(String(64), nullable=True, index=True)
    is_synthetic = Column(Boolean, default=False, nullable=False, index=True)

    rule = relationship("DetectionRule", back_populates="alerts")
    evidence_items = relationship(
        "AlertEvidence",
        back_populates="alert",
        cascade="all, delete-orphan",
    )
    status_history = relationship(
        "AlertStatusHistory",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertStatusHistory.created_at.desc()",
    )
    notes = relationship(
        "InvestigationNote",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="InvestigationNote.created_at.desc()",
    )
    incident_links = relationship(
        "IncidentAlert",
        back_populates="alert",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_alerts_status_sev", "status", "severity"),
        Index("ix_alerts_rule_dedup", "rule_code", "dedup_key"),
    )


class AlertEvidence(Base, TimestampMixin):
    __tablename__ = "alert_evidence"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id = Column(
        Integer,
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_role = Column(String(64), nullable=False, default="triggering_event")
    note = Column(String(255), nullable=True)

    alert = relationship("Alert", back_populates="evidence_items")
    event = relationship("SecurityEvent", back_populates="evidence_links")

    __table_args__ = (
        UniqueConstraint("alert_id", "event_id", name="uq_alert_evidence_pair"),
    )


class AlertStatusHistory(Base, TimestampMixin):
    __tablename__ = "alert_status_history"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_status = Column(String(32), nullable=True)
    new_status = Column(String(32), nullable=False)
    changed_by = Column(String(64), nullable=False)
    comment = Column(Text, nullable=True)

    alert = relationship("Alert", back_populates="status_history")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="Open", index=True)
    description = Column(Text, nullable=False)
    assigned_analyst = Column(String(64), nullable=True, index=True)
    timeline_events = Column(JSON, nullable=False, default=list)
    evidence_references = Column(JSON, nullable=False, default=list)
    resolution_summary = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String(64), nullable=True)

    alert_links = relationship(
        "IncidentAlert",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    notes = relationship(
        "InvestigationNote",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="InvestigationNote.created_at.desc()",
    )


class IncidentAlert(Base, TimestampMixin):
    __tablename__ = "incident_alerts"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id = Column(
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    linked_by = Column(String(64), nullable=True)

    incident = relationship("Incident", back_populates="alert_links")
    alert = relationship("Alert", back_populates="incident_links")

    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert_pair"),
    )


class InvestigationNote(Base, TimestampMixin):
    __tablename__ = "investigation_notes"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    incident_id = Column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    author = Column(String(64), nullable=False, index=True)
    content = Column(Text, nullable=False)
    note_type = Column(String(32), nullable=False, default="analyst_note")

    alert = relationship("Alert", back_populates="notes")
    incident = relationship("Incident", back_populates="notes")


class ThreatIndicator(Base, TimestampMixin):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(32), nullable=False, default="ip", index=True)
    indicator_value = Column(String(255), unique=True, nullable=False, index=True)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="high", index=True)
    confidence = Column(Integer, nullable=False, default=85)
    source = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=False, default=list)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    hit_count = Column(Integer, nullable=False, default=0)


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_username = Column(String(64), nullable=False, index=True)
    actor_role = Column(String(32), nullable=True)
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(128), nullable=True, index=True)
    ip_address = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="success")
    details = Column(JSON, nullable=False, default=dict)

