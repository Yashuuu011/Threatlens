import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ingestion.normalizer import normalize_raw_event_payload


VALID_CATEGORIES = {
    "authentication": "Authentication",
    "authorization": "Authorization",
    "network": "Network",
    "endpoint": "Endpoint",
    "system": "System",
    "application": "Application",
}

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_ALERT_STATUSES = {"New", "Acknowledged", "Investigating", "Resolved", "False Positive"}
VALID_INCIDENT_STATUSES = {"Open", "Investigating", "Contained", "Resolved", "Closed"}


def normalize_utc(dt: Optional[datetime]) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_ip_string(val: str) -> str:
    val = val.strip()
    try:
        return str(ipaddress.ip_address(val))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address '{val}': {exc}") from exc


# --- Auth & User Schemas ---

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=4, max_length=128)


class UserRead(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., min_length=5, max_length=255)
    full_name: str = Field(..., min_length=2, max_length=128)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="analyst")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        r = v.strip().lower()
        if r not in {"admin", "analyst", "soc_lead", "viewer"}:
            raise ValueError("Role must be 'admin', 'analyst', 'soc_lead', or 'viewer'.")
        return r


class UserUpdate(BaseModel):
    email: Optional[str] = Field(default=None, min_length=5, max_length=255)
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    role: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        r = v.strip().lower()
        if r not in {"admin", "analyst", "soc_lead", "viewer"}:
            raise ValueError("Role must be 'admin', 'analyst', 'soc_lead', or 'viewer'.")
        return r


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead


# --- Security Event Schemas ---

class SecurityEventCreate(BaseModel):
    model_config = ConfigDict(validate_default=True)

    event_id: Optional[str] = Field(default=None)
    timestamp: Optional[datetime] = Field(default=None)
    source_ip: str = Field(..., description="Valid IPv4 or IPv6 source address")
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    username: Optional[str] = Field(default=None, max_length=128)
    hostname: Optional[str] = Field(default=None, max_length=128)
    event_type: str = Field(..., min_length=1, max_length=128)
    event_category: str = Field(..., description="One of Authentication, Authorization, Network, Endpoint, System, Application")
    action: str = Field(..., min_length=1, max_length=128)
    status: str = Field(..., min_length=1, max_length=64)
    severity: str = Field(default="low")
    raw_log: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_synthetic: bool = Field(default=False)

    @model_validator(mode="before")
    @classmethod
    def normalize_input_payload(cls, data: Any) -> Any:
        if isinstance(data, cls):
            return data
        return normalize_raw_event_payload(data)

    @field_validator("event_id", mode="before")
    @classmethod
    def ensure_event_id(cls, v: Optional[str]) -> str:
        if not v or not str(v).strip():
            return f"EVT-{uuid.uuid4().hex[:16].upper()}"
        return str(v).strip()

    @field_validator("timestamp", mode="after")
    @classmethod
    def ensure_utc_timestamp(cls, v: Optional[datetime]) -> datetime:
        return normalize_utc(v)

    @field_validator("source_ip")
    @classmethod
    def check_source_ip(cls, v: str) -> str:
        return validate_ip_string(v)

    @field_validator("destination_ip")
    @classmethod
    def check_destination_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not str(v).strip():
            return None
        return validate_ip_string(str(v))

    @field_validator("username")
    @classmethod
    def check_username(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = str(v).strip()
        if not cleaned:
            return None
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned) or any(ch in cleaned for ch in (" ", "\t", ";", "'", '"')):
            raise ValueError(f"Invalid username '{cleaned}': contains whitespace or forbidden characters.")
        return cleaned

    @field_validator("event_category")
    @classmethod
    def check_category(cls, v: str) -> str:
        norm = VALID_CATEGORIES.get(v.strip().lower())
        if not norm:
            raise ValueError(
                f"Unsupported event_category '{v}'. Allowed: {list(VALID_CATEGORIES.values())}"
            )
        return norm

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Unsupported severity '{v}'. Allowed: {sorted(VALID_SEVERITIES)}")
        return s

    @field_validator("status")
    @classmethod
    def check_status(cls, v: str) -> str:
        return v.strip().lower()


class BulkEventIngestRequest(BaseModel):
    events: List[Any] = Field(..., min_length=1, max_length=5000)
    run_detections: bool = True


class SecurityEventRead(BaseModel):
    id: int
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    event_type: str
    event_category: str
    action: str
    status: str
    severity: str
    raw_log: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_synthetic: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BulkEventIngestResponse(BaseModel):
    accepted_count: int
    rejected_count: int
    duplicate_count: int
    generated_alerts_count: int
    generated_alert_ids: List[str] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)


class PaginatedEventsResponse(BaseModel):
    items: List[SecurityEventRead]
    total: int
    page: int
    page_size: int
    total_pages: int


# --- Detection Rule Schemas ---

class DetectionRuleCreate(BaseModel):
    rule_id: str = Field(..., min_length=3, max_length=32)
    rule_key: str = Field(..., min_length=3, max_length=64)
    name: str = Field(..., min_length=3, max_length=160)
    description: str = Field(..., min_length=3)
    detection_logic: str = Field(..., min_length=3)
    event_category: str = Field(..., description="One of Authentication, Authorization, Network, Endpoint, System, Application")
    threshold_count: int = Field(default=5, ge=1, le=10000)
    time_window_seconds: int = Field(default=300, ge=10, le=86400)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    severity: str = Field(default="high")
    enabled: bool = Field(default=True)
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None

    @field_validator("event_category")
    @classmethod
    def check_rule_category(cls, v: str) -> str:
        norm = VALID_CATEGORIES.get(v.strip().lower())
        if not norm:
            raise ValueError(
                f"Unsupported event_category '{v}'. Allowed: {list(VALID_CATEGORIES.values())}"
            )
        return norm

    @field_validator("severity")
    @classmethod
    def check_rule_severity(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Unsupported severity '{v}'. Allowed: {sorted(VALID_SEVERITIES)}")
        return s


class DetectionRuleRead(BaseModel):
    id: int
    rule_id: str
    rule_key: str
    name: str
    description: str
    detection_logic: str
    event_category: str
    threshold_count: int
    time_window_seconds: int
    parameters: Dict[str, Any] = Field(default_factory=dict)
    severity: str
    enabled: bool
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    alert_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=160)
    description: Optional[str] = None
    threshold_count: Optional[int] = Field(default=None, ge=1, le=10000)
    time_window_seconds: Optional[int] = Field(default=None, ge=10, le=86400)
    parameters: Optional[Dict[str, Any]] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator("severity")
    @classmethod
    def validate_sev(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'")
        return s


# --- Alert Schemas ---

class AlertCreate(BaseModel):
    alert_id: Optional[str] = None
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=3)
    severity: str = Field(default="high")
    status: str = Field(default="New")
    rule_id_fk: Optional[int] = None
    rule_code: str = Field(default="MANUAL-001", min_length=2, max_length=32)
    rule_name: str = Field(default="Manual SOC Alert", min_length=2, max_length=160)
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    assigned_to: Optional[str] = None
    event_ids: List[int] = Field(default_factory=list)
    is_synthetic: bool = False

    @field_validator("severity")
    @classmethod
    def check_alert_sev(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed: {sorted(VALID_SEVERITIES)}")
        return s

    @field_validator("status")
    @classmethod
    def check_alert_st(cls, v: str) -> str:
        if v not in VALID_ALERT_STATUSES:
            raise ValueError(f"Invalid status '{v}'. Allowed: {sorted(VALID_ALERT_STATUSES)}")
        return v


class AlertEvidenceCreate(BaseModel):
    event_id: int = Field(..., ge=1)
    evidence_role: str = Field(default="triggering_event", min_length=2, max_length=64)
    note: Optional[str] = Field(default=None, max_length=255)


class AlertEvidenceRead(BaseModel):
    id: int
    alert_id: int
    event_id: int
    evidence_role: str
    note: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationNoteRead(BaseModel):
    id: int
    alert_id: Optional[int] = None
    incident_id: Optional[int] = None
    author: str
    content: str
    note_type: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatusHistoryRead(BaseModel):
    id: int
    alert_id: int
    previous_status: Optional[str] = None
    new_status: str
    changed_by: str
    comment: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertRead(BaseModel):
    id: int
    alert_id: str
    title: str
    description: str
    severity: str
    status: str
    rule_id_fk: Optional[int] = None
    rule_code: str
    rule_name: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    assigned_to: Optional[str] = None
    is_synthetic: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertDetailRead(AlertRead):
    evidence_events: List[SecurityEventRead] = Field(default_factory=list)
    notes: List[InvestigationNoteRead] = Field(default_factory=list)
    status_history: List[AlertStatusHistoryRead] = Field(default_factory=list)
    linked_incident_ids: List[str] = Field(default_factory=list)


class AlertStatusUpdate(BaseModel):
    status: str
    comment: Optional[str] = None
    assigned_to: Optional[str] = None

    @field_validator("status")
    @classmethod
    def check_alert_status(cls, v: str) -> str:
        if v not in VALID_ALERT_STATUSES:
            raise ValueError(f"Invalid status '{v}'. Must be one of {sorted(VALID_ALERT_STATUSES)}")
        return v


class NoteCreateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000)
    note_type: str = Field(default="analyst_note")


class PaginatedAlertsResponse(BaseModel):
    items: List[AlertRead]
    total: int
    page: int
    page_size: int
    total_pages: int


# --- Incident Schemas ---

class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    severity: str = Field(default="high")
    status: Optional[str] = Field(default=None)
    description: str = Field(..., min_length=3)
    assigned_analyst: Optional[str] = None
    alert_ids: List[Union[int, str]] = Field(default_factory=list, description="Database IDs or alert codes to link")
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def check_inc_sev(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'")
        return s

    @field_validator("status")
    @classmethod
    def check_inc_create_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if v not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid incident status '{v}'. Allowed: {sorted(VALID_INCIDENT_STATUSES)}")
        return v


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    assigned_analyst: Optional[str] = None
    resolution_summary: Optional[str] = None
    evidence_references: Optional[List[Dict[str, Any]]] = None
    comment: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def check_inc_update_sev(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'")
        return s

    @field_validator("status")
    @classmethod
    def check_inc_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if v not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid incident status '{v}'. Allowed: {sorted(VALID_INCIDENT_STATUSES)}")
        return v


class IncidentStatusUpdate(BaseModel):
    status: str
    comment: Optional[str] = None
    assigned_analyst: Optional[str] = None
    resolution_summary: Optional[str] = None

    @field_validator("status")
    @classmethod
    def check_inc_st(cls, v: str) -> str:
        if v not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid incident status '{v}'. Allowed: {sorted(VALID_INCIDENT_STATUSES)}")
        return v


class IncidentLinkAlertsRequest(BaseModel):
    alert_ids: List[Union[int, str]] = Field(..., min_length=1)


class IncidentEvidenceCreate(BaseModel):
    type: str = Field(default="event", min_length=2, max_length=64)
    reference: Optional[str] = Field(default=None, max_length=255)
    event_id: Optional[Union[int, str]] = None
    alert_id: Optional[Union[int, str]] = None
    description: Optional[str] = Field(default=None, max_length=1000)
    note: Optional[str] = Field(default=None, max_length=1000)


class IncidentTimelineEntryCreate(BaseModel):
    action: str = Field(..., min_length=2, max_length=128)
    detail: str = Field(..., min_length=2, max_length=2000)


class IncidentRead(BaseModel):
    id: int
    incident_id: str
    title: str
    severity: str
    status: str
    description: str
    assigned_analyst: Optional[str] = None
    timeline_events: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    resolution_summary: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_by: Optional[str] = None
    linked_alert_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    related_alerts: List[AlertRead] = Field(default_factory=list)
    related_events: List[SecurityEventRead] = Field(default_factory=list)
    notes: List[InvestigationNoteRead] = Field(default_factory=list)
    status_history: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)


class PaginatedIncidentsResponse(BaseModel):
    items: List[IncidentRead]
    total: int
    page: int
    page_size: int
    total_pages: int


# --- Threat Intelligence Schemas ---

class ThreatIndicatorCreate(BaseModel):
    indicator_type: str = Field(default="ip")
    indicator_value: str = Field(..., min_length=2, max_length=255)
    threat_type: str = Field(..., min_length=2, max_length=64)
    severity: str = Field(default="high")
    confidence: int = Field(default=85, ge=0, le=100)
    source: str = Field(default="Manual SOC Entry", min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    tags: List[str] = Field(default_factory=list)
    is_active: bool = True

    @field_validator("indicator_type")
    @classmethod
    def check_ioc_type(cls, v: str) -> str:
        t = v.strip().lower()
        if t not in {"ip", "domain", "hash", "url", "cidr"}:
            raise ValueError("indicator_type must be one of: ip, domain, hash, url, cidr")
        return t

    @field_validator("severity")
    @classmethod
    def check_ioc_create_sev(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed: {sorted(VALID_SEVERITIES)}")
        return s

    @model_validator(mode="after")
    def validate_indicator_value_format(self) -> "ThreatIndicatorCreate":
        val = self.indicator_value.strip()
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in val):
            raise ValueError("indicator_value contains invalid control characters.")
        if self.indicator_type == "ip":
            self.indicator_value = validate_ip_string(val)
        elif self.indicator_type == "cidr":
            try:
                self.indicator_value = str(ipaddress.ip_network(val, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR network '{val}': {exc}") from exc
        else:
            self.indicator_value = val
        return self


class ThreatIndicatorRead(BaseModel):
    id: int
    indicator_type: str
    indicator_value: str
    threat_type: str
    severity: str
    confidence: int
    source: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    is_active: bool
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatIndicatorUpdate(BaseModel):
    threat_type: Optional[str] = Field(default=None, min_length=2, max_length=64)
    severity: Optional[str] = None
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    source: Optional[str] = Field(default=None, min_length=2, max_length=128)
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None

    @field_validator("severity")
    @classmethod
    def check_ioc_sev(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = v.strip().lower()
        if s not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed: {sorted(VALID_SEVERITIES)}")
        return s


class ThreatProviderConfigUpdate(BaseModel):
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    enable_external_lookup: bool = True


# --- Audit Log Schemas ---

class AuditLogRead(BaseModel):
    id: int
    actor_username: str
    actor_role: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
