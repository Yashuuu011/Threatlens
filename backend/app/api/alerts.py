from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.deps import get_actor_or_default, require_actor_roles
from app.core.database import get_db
from app.core.websocket import broadcast_sync_or_async
from app.ingestion.pipeline import serialize_event
from app.models.entities import (
    Alert,
    AlertEvidence,
    AlertStatusHistory,
    Incident,
    IncidentAlert,
    InvestigationNote,
    SecurityEvent,
    User,
)
from app.schemas.api_schemas import (
    AlertCreate,
    AlertDetailRead,
    AlertEvidenceCreate,
    AlertEvidenceRead,
    AlertRead,
    AlertStatusHistoryRead,
    AlertStatusUpdate,
    InvestigationNoteRead,
    NoteCreateRequest,
    PaginatedAlertsResponse,
)
from app.services.audit import record_audit_log

router = APIRouter(prefix="/api/alerts", tags=["Alerts Management"])


def _resolve_alert(db: Session, identifier: str) -> Alert:
    alert: Optional[Alert] = None
    if identifier.isdigit():
        alert = db.query(Alert).filter(Alert.id == int(identifier)).first()
    if not alert:
        alert = db.query(Alert).filter(Alert.alert_id == identifier).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{identifier}' not found.",
        )
    return alert


@router.get("", response_model=PaginatedAlertsResponse)
def list_alerts(
    search: Optional[str] = Query(default=None, description="Search title, alert_id, source_ip, username, or rule"),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    rule_code: Optional[str] = Query(default=None),
    sort_by: str = Query(
        default="last_seen",
        pattern="^(last_seen|first_seen|severity|status|event_count|rule_code|source_ip|alert_id|created_at)$",
    ),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
) -> PaginatedAlertsResponse:
    query = db.query(Alert)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Alert.alert_id.ilike(term),
                Alert.title.ilike(term),
                Alert.description.ilike(term),
                Alert.source_ip.ilike(term),
                Alert.username.ilike(term),
                Alert.rule_code.ilike(term),
                Alert.rule_name.ilike(term),
                Alert.mitre_technique_id.ilike(term),
            )
        )

    if severity and severity.strip() and severity.lower() != "all":
        query = query.filter(Alert.severity == severity.strip().lower())
    if status_filter and status_filter.strip() and status_filter.lower() != "all":
        query = query.filter(Alert.status == status_filter.strip())
    if rule_code and rule_code.strip() and rule_code.lower() != "all":
        query = query.filter(Alert.rule_code == rule_code.strip())

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    sort_col = getattr(Alert, sort_by, Alert.last_seen)
    order_col = sort_col.asc() if sort_order == "asc" else sort_col.desc()
    rows = query.order_by(order_col, Alert.id.desc()).offset(offset).limit(page_size).all()

    return PaginatedAlertsResponse(
        items=[AlertRead.model_validate(a) for a in rows],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{alert_identifier}", response_model=AlertDetailRead)
def get_alert_detail(
    alert_identifier: str,
    db: Session = Depends(get_db),
) -> AlertDetailRead:
    alert = _resolve_alert(db, alert_identifier)

    evidence_events_objs = (
        db.query(SecurityEvent)
        .join(AlertEvidence, AlertEvidence.event_id == SecurityEvent.id)
        .filter(AlertEvidence.alert_id == alert.id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )
    linked_incidents = (
        db.query(Incident.incident_id)
        .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
        .filter(IncidentAlert.alert_id == alert.id)
        .all()
    )

    base_data = AlertRead.model_validate(alert).model_dump()
    return AlertDetailRead(
        **base_data,
        evidence_events=[serialize_event(ev) for ev in evidence_events_objs],
        notes=[InvestigationNoteRead.model_validate(n) for n in alert.notes],
        status_history=[AlertStatusHistoryRead.model_validate(h) for h in alert.status_history],
        linked_incident_ids=[row[0] for row in linked_incidents],
    )


@router.patch("/{alert_identifier}/status", response_model=AlertDetailRead)
def update_alert_status(
    alert_identifier: str,
    payload: AlertStatusUpdate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> AlertDetailRead:
    alert = _resolve_alert(db, alert_identifier)
    prev_status = alert.status
    alert.status = payload.status
    if payload.assigned_to is not None:
        alert.assigned_to = payload.assigned_to.strip() or None

    history_entry = AlertStatusHistory(
        alert_id=alert.id,
        previous_status=prev_status,
        new_status=payload.status,
        changed_by=actor.username,
        comment=payload.comment or f"Status transitioned from {prev_status} to {payload.status}",
    )
    db.add(history_entry)

    if payload.comment and payload.comment.strip():
        db.add(
            InvestigationNote(
                alert_id=alert.id,
                author=actor.username,
                content=f"[Status -> {payload.status}] {payload.comment.strip()}",
                note_type="status_change",
            )
        )

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="alert_status_updated",
        resource_type="alert",
        resource_id=alert.alert_id,
        ip_address=request.client.host if request.client else None,
        details={
            "previous_status": prev_status,
            "new_status": payload.status,
            "comment": payload.comment,
        },
        commit=False,
    )
    db.commit()
    db.refresh(alert)

    broadcast_sync_or_async(
        "alert_status_updated",
        {
            "id": alert.id,
            "alert_id": alert.alert_id,
            "previous_status": prev_status,
            "status": alert.status,
            "changed_by": actor.username,
        },
    )

    return get_alert_detail(alert_identifier=str(alert.id), db=db)


@router.post("/{alert_identifier}/notes", response_model=InvestigationNoteRead, status_code=status.HTTP_201_CREATED)
def add_alert_note(
    alert_identifier: str,
    payload: NoteCreateRequest,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> InvestigationNoteRead:
    alert = _resolve_alert(db, alert_identifier)
    note = InvestigationNote(
        alert_id=alert.id,
        author=actor.username,
        content=payload.content.strip(),
        note_type=payload.note_type,
    )
    db.add(note)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="alert_note_added",
        resource_type="alert",
        resource_id=alert.alert_id,
        ip_address=request.client.host if request.client else None,
        details={"note_type": payload.note_type},
        commit=False,
    )
    db.commit()
    db.refresh(note)
    return InvestigationNoteRead.model_validate(note)


@router.post("", response_model=AlertDetailRead, status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> AlertDetailRead:
    now = datetime.now(timezone.utc)
    alert_code = payload.alert_id or f"ALT-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    alert = Alert(
        alert_id=alert_code,
        title=payload.title.strip(),
        description=payload.description.strip(),
        severity=payload.severity,
        status=payload.status,
        rule_id_fk=payload.rule_id_fk,
        rule_code=payload.rule_code.strip(),
        rule_name=payload.rule_name.strip(),
        source_ip=payload.source_ip,
        username=payload.username,
        hostname=payload.hostname,
        first_seen=now,
        last_seen=now,
        event_count=max(1, len(payload.event_ids)),
        dedup_key=f"manual:{alert_code}",
        mitre_tactic=payload.mitre_tactic,
        mitre_technique_id=payload.mitre_technique_id,
        mitre_technique_name=payload.mitre_technique_name,
        evidence_summary=payload.evidence_summary or {},
        assigned_to=payload.assigned_to,
        is_synthetic=payload.is_synthetic,
    )
    db.add(alert)
    db.flush()

    db.add(
        AlertStatusHistory(
            alert_id=alert.id,
            previous_status=None,
            new_status=alert.status,
            changed_by=actor.username,
            comment="Alert created via API.",
        )
    )

    for ev_id in payload.event_ids:
        ev = db.query(SecurityEvent).filter(SecurityEvent.id == ev_id).first()
        if ev:
            db.add(
                AlertEvidence(
                    alert_id=alert.id,
                    event_id=ev.id,
                    evidence_role="triggering_event",
                )
            )

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="alert_created",
        resource_type="alert",
        resource_id=alert.alert_id,
        ip_address=request.client.host if request.client else None,
        details={"severity": alert.severity, "rule_code": alert.rule_code},
        commit=False,
    )
    db.commit()
    db.refresh(alert)
    return get_alert_detail(alert_identifier=str(alert.id), db=db)


@router.get("/{alert_identifier}/evidence", response_model=List[AlertEvidenceRead])
def list_alert_evidence(
    alert_identifier: str,
    db: Session = Depends(get_db),
) -> List[AlertEvidenceRead]:
    alert = _resolve_alert(db, alert_identifier)
    items = (
        db.query(AlertEvidence)
        .filter(AlertEvidence.alert_id == alert.id)
        .order_by(AlertEvidence.id.asc())
        .all()
    )
    return [AlertEvidenceRead.model_validate(i) for i in items]


@router.post("/{alert_identifier}/evidence", response_model=AlertEvidenceRead, status_code=status.HTTP_201_CREATED)
def add_alert_evidence(
    alert_identifier: str,
    payload: AlertEvidenceCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> AlertEvidenceRead:
    alert = _resolve_alert(db, alert_identifier)
    ev = db.query(SecurityEvent).filter(SecurityEvent.id == payload.event_id).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event {payload.event_id} not found.",
        )
    existing = (
        db.query(AlertEvidence)
        .filter(AlertEvidence.alert_id == alert.id, AlertEvidence.event_id == ev.id)
        .first()
    )
    if existing:
        return AlertEvidenceRead.model_validate(existing)

    link = AlertEvidence(
        alert_id=alert.id,
        event_id=ev.id,
        evidence_role=payload.evidence_role,
        note=payload.note,
    )
    db.add(link)
    alert.event_count = (alert.event_count or 0) + 1
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="alert_evidence_linked",
        resource_type="alert_evidence",
        resource_id=f"{alert.alert_id}:{ev.event_id}",
        ip_address=request.client.host if request.client else None,
        commit=False,
    )
    db.commit()
    db.refresh(link)
    return AlertEvidenceRead.model_validate(link)


@router.get("/{alert_identifier}/history", response_model=List[AlertStatusHistoryRead])
def list_alert_status_history(
    alert_identifier: str,
    db: Session = Depends(get_db),
) -> List[AlertStatusHistoryRead]:
    alert = _resolve_alert(db, alert_identifier)
    return [AlertStatusHistoryRead.model_validate(h) for h in alert.status_history]


@router.get("/{alert_identifier}/notes", response_model=List[InvestigationNoteRead])
def list_alert_notes(
    alert_identifier: str,
    db: Session = Depends(get_db),
) -> List[InvestigationNoteRead]:
    alert = _resolve_alert(db, alert_identifier)
    return [InvestigationNoteRead.model_validate(n) for n in alert.notes]


@router.delete("/{alert_identifier}")
def delete_alert(
    alert_identifier: str,
    request: Request,
    actor: User = Depends(require_actor_roles("admin")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    alert = _resolve_alert(db, alert_identifier)
    al_code = alert.alert_id
    db.delete(alert)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="alert_deleted",
        resource_type="alert",
        resource_id=al_code,
        ip_address=request.client.host if request.client else None,
        commit=False,
    )
    db.commit()
    return {"deleted": True, "alert_id": al_code}


