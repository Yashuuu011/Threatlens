from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_actor_or_default, require_actor_roles
from app.api.detections import MITRE_TACTIC_IDS
from app.core.database import get_db
from app.core.websocket import broadcast_sync_or_async
from app.ingestion.pipeline import serialize_event
from app.models.entities import (
    Alert,
    AlertEvidence,
    AlertStatusHistory,
    DetectionRule,
    Incident,
    IncidentAlert,
    InvestigationNote,
    SecurityEvent,
    User,
)
from app.schemas.api_schemas import (
    AlertRead,
    IncidentCreate,
    IncidentDetailRead,
    IncidentEvidenceCreate,
    IncidentLinkAlertsRequest,
    IncidentRead,
    IncidentStatusUpdate,
    IncidentTimelineEntryCreate,
    IncidentUpdate,
    InvestigationNoteRead,
    NoteCreateRequest,
    PaginatedIncidentsResponse,
    SecurityEventRead,
)
from app.services.audit import record_audit_log

router = APIRouter(prefix="/api/incidents", tags=["Incident Investigation"])


def _resolve_incident(db: Session, identifier: str) -> Incident:
    inc: Optional[Incident] = None
    if identifier.isdigit():
        inc = db.query(Incident).filter(Incident.id == int(identifier)).first()
    if not inc:
        inc = db.query(Incident).filter(Incident.incident_id == identifier).first()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{identifier}' not found.",
        )
    return inc


def _resolve_alert_list(
    db: Session,
    identifiers: Sequence[Union[int, str]],
) -> List[Alert]:
    resolved: List[Alert] = []
    seen_ids: Set[int] = set()
    for raw_id in identifiers:
        al: Optional[Alert] = None
        if isinstance(raw_id, int) or (isinstance(raw_id, str) and raw_id.strip().isdigit()):
            al = db.query(Alert).filter(Alert.id == int(raw_id)).first()
        if not al and isinstance(raw_id, str) and raw_id.strip():
            al = db.query(Alert).filter(Alert.alert_id == raw_id.strip()).first()
        if al and al.id not in seen_ids:
            seen_ids.add(al.id)
            resolved.append(al)
    return resolved


def _collect_events_for_alerts(
    db: Session,
    alert_db_ids: Sequence[int],
) -> List[SecurityEvent]:
    if not alert_db_ids:
        return []
    event_id_subq = (
        db.query(AlertEvidence.event_id)
        .filter(AlertEvidence.alert_id.in_(list(alert_db_ids)))
    )
    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id.in_(event_id_subq))
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )


def _merge_evidence_references(
    existing_refs: Optional[List[Dict[str, Any]]],
    linked_alerts: Sequence[Alert],
    linked_events: Sequence[SecurityEvent],
    actor_username: str,
    now_iso: str,
) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str]] = set()

    for r in existing_refs or []:
        if isinstance(r, dict):
            r_type = str(r.get("type") or "artifact").lower()
            r_ref = str(r.get("reference") or "").strip()
            if r_ref and (r_type, r_ref) not in seen_keys:
                seen_keys.add((r_type, r_ref))
                refs.append(dict(r))

    for al in linked_alerts:
        key = ("alert", al.alert_id)
        if key not in seen_keys:
            seen_keys.add(key)
            refs.append(
                {
                    "type": "alert",
                    "reference": al.alert_id,
                    "alert_id": al.id,
                    "rule_code": al.rule_code,
                    "mitre_technique_id": al.mitre_technique_id,
                    "description": f"{al.rule_code}: {al.title}",
                    "added_by": actor_username,
                    "added_at": now_iso,
                }
            )

    for ev in linked_events:
        key = ("event", ev.event_id)
        if key not in seen_keys:
            seen_keys.add(key)
            refs.append(
                {
                    "type": "event",
                    "reference": ev.event_id,
                    "event_id": ev.id,
                    "source_ip": ev.source_ip,
                    "event_category": ev.event_category,
                    "description": f"{ev.event_category}/{ev.event_type} from {ev.source_ip} ({ev.status})",
                    "added_by": actor_username,
                    "added_at": now_iso,
                }
            )

    return refs


def _extract_status_history(inc: Incident) -> List[Dict[str, Any]]:
    history: List[Dict[str, Any]] = []
    for item in inc.timeline_events or []:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action") or "")
        if "new_status" in item:
            history.append(
                {
                    "previous_status": item.get("previous_status"),
                    "new_status": item.get("new_status"),
                    "changed_by": item.get("actor") or inc.created_by or "analyst",
                    "comment": item.get("comment") or item.get("detail"),
                    "timestamp": item.get("timestamp") or (inc.created_at.isoformat() if inc.created_at else ""),
                }
            )
        elif action in ("Incident Created", "Incident Opened") and not history:
            history.append(
                {
                    "previous_status": None,
                    "new_status": item.get("new_status") or "Open",
                    "changed_by": item.get("actor") or inc.created_by or "analyst",
                    "comment": item.get("detail") or "Incident created.",
                    "timestamp": item.get("timestamp") or (inc.created_at.isoformat() if inc.created_at else ""),
                }
            )

    if not history:
        history.append(
            {
                "previous_status": None,
                "new_status": inc.status,
                "changed_by": inc.created_by or "analyst",
                "comment": "Initial incident state.",
                "timestamp": inc.created_at.isoformat() if inc.created_at else datetime.now(timezone.utc).isoformat(),
            }
        )
    return history


def _build_incident_mitre_mappings(
    db: Session,
    related_alerts: Sequence[Alert],
) -> List[Dict[str, Any]]:
    if not related_alerts:
        return []

    rule_codes = list({a.rule_code for a in related_alerts if a.rule_code})
    rules_by_code: Dict[str, DetectionRule] = {}
    if rule_codes:
        rules = db.query(DetectionRule).filter(DetectionRule.rule_id.in_(rule_codes)).all()
        rules_by_code = {r.rule_id: r for r in rules}

    grouped: Dict[str, Dict[str, Any]] = {}
    for al in related_alerts:
        r = rules_by_code.get(al.rule_code)
        tactic = (r.mitre_tactic if r and r.mitre_tactic else al.mitre_tactic) or "Unclassified"
        tech_id = (r.mitre_technique_id if r and r.mitre_technique_id else al.mitre_technique_id) or ""
        tech_name = (
            r.mitre_technique_name
            if r and r.mitre_technique_name
            else al.mitre_technique_name
        ) or al.rule_name
        key = f"{tactic}:{tech_id or al.rule_code}"

        if key not in grouped:
            mitre_url = (
                f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
                if tech_id
                else "https://attack.mitre.org/"
            )
            grouped[key] = {
                "tactic": tactic,
                "mitre_tactic": tactic,
                "tactic_id": MITRE_TACTIC_IDS.get(tactic, "TA0000"),
                "technique_id": tech_id,
                "mitre_technique_id": tech_id,
                "technique_name": tech_name,
                "mitre_technique_name": tech_name,
                "reference_url": mitre_url,
                "associated_rules": [],
                "related_alerts": [],
                "_seen_rules": set(),
            }

        entry = grouped[key]
        if al.rule_code not in entry["_seen_rules"]:
            entry["_seen_rules"].add(al.rule_code)
            entry["associated_rules"].append(
                {
                    "id": r.id if r else al.rule_id_fk,
                    "rule_id": al.rule_code,
                    "name": r.name if r else al.rule_name,
                    "severity": r.severity if r else al.severity,
                    "enabled": r.enabled if r else True,
                }
            )
        entry["related_alerts"].append(
            {
                "id": al.id,
                "alert_id": al.alert_id,
                "title": al.title,
                "severity": al.severity,
                "status": al.status,
                "rule_code": al.rule_code,
                "source_ip": al.source_ip,
                "username": al.username,
                "last_seen": al.last_seen.isoformat() if al.last_seen else None,
            }
        )

    result: List[Dict[str, Any]] = []
    for item in grouped.values():
        item.pop("_seen_rules", None)
        item["rule"] = item["associated_rules"][0] if item["associated_rules"] else None
        item["alert_count"] = len(item["related_alerts"])
        result.append(item)
    return result


def _serialize_incident(inc: Incident) -> IncidentRead:
    return IncidentRead(
        id=inc.id,
        incident_id=inc.incident_id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        description=inc.description,
        assigned_analyst=inc.assigned_analyst,
        timeline_events=inc.timeline_events or [],
        evidence_references=inc.evidence_references or [],
        resolution_summary=inc.resolution_summary,
        resolved_at=inc.resolved_at,
        created_by=inc.created_by,
        linked_alert_count=len(inc.alert_links),
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.get("", response_model=PaginatedIncidentsResponse)
def list_incidents(
    search: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    assigned_analyst: Optional[str] = Query(default=None),
    sort_by: str = Query(
        default="created_at",
        pattern="^(created_at|updated_at|severity|status|incident_id|title)$",
    ),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> PaginatedIncidentsResponse:
    query = db.query(Incident)
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Incident.incident_id.ilike(term),
                Incident.title.ilike(term),
                Incident.description.ilike(term),
                Incident.assigned_analyst.ilike(term),
            )
        )
    if severity and severity.strip() and severity.lower() != "all":
        query = query.filter(Incident.severity == severity.strip().lower())
    if status_filter and status_filter.strip() and status_filter.lower() != "all":
        query = query.filter(Incident.status == status_filter.strip())
    if assigned_analyst and assigned_analyst.strip() and assigned_analyst.lower() != "all":
        query = query.filter(Incident.assigned_analyst.ilike(f"%{assigned_analyst.strip()}%"))

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    sort_col = getattr(Incident, sort_by, Incident.created_at)
    order_col = sort_col.asc() if sort_order == "asc" else sort_col.desc()
    rows = query.order_by(order_col, Incident.id.desc()).offset(offset).limit(page_size).all()

    return PaginatedIncidentsResponse(
        items=[_serialize_incident(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("", response_model=IncidentDetailRead, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    count = db.query(Incident).count() + 1
    inc_code = f"INC-{now.strftime('%Y')}-{count:04d}-{uuid.uuid4().hex[:3].upper()}"

    initial_status = payload.status or "Open"
    assigned = (payload.assigned_analyst.strip() if payload.assigned_analyst else None) or actor.username

    timeline: List[Dict[str, Any]] = [
        {
            "timestamp": now_iso,
            "actor": actor.username,
            "action": "Incident Created",
            "previous_status": None,
            "new_status": initial_status,
            "detail": f"Opened incident '{payload.title.strip()}' with status '{initial_status}' and severity '{payload.severity}'.",
        }
    ]

    if assigned:
        timeline.append(
            {
                "timestamp": now_iso,
                "actor": actor.username,
                "action": "Analyst Assigned",
                "previous_analyst": None,
                "new_analyst": assigned,
                "detail": f"Assigned incident investigation to analyst '{assigned}'.",
            }
        )

    linked_alerts = _resolve_alert_list(db, payload.alert_ids) if payload.alert_ids else []
    linked_events = _collect_events_for_alerts(db, [a.id for a in linked_alerts])

    evidence_refs = _merge_evidence_references(
        existing_refs=payload.evidence_references,
        linked_alerts=linked_alerts,
        linked_events=linked_events,
        actor_username=actor.username,
        now_iso=now_iso,
    )

    if linked_alerts:
        timeline.append(
            {
                "timestamp": now_iso,
                "actor": actor.username,
                "action": "Alerts Linked",
                "detail": (
                    f"Associated {len(linked_alerts)} alert(s): {', '.join(a.alert_id for a in linked_alerts)} "
                    f"({len(linked_events)} correlated security event(s))."
                ),
            }
        )

    incident = Incident(
        incident_id=inc_code,
        title=payload.title.strip(),
        severity=payload.severity,
        status=initial_status,
        description=payload.description.strip(),
        assigned_analyst=assigned,
        timeline_events=timeline,
        evidence_references=evidence_refs,
        resolved_at=now if initial_status in ("Resolved", "Closed") else None,
        created_by=actor.username,
    )
    db.add(incident)
    db.flush()

    for al in linked_alerts:
        db.add(
            IncidentAlert(
                incident_id=incident.id,
                alert_id=al.id,
                linked_by=actor.username,
            )
        )
        if al.status == "New":
            prev_al_status = al.status
            al.status = "Investigating"
            db.add(
                AlertStatusHistory(
                    alert_id=al.id,
                    previous_status=prev_al_status,
                    new_status="Investigating",
                    changed_by=actor.username,
                    comment=f"Escalated and associated with incident {inc_code}",
                )
            )

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_created",
        resource_type="incident",
        resource_id=incident.incident_id,
        ip_address=request.client.host if request.client else None,
        details={
            "title": incident.title,
            "status": incident.status,
            "assigned_analyst": incident.assigned_analyst,
            "linked_alert_ids": [a.alert_id for a in linked_alerts],
        },
        commit=False,
    )
    db.commit()
    db.refresh(incident)

    broadcast_sync_or_async(
        "incident_created",
        _serialize_incident(incident).model_dump(mode="json"),
    )

    return get_incident_detail(incident_identifier=str(incident.id), db=db)


@router.get("/{incident_identifier}", response_model=IncidentDetailRead)
def get_incident_detail(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)

    related_alerts = (
        db.query(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .filter(IncidentAlert.incident_id == inc.id)
        .order_by(Alert.last_seen.desc())
        .all()
    )

    alert_db_ids = [a.id for a in related_alerts]
    related_events_map: Dict[int, SecurityEvent] = {
        ev.id: ev for ev in _collect_events_for_alerts(db, alert_db_ids)
    }

    # Also include any SecurityEvents directly referenced in evidence_references
    for ref in inc.evidence_references or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("type") or "").lower() == "event":
            ev_obj: Optional[SecurityEvent] = None
            ev_id_val = ref.get("event_id")
            ref_code = str(ref.get("reference") or "").strip()
            if isinstance(ev_id_val, int):
                ev_obj = db.query(SecurityEvent).filter(SecurityEvent.id == ev_id_val).first()
            if not ev_obj and ref_code:
                if ref_code.isdigit():
                    ev_obj = db.query(SecurityEvent).filter(SecurityEvent.id == int(ref_code)).first()
                if not ev_obj:
                    ev_obj = db.query(SecurityEvent).filter(SecurityEvent.event_id == ref_code).first()
            if ev_obj:
                related_events_map[ev_obj.id] = ev_obj

    related_events = sorted(related_events_map.values(), key=lambda e: e.timestamp)

    # Ensure evidence_references includes all linked alerts and events
    merged_refs = _merge_evidence_references(
        existing_refs=inc.evidence_references,
        linked_alerts=related_alerts,
        linked_events=related_events,
        actor_username=inc.created_by or "analyst",
        now_iso=inc.updated_at.isoformat() if inc.updated_at else datetime.now(timezone.utc).isoformat(),
    )

    base_data = _serialize_incident(inc).model_dump()
    base_data["evidence_references"] = merged_refs

    return IncidentDetailRead(
        **base_data,
        related_alerts=[AlertRead.model_validate(a) for a in related_alerts],
        related_events=[serialize_event(ev) for ev in related_events],
        notes=[InvestigationNoteRead.model_validate(n) for n in inc.notes],
        status_history=_extract_status_history(inc),
        mitre_mappings=_build_incident_mitre_mappings(db, related_alerts),
    )


def _apply_incident_updates(
    db: Session,
    inc: Incident,
    payload: IncidentUpdate,
    actor: User,
    request: Request,
) -> IncidentDetailRead:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    timeline = list(inc.timeline_events or [])
    changes: List[str] = []
    other_changes: List[str] = []

    if payload.title is not None and payload.title.strip() and payload.title.strip() != inc.title:
        inc.title = payload.title.strip()
        changes.append(f"title updated to '{inc.title}'")
        other_changes.append(f"title updated to '{inc.title}'")

    if payload.severity is not None and payload.severity.lower() != inc.severity:
        inc.severity = payload.severity.lower()
        changes.append(f"severity changed to '{inc.severity}'")
        other_changes.append(f"severity changed to '{inc.severity}'")

    if payload.assigned_analyst is not None:
        new_assignee = payload.assigned_analyst.strip() or None
        if new_assignee != inc.assigned_analyst:
            prev_assignee = inc.assigned_analyst
            inc.assigned_analyst = new_assignee
            assign_msg = f"Assigned analyst changed from '{prev_assignee or 'unassigned'}' to '{new_assignee or 'unassigned'}'"
            changes.append(assign_msg)
            timeline.append(
                {
                    "timestamp": now_iso,
                    "actor": actor.username,
                    "action": "Analyst Assigned",
                    "previous_analyst": prev_assignee,
                    "new_analyst": new_assignee,
                    "detail": assign_msg,
                }
            )

    if payload.status is not None and payload.status != inc.status:
        prev_st = inc.status
        inc.status = payload.status
        comment_suffix = f" ({payload.comment.strip()})" if (payload.comment and payload.comment.strip()) else ""
        status_msg = f"Status transitioned from '{prev_st}' to '{inc.status}'{comment_suffix}"
        changes.append(status_msg)
        if inc.status in ("Resolved", "Closed"):
            inc.resolved_at = now
        else:
            inc.resolved_at = None
        timeline.append(
            {
                "timestamp": now_iso,
                "actor": actor.username,
                "action": "Status Changed",
                "previous_status": prev_st,
                "new_status": inc.status,
                "comment": payload.comment.strip() if (payload.comment and payload.comment.strip()) else None,
                "detail": status_msg,
            }
        )

    if payload.description is not None and payload.description.strip() != inc.description:
        inc.description = payload.description.strip()
        changes.append("description updated")
        other_changes.append("description updated")

    if payload.resolution_summary is not None:
        cleaned_res = payload.resolution_summary.strip()
        if cleaned_res != (inc.resolution_summary or ""):
            inc.resolution_summary = cleaned_res
            changes.append("resolution summary updated")
            other_changes.append("resolution summary updated")

    if payload.evidence_references is not None:
        inc.evidence_references = payload.evidence_references
        changes.append("evidence references updated")
        other_changes.append("evidence references updated")

    if other_changes:
        timeline.append(
            {
                "timestamp": now_iso,
                "actor": actor.username,
                "action": "Incident Updated",
                "detail": "; ".join(other_changes),
            }
        )

    if changes:
        inc.timeline_events = timeline

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_updated",
        resource_type="incident",
        resource_id=inc.incident_id,
        ip_address=request.client.host if request.client else None,
        details={
            "changes": changes,
            "status": inc.status,
            "assigned_analyst": inc.assigned_analyst,
        },
        commit=False,
    )
    db.commit()
    db.refresh(inc)

    broadcast_sync_or_async(
        "incident_updated",
        {
            "id": inc.id,
            "incident_id": inc.incident_id,
            "status": inc.status,
            "assigned_analyst": inc.assigned_analyst,
            "updated_by": actor.username,
        },
    )

    return get_incident_detail(incident_identifier=str(inc.id), db=db)


@router.patch("/{incident_identifier}", response_model=IncidentDetailRead)
def update_incident(
    incident_identifier: str,
    payload: IncidentUpdate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)
    return _apply_incident_updates(db, inc, payload, actor, request)


@router.patch("/{incident_identifier}/status", response_model=IncidentDetailRead)
def update_incident_status(
    incident_identifier: str,
    payload: IncidentStatusUpdate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)
    update_payload = IncidentUpdate(
        status=payload.status,
        comment=payload.comment,
        assigned_analyst=payload.assigned_analyst,
        resolution_summary=payload.resolution_summary,
    )
    return _apply_incident_updates(db, inc, update_payload, actor, request)


@router.post("/{incident_identifier}/alerts", response_model=IncidentDetailRead)
def link_alerts_to_incident(
    incident_identifier: str,
    payload: IncidentLinkAlertsRequest,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    existing_alert_ids: Set[int] = {link.alert_id for link in inc.alert_links}

    alerts_to_link = _resolve_alert_list(db, payload.alert_ids)
    newly_linked_alerts: List[Alert] = []
    added_codes: List[str] = []

    for al in alerts_to_link:
        if al.id not in existing_alert_ids:
            db.add(
                IncidentAlert(
                    incident_id=inc.id,
                    alert_id=al.id,
                    linked_by=actor.username,
                )
            )
            existing_alert_ids.add(al.id)
            newly_linked_alerts.append(al)
            added_codes.append(al.alert_id)
            if al.status == "New":
                prev_al_st = al.status
                al.status = "Investigating"
                db.add(
                    AlertStatusHistory(
                        alert_id=al.id,
                        previous_status=prev_al_st,
                        new_status="Investigating",
                        changed_by=actor.username,
                        comment=f"Associated with incident {inc.incident_id}",
                    )
                )

    if newly_linked_alerts:
        new_events = _collect_events_for_alerts(db, [a.id for a in newly_linked_alerts])
        inc.evidence_references = _merge_evidence_references(
            existing_refs=inc.evidence_references,
            linked_alerts=newly_linked_alerts,
            linked_events=new_events,
            actor_username=actor.username,
            now_iso=now_iso,
        )
        timeline = list(inc.timeline_events or [])
        timeline.append(
            {
                "timestamp": now_iso,
                "actor": actor.username,
                "action": "Alerts Linked",
                "detail": (
                    f"Linked alert(s): {', '.join(added_codes)} "
                    f"({len(new_events)} triggering event(s) added to evidence)."
                ),
            }
        )
        inc.timeline_events = timeline

        record_audit_log(
            db,
            actor_username=actor.username,
            actor_role=actor.role,
            action="incident_alerts_linked",
            resource_type="incident",
            resource_id=inc.incident_id,
            ip_address=request.client.host if request.client else None,
            details={"linked_alerts": added_codes},
            commit=False,
        )
        db.commit()
        db.refresh(inc)

    return get_incident_detail(incident_identifier=str(inc.id), db=db)


@router.delete("/{incident_identifier}/alerts/{alert_identifier}", response_model=IncidentDetailRead)
def unlink_alert_from_incident(
    incident_identifier: str,
    alert_identifier: str,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)
    resolved_alerts = _resolve_alert_list(db, [alert_identifier])
    if not resolved_alerts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_identifier}' not found.",
        )
    target_alert = resolved_alerts[0]
    link = (
        db.query(IncidentAlert)
        .filter(
            IncidentAlert.incident_id == inc.id,
            IncidentAlert.alert_id == target_alert.id,
        )
        .first()
    )
    if link:
        db.delete(link)
        timeline = list(inc.timeline_events or [])
        timeline.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": actor.username,
                "action": "Alert Unlinked",
                "detail": f"Removed alert {target_alert.alert_id} from incident.",
            }
        )
        inc.timeline_events = timeline
        record_audit_log(
            db,
            actor_username=actor.username,
            actor_role=actor.role,
            action="incident_alert_unlinked",
            resource_type="incident",
            resource_id=inc.incident_id,
            ip_address=request.client.host if request.client else None,
            details={"unlinked_alert": target_alert.alert_id},
            commit=False,
        )
        db.commit()

    return get_incident_detail(incident_identifier=str(inc.id), db=db)


@router.get("/{incident_identifier}/evidence")
def get_incident_evidence(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    detail = get_incident_detail(incident_identifier=incident_identifier, db=db)
    return {
        "incident_id": detail.incident_id,
        "evidence_references": detail.evidence_references,
        "related_alerts": [a.model_dump(mode="json") for a in detail.related_alerts],
        "related_events": [e.model_dump(mode="json") for e in detail.related_events],
    }


@router.post("/{incident_identifier}/evidence", response_model=IncidentDetailRead, status_code=status.HTTP_201_CREATED)
def add_incident_evidence(
    incident_identifier: str,
    payload: IncidentEvidenceCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)
    now_iso = datetime.now(timezone.utc).isoformat()
    refs = list(inc.evidence_references or [])
    ev_type = payload.type.strip().lower()
    ref_code = (payload.reference or "").strip()
    desc = (payload.description or payload.note or "").strip()

    new_entry: Dict[str, Any] = {
        "type": ev_type,
        "reference": ref_code,
        "description": desc,
        "added_by": actor.username,
        "added_at": now_iso,
    }

    # Resolve SecurityEvent if event_id is provided or type is 'event'
    if payload.event_id is not None or (ev_type == "event" and ref_code):
        lookup_val = payload.event_id if payload.event_id is not None else ref_code
        ev_obj: Optional[SecurityEvent] = None
        if isinstance(lookup_val, int) or (isinstance(lookup_val, str) and lookup_val.isdigit()):
            ev_obj = db.query(SecurityEvent).filter(SecurityEvent.id == int(lookup_val)).first()
        if not ev_obj and isinstance(lookup_val, str):
            ev_obj = db.query(SecurityEvent).filter(SecurityEvent.event_id == lookup_val.strip()).first()
        if not ev_obj and payload.event_id is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security event '{lookup_val}' not found.",
            )
        if ev_obj:
            new_entry["type"] = "event"
            new_entry["reference"] = ev_obj.event_id
            new_entry["event_id"] = ev_obj.id
            new_entry["source_ip"] = ev_obj.source_ip
            new_entry["event_category"] = ev_obj.event_category
            if not new_entry["description"]:
                new_entry["description"] = (
                    f"{ev_obj.event_category}/{ev_obj.event_type} from {ev_obj.source_ip} ({ev_obj.status})"
                )

    # Resolve Alert if alert_id is provided or type is 'alert'
    elif payload.alert_id is not None or (ev_type == "alert" and ref_code):
        lookup_al = payload.alert_id if payload.alert_id is not None else ref_code
        resolved = _resolve_alert_list(db, [lookup_al])
        if not resolved and payload.alert_id is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{lookup_al}' not found.",
            )
        if resolved:
            al_obj = resolved[0]
            new_entry["type"] = "alert"
            new_entry["reference"] = al_obj.alert_id
            new_entry["alert_id"] = al_obj.id
            new_entry["rule_code"] = al_obj.rule_code
            if not new_entry["description"]:
                new_entry["description"] = f"{al_obj.rule_code}: {al_obj.title}"
            existing_link = (
                db.query(IncidentAlert)
                .filter(IncidentAlert.incident_id == inc.id, IncidentAlert.alert_id == al_obj.id)
                .first()
            )
            if not existing_link:
                db.add(IncidentAlert(incident_id=inc.id, alert_id=al_obj.id, linked_by=actor.username))

    if not new_entry.get("reference"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Evidence reference identifier (reference, event_id, or alert_id) is required.",
        )

    existing_keys = {
        (str(r.get("type") or "").lower(), str(r.get("reference") or "").strip())
        for r in refs
        if isinstance(r, dict)
    }
    entry_key = (new_entry["type"], new_entry["reference"])
    if entry_key not in existing_keys:
        refs.append(new_entry)
        inc.evidence_references = refs

    timeline = list(inc.timeline_events or [])
    timeline.append(
        {
            "timestamp": now_iso,
            "actor": actor.username,
            "action": "Evidence Added",
            "detail": f"Added {new_entry['type']} evidence '{new_entry['reference']}': {new_entry.get('description') or 'Forensic reference'}",
        }
    )
    inc.timeline_events = timeline

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_evidence_added",
        resource_type="incident",
        resource_id=inc.incident_id,
        ip_address=request.client.host if request.client else None,
        details={"type": new_entry["type"], "reference": new_entry["reference"]},
        commit=False,
    )
    db.commit()
    db.refresh(inc)
    return get_incident_detail(incident_identifier=str(inc.id), db=db)


@router.get("/{incident_identifier}/events", response_model=List[SecurityEventRead])
def list_incident_events(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> List[SecurityEventRead]:
    detail = get_incident_detail(incident_identifier=incident_identifier, db=db)
    return detail.related_events


@router.get("/{incident_identifier}/timeline", response_model=List[Dict[str, Any]])
def get_incident_timeline(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    inc = _resolve_incident(db, incident_identifier)
    return list(inc.timeline_events or [])


@router.post("/{incident_identifier}/timeline", response_model=IncidentDetailRead, status_code=status.HTTP_201_CREATED)
def add_incident_timeline_entry(
    incident_identifier: str,
    payload: IncidentTimelineEntryCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> IncidentDetailRead:
    inc = _resolve_incident(db, incident_identifier)
    now_iso = datetime.now(timezone.utc).isoformat()
    timeline = list(inc.timeline_events or [])
    timeline.append(
        {
            "timestamp": now_iso,
            "actor": actor.username,
            "action": payload.action.strip(),
            "detail": payload.detail.strip(),
        }
    )
    inc.timeline_events = timeline
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_timeline_entry_added",
        resource_type="incident",
        resource_id=inc.incident_id,
        ip_address=request.client.host if request.client else None,
        details={"action": payload.action.strip()},
        commit=False,
    )
    db.commit()
    db.refresh(inc)
    return get_incident_detail(incident_identifier=str(inc.id), db=db)


@router.get("/{incident_identifier}/history", response_model=List[Dict[str, Any]])
def get_incident_status_history(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    inc = _resolve_incident(db, incident_identifier)
    return _extract_status_history(inc)


@router.post("/{incident_identifier}/notes", response_model=InvestigationNoteRead, status_code=status.HTTP_201_CREATED)
def add_incident_note(
    incident_identifier: str,
    payload: NoteCreateRequest,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> InvestigationNoteRead:
    inc = _resolve_incident(db, incident_identifier)
    now = datetime.now(timezone.utc)
    note = InvestigationNote(
        incident_id=inc.id,
        author=actor.username,
        content=payload.content.strip(),
        note_type=payload.note_type,
    )
    db.add(note)

    timeline = list(inc.timeline_events or [])
    timeline.append(
        {
            "timestamp": now.isoformat(),
            "actor": actor.username,
            "action": "Investigation Note Added",
            "note_type": payload.note_type,
            "detail": payload.content.strip()[:240],
        }
    )
    inc.timeline_events = timeline

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_note_added",
        resource_type="incident",
        resource_id=inc.incident_id,
        ip_address=request.client.host if request.client else None,
        details={"note_type": payload.note_type},
        commit=False,
    )
    db.commit()
    db.refresh(note)
    return InvestigationNoteRead.model_validate(note)


@router.get("/{incident_identifier}/notes", response_model=List[InvestigationNoteRead])
def list_incident_notes(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> List[InvestigationNoteRead]:
    inc = _resolve_incident(db, incident_identifier)
    return [InvestigationNoteRead.model_validate(n) for n in inc.notes]


@router.delete("/{incident_identifier}")
def delete_incident(
    incident_identifier: str,
    request: Request,
    actor: User = Depends(require_actor_roles("admin")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    inc = _resolve_incident(db, incident_identifier)
    inc_code = inc.incident_id
    db.delete(inc)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_deleted",
        resource_type="incident",
        resource_id=inc_code,
        ip_address=request.client.host if request.client else None,
        commit=False,
    )
    db.commit()
    return {"deleted": True, "incident_id": inc_code}
