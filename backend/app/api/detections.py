from collections import Counter
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_actor_or_default, require_actor_roles
from app.core.database import get_db
from app.detection.engine import ThreatDetectionEngine
from app.models.entities import Alert, AlertEvidence, AuditLog, DetectionRule, SecurityEvent, User
from app.schemas.api_schemas import DetectionRuleCreate, DetectionRuleRead, DetectionRuleUpdate
from app.services.audit import record_audit_log

router = APIRouter(prefix="/api/detections", tags=["Threat Detection & MITRE ATT&CK"])


def _serialize_rule(rule: DetectionRule, alert_count: int = 0) -> DetectionRuleRead:
    return DetectionRuleRead(
        id=rule.id,
        rule_id=rule.rule_id,
        rule_key=rule.rule_key,
        name=rule.name,
        description=rule.description,
        detection_logic=rule.detection_logic,
        event_category=rule.event_category,
        threshold_count=rule.threshold_count,
        time_window_seconds=rule.time_window_seconds,
        parameters=rule.parameters or {},
        severity=rule.severity,
        enabled=rule.enabled,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique_id=rule.mitre_technique_id,
        mitre_technique_name=rule.mitre_technique_name,
        alert_count=alert_count,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


@router.get("", response_model=List[DetectionRuleRead])
@router.get("/rules", response_model=List[DetectionRuleRead])
def list_detection_rules(db: Session = Depends(get_db)) -> List[DetectionRuleRead]:
    rules = db.query(DetectionRule).order_by(DetectionRule.rule_id.asc()).all()
    counts = dict(
        db.query(Alert.rule_code, func.count(Alert.id))
        .group_by(Alert.rule_code)
        .all()
    )
    return [_serialize_rule(r, counts.get(r.rule_id, 0)) for r in rules]


@router.post("/rules", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED)
def create_detection_rule(
    payload: DetectionRuleCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin")),
    db: Session = Depends(get_db),
) -> DetectionRuleRead:
    existing = (
        db.query(DetectionRule)
        .filter(
            (DetectionRule.rule_id == payload.rule_id.strip())
            | (DetectionRule.rule_key == payload.rule_key.strip())
            | (DetectionRule.name == payload.name.strip())
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A detection rule with the same rule_id, rule_key, or name already exists.",
        )

    rule = DetectionRule(
        rule_id=payload.rule_id.strip(),
        rule_key=payload.rule_key.strip(),
        name=payload.name.strip(),
        description=payload.description.strip(),
        detection_logic=payload.detection_logic.strip(),
        event_category=payload.event_category,
        threshold_count=payload.threshold_count,
        time_window_seconds=payload.time_window_seconds,
        parameters=payload.parameters or {},
        severity=payload.severity,
        enabled=payload.enabled,
        mitre_tactic=payload.mitre_tactic,
        mitre_technique_id=payload.mitre_technique_id,
        mitre_technique_name=payload.mitre_technique_name,
    )
    db.add(rule)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="detection_rule_created",
        resource_type="detection_rule",
        resource_id=rule.rule_id,
        ip_address=request.client.host if request.client else None,
        details={"rule_key": rule.rule_key, "severity": rule.severity},
        commit=False,
    )
    db.commit()
    db.refresh(rule)
    return _serialize_rule(rule, 0)


@router.get("/rules/{rule_identifier}")
def get_detection_rule(
    rule_identifier: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    rule: Optional[DetectionRule] = None
    if rule_identifier.isdigit():
        rule = db.query(DetectionRule).filter(DetectionRule.id == int(rule_identifier)).first()
    if not rule:
        rule = (
            db.query(DetectionRule)
            .filter(
                (DetectionRule.rule_id == rule_identifier)
                | (DetectionRule.rule_key == rule_identifier)
            )
            .first()
        )
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_identifier}' not found.",
        )

    related_alerts = (
        db.query(Alert)
        .filter(Alert.rule_code == rule.rule_id)
        .order_by(Alert.last_seen.desc())
        .limit(20)
        .all()
    )
    return {
        "rule": _serialize_rule(rule, len(related_alerts)).model_dump(mode="json"),
        "recent_alerts": [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "source_ip": a.source_ip,
                "username": a.username,
                "event_count": a.event_count,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in related_alerts
        ],
    }


@router.patch("/rules/{rule_identifier}", response_model=DetectionRuleRead)
def update_detection_rule(
    rule_identifier: str,
    payload: DetectionRuleUpdate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> DetectionRuleRead:
    rule: Optional[DetectionRule] = None
    if rule_identifier.isdigit():
        rule = db.query(DetectionRule).filter(DetectionRule.id == int(rule_identifier)).first()
    if not rule:
        rule = (
            db.query(DetectionRule)
            .filter(
                (DetectionRule.rule_id == rule_identifier)
                | (DetectionRule.rule_key == rule_identifier)
            )
            .first()
        )
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_identifier}' not found.",
        )

    changes: Dict[str, Any] = {}
    if payload.name is not None:
        rule.name = payload.name.strip()
        changes["name"] = rule.name
    if payload.description is not None:
        rule.description = payload.description.strip()
        changes["description"] = rule.description
    if payload.threshold_count is not None:
        rule.threshold_count = payload.threshold_count
        changes["threshold_count"] = rule.threshold_count
    if payload.time_window_seconds is not None:
        rule.time_window_seconds = payload.time_window_seconds
        changes["time_window_seconds"] = rule.time_window_seconds
    if payload.parameters is not None:
        rule.parameters = payload.parameters
        changes["parameters"] = rule.parameters
    if payload.severity is not None:
        rule.severity = payload.severity
        changes["severity"] = rule.severity
    if payload.enabled is not None:
        rule.enabled = payload.enabled
        changes["enabled"] = rule.enabled

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="detection_rule_updated",
        resource_type="detection_rule",
        resource_id=rule.rule_id,
        ip_address=request.client.host if request.client else None,
        details=changes,
        commit=False,
    )
    db.commit()
    db.refresh(rule)

    alert_count = db.query(func.count(Alert.id)).filter(Alert.rule_code == rule.rule_id).scalar() or 0
    return _serialize_rule(rule, alert_count)


@router.delete("/rules/{rule_identifier}")
def delete_detection_rule(
    rule_identifier: str,
    request: Request,
    actor: User = Depends(require_actor_roles("admin")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    rule: Optional[DetectionRule] = None
    if rule_identifier.isdigit():
        rule = db.query(DetectionRule).filter(DetectionRule.id == int(rule_identifier)).first()
    if not rule:
        rule = (
            db.query(DetectionRule)
            .filter(
                (DetectionRule.rule_id == rule_identifier)
                | (DetectionRule.rule_key == rule_identifier)
            )
            .first()
        )
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_identifier}' not found.",
        )

    r_code = rule.rule_id
    db.delete(rule)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="detection_rule_deleted",
        resource_type="detection_rule",
        resource_id=r_code,
        ip_address=request.client.host if request.client else None,
        commit=False,
    )
    db.commit()
    return {"deleted": True, "rule_id": r_code}


MITRE_TACTIC_IDS: Dict[str, str] = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}


def build_mitre_mappings_for_rules_and_alerts(
    rules: List[DetectionRule],
    alerts: List[Alert],
) -> Dict[str, Any]:
    alerts_by_rule: Dict[str, List[Alert]] = {}
    for a in alerts:
        alerts_by_rule.setdefault(a.rule_code, []).append(a)

    rules_by_technique: Dict[str, List[Dict[str, Any]]] = {}
    for r in rules:
        tech_key = r.mitre_technique_id or r.rule_id
        rules_by_technique.setdefault(tech_key, []).append(
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "rule_key": r.rule_key,
                "name": r.name,
                "description": r.description,
                "event_category": r.event_category,
                "severity": r.severity,
                "enabled": r.enabled,
                "threshold_count": r.threshold_count,
                "time_window_seconds": r.time_window_seconds,
            }
        )

    mappings = []
    tactic_counts: Counter[str] = Counter()
    tactic_rule_counts: Counter[str] = Counter()

    for r in rules:
        r_alerts = alerts_by_rule.get(r.rule_id, [])
        tactic = r.mitre_tactic or "Unclassified"
        tactic_id = MITRE_TACTIC_IDS.get(tactic, "TA0000")
        tactic_counts[tactic] += len(r_alerts)
        tactic_rule_counts[tactic] += 1
        tech_id = r.mitre_technique_id or ""
        tech_name = r.mitre_technique_name or r.name
        mitre_url = (
            f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
            if tech_id
            else "https://attack.mitre.org/"
        )
        rule_info = {
            "id": r.id,
            "rule_id": r.rule_id,
            "rule_key": r.rule_key,
            "name": r.name,
            "description": r.description,
            "event_category": r.event_category,
            "severity": r.severity,
            "enabled": r.enabled,
            "threshold_count": r.threshold_count,
            "time_window_seconds": r.time_window_seconds,
        }
        associated_rules = rules_by_technique.get(tech_id or r.rule_id, [rule_info])
        related_alert_dicts = [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "rule_code": a.rule_code,
                "rule_name": a.rule_name,
                "source_ip": a.source_ip,
                "username": a.username,
                "hostname": a.hostname,
                "event_count": a.event_count,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in r_alerts[:20]
        ]
        mappings.append(
            {
                "tactic": tactic,
                "mitre_tactic": tactic,
                "tactic_id": tactic_id,
                "technique_id": tech_id,
                "mitre_technique_id": tech_id,
                "technique_name": tech_name,
                "mitre_technique_name": tech_name,
                "reference_url": mitre_url,
                "rule": rule_info,
                "associated_rules": associated_rules,
                "alert_count": len(r_alerts),
                "related_alerts": related_alert_dicts,
            }
        )

    return {
        "total_mapped_rules": len(mappings),
        "total_related_alerts": sum(tactic_counts.values()),
        "tactic_summary": [
            {
                "tactic": t,
                "tactic_id": MITRE_TACTIC_IDS.get(t, "TA0000"),
                "rule_count": tactic_rule_counts[t],
                "alert_count": c,
            }
            for t, c in tactic_counts.items()
        ],
        "mappings": mappings,
    }


@router.get("/mitre")
def get_mitre_attack_mappings(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Returns official MITRE ATT&CK mappings linked to ThreatLens detection rules and alerts."""
    rules = db.query(DetectionRule).order_by(DetectionRule.rule_id.asc()).all()
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
    return build_mitre_mappings_for_rules_and_alerts(rules, alerts)


@router.get("/history")
def get_detection_history(
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Returns chronological detection history including triggered alerts, linked evidence events, and rule configuration changes."""
    alert_query = db.query(Alert)
    if rule_id and rule_id.strip() and rule_id.lower() != "all":
        alert_query = alert_query.filter(Alert.rule_code == rule_id.strip().upper())
    if severity and severity.strip() and severity.lower() != "all":
        alert_query = alert_query.filter(Alert.severity == severity.strip().lower())

    alerts = (
        alert_query.order_by(Alert.last_seen.desc(), Alert.id.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )

    alert_ids = [a.id for a in alerts]
    evidence_by_alert: Dict[int, List[Dict[str, Any]]] = {}
    if alert_ids:
        ev_rows = (
            db.query(AlertEvidence, SecurityEvent)
            .join(SecurityEvent, AlertEvidence.event_id == SecurityEvent.id)
            .filter(AlertEvidence.alert_id.in_(alert_ids))
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )
        for ae, se in ev_rows:
            evidence_by_alert.setdefault(ae.alert_id, []).append(
                {
                    "event_db_id": se.id,
                    "event_id": se.event_id,
                    "evidence_role": ae.evidence_role,
                    "timestamp": se.timestamp.isoformat() if se.timestamp else None,
                    "source_ip": se.source_ip,
                    "username": se.username,
                    "event_type": se.event_type,
                    "status": se.status,
                }
            )

    rule_audit_logs = (
        db.query(AuditLog)
        .filter(AuditLog.resource_type == "detection_rule")
        .order_by(AuditLog.created_at.desc())
        .limit(50)
        .all()
    )

    return {
        "total_detections": len(alerts),
        "detections": [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "rule_code": a.rule_code,
                "rule_name": a.rule_name,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "status": a.status,
                "source_ip": a.source_ip,
                "username": a.username,
                "hostname": a.hostname,
                "dedup_key": a.dedup_key,
                "event_count": a.event_count,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique_id": a.mitre_technique_id,
                "mitre_technique_name": a.mitre_technique_name,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "evidence_summary": a.evidence_summary or {},
                "triggering_events": evidence_by_alert.get(a.id, []),
            }
            for a in alerts
        ],
        "rule_configuration_history": [
            {
                "id": l.id,
                "actor_username": l.actor_username,
                "action": l.action,
                "rule_id": l.resource_id,
                "details": l.details or {},
                "created_at": l.created_at.isoformat() if l.created_at else None,
            }
            for l in rule_audit_logs
        ],
    }


@router.post("/evaluate")
def run_detection_evaluation(
    limit: int = 500,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    recent_events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.asc())
        .limit(limit)
        .all()
    )
    engine = ThreatDetectionEngine(db)
    new_alerts = engine.evaluate_events(recent_events)
    return {
        "evaluated_events_count": len(recent_events),
        "new_alerts_generated": len(new_alerts),
        "alert_ids": [a.alert_id for a in new_alerts],
    }

