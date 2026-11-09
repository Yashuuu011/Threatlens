from datetime import datetime, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from app.api.deps import get_actor_or_default, require_actor_roles
from app.core.config import settings
from app.core.database import (
    ACTIVE_DB_BACKEND,
    LAST_POSTGRES_ERROR,
    get_db,
    probe_postgresql_connection,
)
from app.core.rate_limit import rate_limiter
from app.core.websocket import broadcast_sync_or_async, ws_manager
from app.ingestion.pipeline import EventIngestionPipeline
from app.intelligence.provider import provider_config
from app.models.entities import (
    Alert,
    AuditLog,
    DetectionRule,
    Incident,
    SecurityEvent,
    ThreatIndicator,
    User,
)
from app.services.audit import record_audit_log
from app.services.bootstrap import seed_initial_data
from telemetry.scenarios.catalog import (
    SCENARIO_DEFINITIONS,
    generate_attack_mode_telemetry,
    generate_full_simulation_suite,
    generate_normal_mode_telemetry,
    generate_scenario_events,
)

router = APIRouter(prefix="/api/system", tags=["System Configuration & Telemetry Simulation"])


class SimulationRequest(BaseModel):
    scenario_id: str = Field(default="all", description="Scenario ID, 'normal_mode', 'attack_mode', or 'all'")
    volume_multiplier: int = Field(default=1, ge=1, le=10)
    run_detections: bool = Field(default=True, description="Whether to evaluate detection rules during simulation")


@router.get("/health")
def get_system_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    orm_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        orm_ok = False

    pg_probe = probe_postgresql_connection()
    pg_connected = bool(pg_probe["postgresql_connected"])

    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    enabled_rules = (
        db.query(func.count(DetectionRule.id))
        .filter(DetectionRule.enabled.is_(True))
        .scalar()
        or 0
    )
    total_rules = db.query(func.count(DetectionRule.id)).scalar() or 0
    active_iocs = (
        db.query(func.count(ThreatIndicator.id))
        .filter(ThreatIndicator.is_active.is_(True))
        .scalar()
        or 0
    )

    overall_status = (
        "healthy"
        if (orm_ok and pg_connected)
        else ("degraded_sqlite_fallback" if orm_ok else "unhealthy")
    )

    return {
        "status": overall_status,
        "backend_connected": True,
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "connected": orm_ok,
            "postgresql_connected": pg_connected,
            "postgresql_version": pg_probe.get("version"),
            "postgresql_error": pg_probe.get("error") or LAST_POSTGRES_ERROR,
            "backend": "postgresql" if pg_connected else ACTIVE_DB_BACKEND,
            "configured_host": f"{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}",
        },
        "detection_engine": {
            "status": "operational" if orm_ok else "degraded",
            "enabled_rules": enabled_rules,
            "total_rules": total_rules,
        },
        "realtime_websocket": {
            "active_connections": len(ws_manager.active_connections),
            "latest_seq": ws_manager.latest_seq,
            "endpoint": "/ws",
            "polling_fallback_endpoint": "/api/system/realtime/poll",
            "polling_fallback_supported": True,
        },
        "counters": {
            "security_events": total_events,
            "alerts": total_alerts,
            "incidents": total_incidents,
            "active_iocs": active_iocs,
        },
        "security_controls": {
            "jwt_authentication": True,
            "rbac_enabled": True,
            "supported_roles": ["admin", "soc_lead", "analyst", "viewer"],
            "rate_limit_login_per_min": settings.RATE_LIMIT_LOGIN_PER_MINUTE,
            "rate_limit_ingest_per_min": settings.RATE_LIMIT_INGEST_PER_MINUTE,
            "rate_limit_intel_per_min": settings.RATE_LIMIT_INTEL_PER_MINUTE,
            "rate_limit_export_per_min": settings.RATE_LIMIT_EXPORT_PER_MINUTE,
            "rate_limiter_stats": rate_limiter.status_summary(),
            "audit_logging": True,
        },
        "threat_intel_providers": provider_config.status_summary(),
    }


@router.get("/realtime")
@router.get("/realtime/poll")
def poll_realtime_updates(
    since_seq: int = Query(default=0, ge=0, description="Return messages after this sequence number"),
    limit: int = Query(default=30, ge=1, le=100),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Polling fallback endpoint delivering live event updates, alert notifications, and dashboard metrics."""
    snapshot = ws_manager.get_poll_snapshot(since_seq=since_seq, limit=limit)
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0
    high_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "high").scalar() or 0
    active_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status.in_(["Open", "Investigating", "Contained"]))
        .scalar()
        or 0
    )
    resolved_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status.in_(["Resolved", "Closed"]))
        .scalar()
        or 0
    )
    return {
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "websocket_endpoint": "/ws",
        "active_websocket_connections": snapshot["active_connections"],
        "polling_fallback_enabled": True,
        "latest_seq": snapshot["latest_seq"],
        "messages": snapshot["messages"],
        "metrics": {
            "total_security_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_severity_alerts": high_alerts,
            "active_incidents": active_incidents,
            "resolved_incidents": resolved_incidents,
        },
    }


@router.get("/audit-logs")
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    page: int = Query(default=1, ge=1),
    search: str | None = Query(default=None),
    actor_username: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    query = db.query(AuditLog)
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AuditLog.actor_username.ilike(term),
                AuditLog.action.ilike(term),
                AuditLog.resource_type.ilike(term),
                AuditLog.resource_id.ilike(term),
            )
        )
    if actor_username and actor_username.strip():
        query = query.filter(AuditLog.actor_username.ilike(f"%{actor_username.strip()}%"))
    if action and action.strip():
        query = query.filter(AuditLog.action.ilike(f"%{action.strip()}%"))
    if resource_type and resource_type.strip():
        query = query.filter(AuditLog.resource_type.ilike(f"%{resource_type.strip()}%"))
    if status_filter and status_filter.strip() and status_filter.lower() != "all":
        query = query.filter(AuditLog.status == status_filter.strip().lower())

    offset = (page - 1) * limit
    logs = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": l.id,
            "actor_username": l.actor_username,
            "actor_role": l.actor_role,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "ip_address": l.ip_address,
            "status": l.status,
            "details": l.details or {},
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in logs
    ]


@router.get("/scenarios")
def list_telemetry_scenarios() -> List[Dict[str, Any]]:
    return SCENARIO_DEFINITIONS


@router.post("/simulate")
def run_synthetic_simulation(
    payload: SimulationRequest,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    scen = payload.scenario_id.strip().lower()
    if scen == "all":
        events = generate_full_simulation_suite(base_time=now)
    elif scen in ("normal_mode", "normal"):
        events = generate_normal_mode_telemetry(base_time=now, volume_multiplier=payload.volume_multiplier)
    elif scen in ("attack_mode", "attack"):
        events = generate_attack_mode_telemetry(base_time=now, volume_multiplier=payload.volume_multiplier)
    else:
        valid_ids = {s["id"] for s in SCENARIO_DEFINITIONS}
        if payload.scenario_id not in valid_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown scenario '{payload.scenario_id}'. Valid scenarios: {sorted(valid_ids | {'normal_mode', 'attack_mode', 'all'})}",
            )
        events = generate_scenario_events(
            payload.scenario_id,
            base_time=now,
            volume_multiplier=payload.volume_multiplier,
        )

    pipeline = EventIngestionPipeline(db)
    result = pipeline.ingest_bulk(events, run_detections=payload.run_detections)

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="synthetic_telemetry_simulated",
        resource_type="telemetry_scenario",
        resource_id=payload.scenario_id,
        ip_address=request.client.host if request.client else None,
        details={
            "scenario_id": payload.scenario_id,
            "volume_multiplier": payload.volume_multiplier,
            "accepted_events": result.accepted_count,
            "generated_alerts": result.generated_alerts_count,
            "alert_ids": result.generated_alert_ids,
        },
    )

    broadcast_sync_or_async(
        "dashboard_metrics_updated",
        {
            "scenario_id": payload.scenario_id,
            "accepted_count": result.accepted_count,
            "generated_alerts_count": result.generated_alerts_count,
        },
    )

    return {
        "scenario_id": payload.scenario_id,
        "simulated_at": now.isoformat(),
        "accepted_count": result.accepted_count,
        "generated_alerts_count": result.generated_alerts_count,
        "generated_alert_ids": result.generated_alert_ids,
    }


@router.post("/reset-demo")
def reset_and_reseed_demo(
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "soc_lead")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    db.query(Incident).delete()
    db.query(Alert).delete()
    db.query(SecurityEvent).delete()
    db.commit()

    seed_initial_data(db, seed_telemetry=True)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="demo_environment_reset",
        resource_type="system",
        resource_id="database",
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "reset_complete", "timestamp": datetime.now(timezone.utc).isoformat()}

