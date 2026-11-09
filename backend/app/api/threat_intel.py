from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_actor_or_default, require_actor_roles
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.intelligence.provider import ThreatIntelligenceService, provider_config
from app.models.entities import ThreatIndicator, User
from app.schemas.api_schemas import (
    ThreatIndicatorCreate,
    ThreatIndicatorRead,
    ThreatIndicatorUpdate,
    ThreatProviderConfigUpdate,
)
from app.services.audit import record_audit_log

router = APIRouter(prefix="/api/threat-intelligence", tags=["Threat Intelligence & IOCs"])


@router.get("/lookup")
def lookup_ip_intelligence(
    request: Request,
    ip: str = Query(..., description="IPv4 or IPv6 address to query"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    enforce_rate_limit(
        request,
        scope="threat_intel_lookup",
        max_requests=settings.RATE_LIMIT_INTEL_PER_MINUTE,
        window_seconds=60,
    )
    service = ThreatIntelligenceService(db)
    try:
        return service.lookup_ip_reputation(ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/suspicious-ips")
def list_suspicious_ips(
    limit: int = Query(default=50, ge=1, le=200),
    search: Optional[str] = Query(default=None),
    only_iocs: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Returns tracked suspicious IPs correlated from SIEM telemetry, alerts, and local IOCs."""
    service = ThreatIntelligenceService(db)
    return service.get_suspicious_ips(limit=limit, search=search, only_iocs=only_iocs)


@router.get("/indicators", response_model=List[ThreatIndicatorRead])
def list_threat_indicators(
    search: Optional[str] = Query(default=None),
    indicator_type: Optional[str] = Query(default=None),
    threat_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    active_only: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> List[ThreatIndicatorRead]:
    query = db.query(ThreatIndicator)
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ThreatIndicator.indicator_value.ilike(term),
                ThreatIndicator.threat_type.ilike(term),
                ThreatIndicator.source.ilike(term),
                ThreatIndicator.description.ilike(term),
            )
        )
    if indicator_type and indicator_type.lower() != "all":
        query = query.filter(ThreatIndicator.indicator_type == indicator_type.lower())
    if threat_type and threat_type.lower() != "all":
        query = query.filter(ThreatIndicator.threat_type == threat_type.lower())
    if severity and severity.lower() != "all":
        query = query.filter(ThreatIndicator.severity == severity.lower())
    if active_only:
        query = query.filter(ThreatIndicator.is_active.is_(True))

    rows = query.order_by(ThreatIndicator.confidence.desc(), ThreatIndicator.id.desc()).all()
    return [ThreatIndicatorRead.model_validate(r) for r in rows]


@router.post("/indicators", response_model=ThreatIndicatorRead, status_code=status.HTTP_201_CREATED)
def create_threat_indicator(
    payload: ThreatIndicatorCreate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> ThreatIndicatorRead:
    val = payload.indicator_value.strip()
    existing = (
        db.query(ThreatIndicator)
        .filter(ThreatIndicator.indicator_value == val)
        .first()
    )
    now = datetime.now(timezone.utc)
    if existing:
        existing.threat_type = payload.threat_type.strip().lower()
        existing.severity = payload.severity.strip().lower()
        existing.confidence = payload.confidence
        existing.source = payload.source.strip()
        existing.description = payload.description
        existing.tags = payload.tags
        existing.is_active = payload.is_active
        existing.last_seen = now
        db.commit()
        db.refresh(existing)
        return ThreatIndicatorRead.model_validate(existing)

    ioc = ThreatIndicator(
        indicator_type=payload.indicator_type.strip().lower(),
        indicator_value=val,
        threat_type=payload.threat_type.strip().lower(),
        severity=payload.severity.strip().lower(),
        confidence=payload.confidence,
        source=payload.source.strip(),
        description=payload.description,
        tags=payload.tags or [],
        is_active=payload.is_active,
        first_seen=now,
        last_seen=now,
        hit_count=0,
    )
    db.add(ioc)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="threat_indicator_created",
        resource_type="threat_indicator",
        resource_id=val,
        ip_address=request.client.host if request.client else None,
        details={"threat_type": ioc.threat_type, "severity": ioc.severity, "confidence": ioc.confidence},
        commit=False,
    )
    db.commit()
    db.refresh(ioc)
    return ThreatIndicatorRead.model_validate(ioc)


@router.patch("/indicators/{indicator_id}", response_model=ThreatIndicatorRead)
def update_threat_indicator(
    indicator_id: int,
    payload: ThreatIndicatorUpdate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> ThreatIndicatorRead:
    ioc = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator {indicator_id} not found.",
        )

    changes: Dict[str, Any] = {}
    if payload.threat_type is not None:
        ioc.threat_type = payload.threat_type.strip().lower()
        changes["threat_type"] = ioc.threat_type
    if payload.severity is not None:
        ioc.severity = payload.severity
        changes["severity"] = ioc.severity
    if payload.confidence is not None:
        ioc.confidence = payload.confidence
        changes["confidence"] = ioc.confidence
    if payload.source is not None:
        ioc.source = payload.source.strip()
        changes["source"] = ioc.source
    if payload.description is not None:
        ioc.description = payload.description
        changes["description"] = ioc.description
    if payload.tags is not None:
        ioc.tags = payload.tags
        changes["tags"] = ioc.tags
    if payload.is_active is not None:
        ioc.is_active = payload.is_active
        changes["is_active"] = ioc.is_active

    ioc.last_seen = datetime.now(timezone.utc)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="threat_indicator_updated",
        resource_type="threat_indicator",
        resource_id=ioc.indicator_value,
        ip_address=request.client.host if request.client else None,
        details=changes,
        commit=False,
    )
    db.commit()
    db.refresh(ioc)
    return ThreatIndicatorRead.model_validate(ioc)


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_200_OK)
def delete_threat_indicator(
    indicator_id: int,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "analyst", "soc_lead")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ioc = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator {indicator_id} not found.",
        )
    val = ioc.indicator_value
    db.delete(ioc)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="threat_indicator_deleted",
        resource_type="threat_indicator",
        resource_id=val,
        ip_address=request.client.host if request.client else None,
        commit=False,
    )
    db.commit()
    return {"deleted": True, "indicator_value": val}


@router.get("/providers")
def get_provider_configuration() -> Dict[str, Any]:
    return provider_config.status_summary()


@router.put("/providers")
def update_provider_configuration(
    payload: ThreatProviderConfigUpdate,
    request: Request,
    actor: User = Depends(require_actor_roles("admin", "soc_lead")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    if payload.abuseipdb_api_key is not None:
        provider_config.abuseipdb_api_key = payload.abuseipdb_api_key.strip()
    if payload.virustotal_api_key is not None:
        provider_config.virustotal_api_key = payload.virustotal_api_key.strip()
    if payload.otx_api_key is not None:
        provider_config.otx_api_key = payload.otx_api_key.strip()
    provider_config.enable_external_lookup = payload.enable_external_lookup

    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="threat_intel_providers_updated",
        resource_type="system_config",
        resource_id="threat_intel_providers",
        ip_address=request.client.host if request.client else None,
        details={"enable_external_lookup": payload.enable_external_lookup},
    )
    return provider_config.status_summary()

