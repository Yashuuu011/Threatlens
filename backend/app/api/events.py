from datetime import datetime, timedelta, timezone
import math
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import require_actor_roles
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.ingestion.pipeline import EventIngestionPipeline, serialize_event
from app.models.entities import Alert, AlertEvidence, SecurityEvent, User
from app.schemas.api_schemas import (
    BulkEventIngestRequest,
    BulkEventIngestResponse,
    PaginatedEventsResponse,
    SecurityEventCreate,
)
from app.services.audit import record_audit_log

router = APIRouter(prefix="/api/events", tags=["Security Events & Ingestion"])


@router.post("", status_code=status.HTTP_201_CREATED)
def ingest_event(
    payload: SecurityEventCreate,
    request: Request,
    run_detections: bool = Query(default=True),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    enforce_rate_limit(
        request,
        scope="event_ingest",
        max_requests=settings.RATE_LIMIT_INGEST_PER_MINUTE,
        window_seconds=60,
    )
    pipeline = EventIngestionPipeline(db)
    ev, alerts = pipeline.ingest_single(payload, run_detections=run_detections)
    return {
        "event": serialize_event(ev).model_dump(mode="json"),
        "generated_alerts_count": len(alerts),
        "generated_alert_ids": [a.alert_id for a in alerts],
    }


@router.post("/bulk", response_model=BulkEventIngestResponse)
def ingest_bulk_events(
    payload: BulkEventIngestRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> BulkEventIngestResponse:
    enforce_rate_limit(
        request,
        scope="event_ingest_bulk",
        max_requests=settings.RATE_LIMIT_INGEST_PER_MINUTE,
        window_seconds=60,
    )
    pipeline = EventIngestionPipeline(db)
    return pipeline.ingest_bulk(payload.events, run_detections=payload.run_detections)


@router.get("", response_model=PaginatedEventsResponse)
def list_events(
    search: Optional[str] = Query(default=None, description="Search IP, username, hostname, event_type, or raw log"),
    source_ip: Optional[str] = Query(default=None),
    destination_ip: Optional[str] = Query(default=None),
    username: Optional[str] = Query(default=None),
    hostname: Optional[str] = Query(default=None),
    event_category: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    is_synthetic: Optional[bool] = Query(default=None),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    sort_by: str = Query(
        default="timestamp",
        pattern="^(timestamp|severity|source_ip|destination_ip|event_category|event_type|username|hostname|status|created_at|id)$",
    ),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
) -> PaginatedEventsResponse:
    query = db.query(SecurityEvent)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SecurityEvent.event_id.ilike(term),
                SecurityEvent.source_ip.ilike(term),
                SecurityEvent.destination_ip.ilike(term),
                SecurityEvent.username.ilike(term),
                SecurityEvent.hostname.ilike(term),
                SecurityEvent.event_type.ilike(term),
                SecurityEvent.action.ilike(term),
                SecurityEvent.raw_log.ilike(term),
            )
        )

    if source_ip and source_ip.strip():
        query = query.filter(SecurityEvent.source_ip.ilike(f"%{source_ip.strip()}%"))
    if destination_ip and destination_ip.strip():
        query = query.filter(SecurityEvent.destination_ip.ilike(f"%{destination_ip.strip()}%"))
    if username and username.strip():
        query = query.filter(SecurityEvent.username.ilike(f"%{username.strip()}%"))
    if hostname and hostname.strip():
        query = query.filter(SecurityEvent.hostname.ilike(f"%{hostname.strip()}%"))
    if event_category and event_category.strip() and event_category.lower() != "all":
        query = query.filter(SecurityEvent.event_category.ilike(event_category.strip()))
    if severity and severity.strip() and severity.lower() != "all":
        query = query.filter(SecurityEvent.severity == severity.strip().lower())
    if status_filter and status_filter.strip() and status_filter.lower() != "all":
        query = query.filter(SecurityEvent.status == status_filter.strip().lower())
    if is_synthetic is not None:
        query = query.filter(SecurityEvent.is_synthetic.is_(is_synthetic))
    if start_time is not None:
        query = query.filter(SecurityEvent.timestamp >= start_time)
    if end_time is not None:
        query = query.filter(SecurityEvent.timestamp <= end_time)

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    sort_col = getattr(SecurityEvent, sort_by, SecurityEvent.timestamp)
    primary_order = sort_col.asc() if sort_order.lower() == "asc" else sort_col.desc()
    secondary_order = SecurityEvent.id.asc() if sort_order.lower() == "asc" else SecurityEvent.id.desc()

    rows = (
        query.order_by(primary_order, secondary_order)
        .offset(offset)
        .limit(page_size)
        .all()
    )

    return PaginatedEventsResponse(
        items=[serialize_event(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{event_identifier}")
def get_event_detail(
    event_identifier: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ev: Optional[SecurityEvent] = None
    if event_identifier.isdigit():
        ev = db.query(SecurityEvent).filter(SecurityEvent.id == int(event_identifier)).first()
    if not ev:
        ev = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_identifier).first()

    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_identifier}' not found.",
        )

    # Related event correlation: same source_ip or same username within +/- 15 minutes
    ts = ev.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    w_start = ts - timedelta(minutes=15)
    w_end = ts + timedelta(minutes=15)

    corr_filters = [SecurityEvent.source_ip == ev.source_ip]
    if ev.username:
        corr_filters.append(SecurityEvent.username == ev.username)

    related_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.id != ev.id,
            or_(*corr_filters),
            SecurityEvent.timestamp >= w_start,
            SecurityEvent.timestamp <= w_end,
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(15)
        .all()
    )

    # Linked alerts via AlertEvidence
    linked_alerts = (
        db.query(Alert)
        .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
        .filter(AlertEvidence.event_id == ev.id)
        .all()
    )

    return {
        "event": serialize_event(ev).model_dump(mode="json"),
        "related_events": [serialize_event(r).model_dump(mode="json") for r in related_events],
        "linked_alerts": [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "rule_code": a.rule_code,
            }
            for a in linked_alerts
        ],
    }


@router.delete("/{event_identifier}")
def delete_event(
    event_identifier: str,
    request: Request,
    actor: User = Depends(require_actor_roles("admin")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    ev: Optional[SecurityEvent] = None
    if event_identifier.isdigit():
        ev = db.query(SecurityEvent).filter(SecurityEvent.id == int(event_identifier)).first()
    if not ev:
        ev = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_identifier).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_identifier}' not found.",
        )

    ev_code = ev.event_id
    db.delete(ev)
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="security_event_deleted",
        resource_type="security_event",
        resource_id=ev_code,
        ip_address=request.client.host if request.client else None,
        commit=False,
    )
    db.commit()
    return {"deleted": True, "event_id": ev_code}


