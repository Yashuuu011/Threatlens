from typing import Any, Dict, List, Tuple
from pydantic import ValidationError
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.websocket import broadcast_sync_or_async
from app.detection.engine import ThreatDetectionEngine
from app.models.entities import Alert, Incident, SecurityEvent, ThreatIndicator
from app.schemas.api_schemas import BulkEventIngestResponse, SecurityEventCreate, SecurityEventRead


def _compute_live_dashboard_metrics(db: Session) -> Dict[str, Any]:
    return {
        "total_security_events": db.query(func.count(SecurityEvent.id)).scalar() or 0,
        "total_alerts": db.query(func.count(Alert.id)).scalar() or 0,
        "critical_alerts": db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0,
        "high_severity_alerts": db.query(func.count(Alert.id)).filter(Alert.severity == "high").scalar() or 0,
        "active_incidents": db.query(func.count(Incident.id)).filter(Incident.status.in_(["Open", "Investigating", "Contained"])).scalar() or 0,
        "resolved_incidents": db.query(func.count(Incident.id)).filter(Incident.status.in_(["Resolved", "Closed"])).scalar() or 0,
    }


def serialize_event(ev: SecurityEvent) -> SecurityEventRead:
    return SecurityEventRead(
        id=ev.id,
        event_id=ev.event_id,
        timestamp=ev.timestamp,
        source_ip=ev.source_ip,
        destination_ip=ev.destination_ip,
        destination_port=ev.destination_port,
        username=ev.username,
        hostname=ev.hostname,
        event_type=ev.event_type,
        event_category=ev.event_category,
        action=ev.action,
        status=ev.status,
        severity=ev.severity,
        raw_log=ev.raw_log,
        metadata=ev.event_metadata or {},
        is_synthetic=ev.is_synthetic,
        created_at=ev.created_at,
    )


class EventIngestionPipeline:
    """Validates, normalizes, persists, and evaluates incoming security telemetry."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def ingest_single(
        self,
        payload: SecurityEventCreate,
        run_detections: bool = True,
    ) -> Tuple[SecurityEvent, List[Alert]]:
        existing = (
            self.db.query(SecurityEvent)
            .filter(SecurityEvent.event_id == payload.event_id)
            .first()
        )
        if existing:
            return existing, []

        meta = dict(payload.metadata or {})
        dest_port = payload.destination_port
        if dest_port is None and "destination_port" in meta:
            try:
                dest_port = int(meta["destination_port"])
            except (TypeError, ValueError):
                dest_port = None
        elif dest_port is not None and "destination_port" not in meta:
            meta["destination_port"] = dest_port

        if payload.is_synthetic:
            meta["is_synthetic"] = True

        event_obj = SecurityEvent(
            event_id=payload.event_id,
            timestamp=payload.timestamp,
            source_ip=payload.source_ip,
            destination_ip=payload.destination_ip,
            destination_port=dest_port,
            username=payload.username,
            hostname=payload.hostname,
            event_type=payload.event_type,
            event_category=payload.event_category,
            action=payload.action,
            status=payload.status,
            severity=payload.severity,
            raw_log=payload.raw_log,
            event_metadata=meta,
            is_synthetic=payload.is_synthetic or bool(meta.get("is_synthetic", False)),
        )
        self.db.add(event_obj)
        self._update_ioc_hits([event_obj])
        self.db.commit()
        self.db.refresh(event_obj)

        broadcast_sync_or_async(
            "event_ingested",
            serialize_event(event_obj).model_dump(mode="json"),
        )

        alerts: List[Alert] = []
        if run_detections:
            engine = ThreatDetectionEngine(self.db)
            alerts = engine.evaluate_events([event_obj])

        broadcast_sync_or_async(
            "dashboard_metrics_updated",
            _compute_live_dashboard_metrics(self.db),
        )

        return event_obj, alerts

    def ingest_bulk(
        self,
        raw_events: List[Any],
        run_detections: bool = True,
    ) -> BulkEventIngestResponse:
        accepted_objs: List[SecurityEvent] = []
        errors: List[Dict[str, Any]] = []
        duplicate_count = 0

        # Pre-validate items safely
        validated_items: List[SecurityEventCreate] = []
        seen_batch_ids = set()

        for idx, raw_item in enumerate(raw_events):
            try:
                parsed = SecurityEventCreate.model_validate(raw_item)
                if parsed.event_id in seen_batch_ids:
                    duplicate_count += 1
                    continue
                seen_batch_ids.add(parsed.event_id)
                validated_items.append(parsed)
            except ValidationError as exc:
                errors.append(
                    {
                        "index": idx,
                        "event_id": raw_item.get("event_id") if isinstance(raw_item, dict) else None,
                        "error": exc.errors()[0].get("msg", "Validation error") if exc.errors() else str(exc),
                    }
                )
            except Exception as exc:
                errors.append(
                    {
                        "index": idx,
                        "error": str(exc),
                    }
                )

        if validated_items:
            candidate_ids = [item.event_id for item in validated_items]
            existing_ids = {
                row[0]
                for row in self.db.query(SecurityEvent.event_id)
                .filter(SecurityEvent.event_id.in_(candidate_ids))
                .all()
            }

            for item in validated_items:
                if item.event_id in existing_ids:
                    duplicate_count += 1
                    continue

                meta = dict(item.metadata or {})
                dest_port = item.destination_port
                if dest_port is None and "destination_port" in meta:
                    try:
                        dest_port = int(meta["destination_port"])
                    except (TypeError, ValueError):
                        dest_port = None
                elif dest_port is not None and "destination_port" not in meta:
                    meta["destination_port"] = dest_port

                if item.is_synthetic:
                    meta["is_synthetic"] = True

                ev_obj = SecurityEvent(
                    event_id=item.event_id,
                    timestamp=item.timestamp,
                    source_ip=item.source_ip,
                    destination_ip=item.destination_ip,
                    destination_port=dest_port,
                    username=item.username,
                    hostname=item.hostname,
                    event_type=item.event_type,
                    event_category=item.event_category,
                    action=item.action,
                    status=item.status,
                    severity=item.severity,
                    raw_log=item.raw_log,
                    event_metadata=meta,
                    is_synthetic=item.is_synthetic or bool(meta.get("is_synthetic", False)),
                )
                self.db.add(ev_obj)
                accepted_objs.append(ev_obj)

            if accepted_objs:
                self._update_ioc_hits(accepted_objs)
                self.db.commit()
                for ev in accepted_objs:
                    self.db.refresh(ev)

        generated_alerts: List[Alert] = []
        if run_detections and accepted_objs:
            engine = ThreatDetectionEngine(self.db)
            generated_alerts = engine.evaluate_events(accepted_objs)

        if accepted_objs:
            broadcast_sync_or_async(
                "bulk_events_ingested",
                {
                    "accepted_count": len(accepted_objs),
                    "generated_alerts_count": len(generated_alerts),
                    "latest_event": serialize_event(accepted_objs[-1]).model_dump(mode="json"),
                },
            )
            broadcast_sync_or_async(
                "dashboard_metrics_updated",
                _compute_live_dashboard_metrics(self.db),
            )

        return BulkEventIngestResponse(
            accepted_count=len(accepted_objs),
            rejected_count=len(errors),
            duplicate_count=duplicate_count,
            generated_alerts_count=len(generated_alerts),
            generated_alert_ids=[a.alert_id for a in generated_alerts],
            errors=errors,
        )

    def _update_ioc_hits(self, events: List[SecurityEvent]) -> None:
        ips = set()
        for ev in events:
            if ev.source_ip:
                ips.add(ev.source_ip)
            if ev.destination_ip:
                ips.add(ev.destination_ip)
        if not ips:
            return
        matched_iocs = (
            self.db.query(ThreatIndicator)
            .filter(ThreatIndicator.indicator_value.in_(list(ips)))
            .all()
        )
        for ioc in matched_iocs:
            ioc.hit_count = (ioc.hit_count or 0) + 1
            ioc.last_seen = events[-1].timestamp

