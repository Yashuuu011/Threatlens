from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_actor_or_default
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.entities import User
from app.services.analytics_service import (
    compute_analytics_and_detection_metrics,
    generate_csv_report,
    generate_incident_csv_report,
    generate_incident_pdf_report,
    generate_incident_report_data,
    generate_pdf_report,
    get_overview_dashboard_data,
)
from app.services.audit import record_audit_log

analytics_router = APIRouter(prefix="/api/analytics", tags=["Analytics & SOC Metrics"])
reports_router = APIRouter(prefix="/api/reports", tags=["Reports & Exports"])


@analytics_router.get("")
@analytics_router.get("/overview")
def get_dashboard_overview(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return get_overview_dashboard_data(db)


@analytics_router.get("/performance")
def get_analytics_performance(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return compute_analytics_and_detection_metrics(db)


@analytics_router.get("/detection-accuracy")
def get_detection_accuracy_metrics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    data = compute_analytics_and_detection_metrics(db)
    return {
        "generated_at": data["generated_at"],
        "detection_evaluation": data["detection_evaluation"],
        "rule_performance": data["rule_performance"],
    }


@analytics_router.get("/incidents")
def get_incident_resolution_analytics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    data = compute_analytics_and_detection_metrics(db)
    return {
        "generated_at": data["generated_at"],
        "incident_resolution_stats": data["incident_resolution_stats"],
        "incidents_summary": data["incidents_summary"],
    }


@reports_router.get("")
def get_report_summary(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return compute_analytics_and_detection_metrics(db)


@reports_router.get("/export/csv")
def export_report_as_csv(
    request: Request,
    actor: User = Depends(get_actor_or_default),
    db: Session = Depends(get_db),
) -> Response:
    enforce_rate_limit(
        request,
        scope="report_export",
        max_requests=settings.RATE_LIMIT_EXPORT_PER_MINUTE,
        window_seconds=60,
    )
    csv_content = generate_csv_report(db)
    filename = f"threatlens_soc_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="report_exported_csv",
        resource_type="report",
        resource_id=filename,
        ip_address=request.client.host if request.client else None,
        details={"format": "csv", "scope": "soc_analytics"},
    )
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@reports_router.get("/export/pdf")
def export_report_as_pdf(
    request: Request,
    actor: User = Depends(get_actor_or_default),
    db: Session = Depends(get_db),
) -> Response:
    enforce_rate_limit(
        request,
        scope="report_export",
        max_requests=settings.RATE_LIMIT_EXPORT_PER_MINUTE,
        window_seconds=60,
    )
    pdf_bytes = generate_pdf_report(db)
    filename = f"threatlens_soc_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="report_exported_pdf",
        resource_type="report",
        resource_id=filename,
        ip_address=request.client.host if request.client else None,
        details={"format": "pdf", "scope": "soc_analytics"},
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@reports_router.get("/incidents/{incident_identifier}")
def get_incident_investigation_report(
    incident_identifier: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    return generate_incident_report_data(db, incident_identifier)


@reports_router.get("/incidents/{incident_identifier}/csv")
@reports_router.get("/export/incident/{incident_identifier}/csv")
def export_incident_report_as_csv(
    incident_identifier: str,
    request: Request,
    actor: User = Depends(get_actor_or_default),
    db: Session = Depends(get_db),
) -> Response:
    enforce_rate_limit(
        request,
        scope="report_export",
        max_requests=settings.RATE_LIMIT_EXPORT_PER_MINUTE,
        window_seconds=60,
    )
    csv_content = generate_incident_csv_report(db, incident_identifier)
    filename = f"threatlens_incident_{incident_identifier}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_report_exported_csv",
        resource_type="incident_report",
        resource_id=str(incident_identifier),
        ip_address=request.client.host if request.client else None,
        details={"format": "csv", "incident_identifier": incident_identifier},
    )
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@reports_router.get("/incidents/{incident_identifier}/pdf")
@reports_router.get("/export/incident/{incident_identifier}/pdf")
def export_incident_report_as_pdf(
    incident_identifier: str,
    request: Request,
    actor: User = Depends(get_actor_or_default),
    db: Session = Depends(get_db),
) -> Response:
    enforce_rate_limit(
        request,
        scope="report_export",
        max_requests=settings.RATE_LIMIT_EXPORT_PER_MINUTE,
        window_seconds=60,
    )
    pdf_bytes = generate_incident_pdf_report(db, incident_identifier)
    filename = f"threatlens_incident_{incident_identifier}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    record_audit_log(
        db,
        actor_username=actor.username,
        actor_role=actor.role,
        action="incident_report_exported_pdf",
        resource_type="incident_report",
        resource_id=str(incident_identifier),
        ip_address=request.client.host if request.client else None,
        details={"format": "pdf", "incident_identifier": incident_identifier},
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


