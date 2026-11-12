from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import sys
from pathlib import Path
from typing import Any, Dict
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

# Ensure root project directory is in sys.path so `telemetry` package is always resolvable
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.api.alerts import router as alerts_router
from app.api.analytics_reports import analytics_router, reports_router
from app.api.auth import router as auth_router
from app.api.detections import router as detections_router
from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.api.system import get_system_health, router as system_router
from app.api.threat_intel import router as threat_intel_router
from app.core.config import settings
from app.core.database import Base, SessionLocal, engine, get_db
from app.core.websocket import ws_manager
from app.models.entities import Alert, DetectionRule, Incident, SecurityEvent, ThreatIndicator
from app.services.bootstrap import seed_initial_data

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threatlens.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_initial_data(db, seed_telemetry=True)
    except Exception as exc:
        logger.error("Error during initial database seed: %s", exc)
    finally:
        db.close()
    yield


app = FastAPI(
    title="ThreatLens SIEM & Security Operations API",
    description=(
        "Intelligent Security Operations, Event Ingestion, Rule-Based Threat Detection, "
        "MITRE ATT&CK Correlation, Alert Triage, and Incident Investigation Platform."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
            "path": request.url.path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": jsonable_encoder(exc.errors()),
            "status_code": 422,
            "error": "Validation Error",
            "path": request.url.path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    logger.error("Database error on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "A database error occurred while processing the request.",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "error": "Database Error",
            "path": request.url.path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

app.include_router(auth_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(threat_intel_router)
app.include_router(analytics_router)
app.include_router(reports_router)
app.include_router(system_router)


@app.get("/api/health", tags=["Health Check"])
def root_health_check(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Direct health-check API reporting real backend and PostgreSQL connectivity."""
    return get_system_health(db=db)


@app.get("/api/search", tags=["Global Search"])
def global_search(
    q: str = Query(..., min_length=1, description="Global SOC search query"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    term = f"%{q.strip()}%"
    alerts = (
        db.query(Alert)
        .filter(
            or_(
                Alert.alert_id.ilike(term),
                Alert.title.ilike(term),
                Alert.source_ip.ilike(term),
                Alert.username.ilike(term),
                Alert.rule_code.ilike(term),
            )
        )
        .order_by(Alert.last_seen.desc())
        .limit(6)
        .all()
    )
    events = (
        db.query(SecurityEvent)
        .filter(
            or_(
                SecurityEvent.event_id.ilike(term),
                SecurityEvent.source_ip.ilike(term),
                SecurityEvent.username.ilike(term),
                SecurityEvent.hostname.ilike(term),
                SecurityEvent.event_type.ilike(term),
                SecurityEvent.raw_log.ilike(term),
            )
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(6)
        .all()
    )
    incidents = (
        db.query(Incident)
        .filter(
            or_(
                Incident.incident_id.ilike(term),
                Incident.title.ilike(term),
                Incident.description.ilike(term),
            )
        )
        .order_by(Incident.created_at.desc())
        .limit(5)
        .all()
    )
    rules = (
        db.query(DetectionRule)
        .filter(
            or_(
                DetectionRule.rule_id.ilike(term),
                DetectionRule.name.ilike(term),
                DetectionRule.mitre_technique_id.ilike(term),
            )
        )
        .limit(5)
        .all()
    )
    iocs = (
        db.query(ThreatIndicator)
        .filter(
            or_(
                ThreatIndicator.indicator_value.ilike(term),
                ThreatIndicator.threat_type.ilike(term),
            )
        )
        .limit(5)
        .all()
    )

    return {
        "query": q.strip(),
        "alerts": [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "source_ip": a.source_ip,
            }
            for a in alerts
        ],
        "events": [
            {
                "id": e.id,
                "event_id": e.event_id,
                "event_type": e.event_type,
                "event_category": e.event_category,
                "source_ip": e.source_ip,
                "username": e.username,
                "severity": e.severity,
            }
            for e in events
        ],
        "incidents": [
            {
                "id": i.id,
                "incident_id": i.incident_id,
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
            }
            for i in incidents
        ],
        "rules": [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "name": r.name,
                "mitre_technique_id": r.mitre_technique_id,
                "severity": r.severity,
            }
            for r in rules
        ],
        "indicators": [
            {
                "id": t.id,
                "indicator_value": t.indicator_value,
                "threat_type": t.threat_type,
                "severity": t.severity,
            }
            for t in iocs
        ],
    }


@app.websocket("/ws")
@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    import json
    from app.core.security import decode_access_token

    token = websocket.query_params.get("token")
    authenticated_user: str | None = None
    if token:
        decoded = decode_access_token(token)
        if not decoded or "sub" not in decoded:
            await websocket.close(code=1008, reason="Invalid or expired JWT token")
            return
        authenticated_user = str(decoded.get("sub"))

    await ws_manager.connect(websocket)
    try:
        await websocket.send_json(
            {
                "seq": ws_manager.latest_seq,
                "type": "connection_established",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {
                    "status": "connected",
                    "message": "ThreatLens Real-Time Telemetry Stream Active",
                    "active_connections": len(ws_manager.active_connections),
                    "latest_seq": ws_manager.latest_seq,
                    "authenticated_user": authenticated_user,
                    "polling_fallback_endpoint": "/api/system/realtime/poll",
                },
            }
        )
        while True:
            msg = await websocket.receive_text()
            raw = msg.strip()
            if raw == "ping":
                await websocket.send_json(
                    {
                        "seq": ws_manager.latest_seq,
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "data": {
                            "status": "alive",
                            "active_connections": len(ws_manager.active_connections),
                            "latest_seq": ws_manager.latest_seq,
                        },
                    }
                )
                continue
            try:
                parsed = json.loads(raw)
                msg_type = parsed.get("type") or parsed.get("action")
                if msg_type == "ping":
                    await websocket.send_json(
                        {
                            "seq": ws_manager.latest_seq,
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "data": {
                                "status": "alive",
                                "active_connections": len(ws_manager.active_connections),
                                "latest_seq": ws_manager.latest_seq,
                            },
                        }
                    )
                elif msg_type == "sync":
                    since_seq = int(parsed.get("since_seq", 0) or 0)
                    await websocket.send_json(
                        {
                            "seq": ws_manager.latest_seq,
                            "type": "sync_snapshot",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "data": ws_manager.get_poll_snapshot(since_seq=since_seq),
                        }
                    )
            except Exception:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)


