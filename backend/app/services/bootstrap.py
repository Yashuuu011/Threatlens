from datetime import datetime, timezone
import logging
import sys
from pathlib import Path
from typing import List
from sqlalchemy.orm import Session

# Ensure root project directory is importable for telemetry package
ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.core.config import settings
from app.core.security import get_password_hash
from app.detection.default_rules import DEFAULT_DETECTION_RULES
from app.ingestion.pipeline import EventIngestionPipeline
from app.models.entities import (
    Alert,
    DetectionRule,
    Incident,
    IncidentAlert,
    InvestigationNote,
    SecurityEvent,
    ThreatIndicator,
    User,
)
from telemetry.scenarios.catalog import generate_full_simulation_suite

logger = logging.getLogger("threatlens.bootstrap")

INITIAL_THREAT_INDICATORS = [
    {
        "indicator_type": "ip",
        "indicator_value": "185.220.101.42",
        "threat_type": "brute_force",
        "severity": "high",
        "confidence": 94,
        "source": "ThreatLens Curated IOC Feed",
        "description": "Known SSH brute-force and credential stuffing relay node.",
        "tags": ["ssh-bruteforce", "tor-exit", "credential-access"],
    },
    {
        "indicator_type": "ip",
        "indicator_value": "91.240.118.172",
        "threat_type": "botnet",
        "severity": "high",
        "confidence": 91,
        "source": "ThreatLens Curated IOC Feed",
        "description": "Distributed password spraying infrastructure targeting enterprise OAuth/SSO endpoints.",
        "tags": ["password-spraying", "oauth-target", "botnet"],
    },
    {
        "indicator_type": "ip",
        "indicator_value": "45.155.205.109",
        "threat_type": "suspicious_actor",
        "severity": "critical",
        "confidence": 89,
        "source": "Internal SOC Investigation",
        "description": "External adversary host associated with credential stuffing and CI runner compromise.",
        "tags": ["initial-access", "ci-compromise"],
    },
    {
        "indicator_type": "ip",
        "indicator_value": "203.0.113.250",
        "threat_type": "c2",
        "severity": "critical",
        "confidence": 98,
        "source": "ThreatLens Threat Intel Team",
        "description": "Confirmed Command & Control (C2) listener operating on TCP port 4444.",
        "tags": ["c2", "exfiltration", "port-4444"],
    },
    {
        "indicator_type": "ip",
        "indicator_value": "198.51.100.88",
        "threat_type": "scanner",
        "severity": "medium",
        "confidence": 78,
        "source": "Internal SOC Investigation",
        "description": "Unrecognized external network observed in off-hours bastion VPN logins.",
        "tags": ["unusual-login", "vpn-anomaly"],
    },
]


def seed_initial_data(db: Session, seed_telemetry: bool = True) -> None:
    """Seeds default users, 7 MITRE detection rules, curated IOCs, and initial synthetic telemetry."""
    # 1. Seed Users
    if db.query(User).count() == 0:
        default_users = [
            User(
                username=settings.INITIAL_ADMIN_USERNAME,
                email=settings.INITIAL_ADMIN_EMAIL,
                full_name="Elena Rostova (SOC Director)",
                hashed_password=get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            ),
            User(
                username=settings.INITIAL_ANALYST_USERNAME,
                email=settings.INITIAL_ANALYST_EMAIL,
                full_name="Marcus Vance (Senior SOC Analyst)",
                hashed_password=get_password_hash(settings.INITIAL_ANALYST_PASSWORD),
                role="analyst",
                is_active=True,
            ),
            User(
                username="ir.lead",
                email="ir.lead@threatlens.local",
                full_name="Sarah Lin (Incident Response Lead)",
                hashed_password=get_password_hash("ThreatLens!Lead2026"),
                role="soc_lead",
                is_active=True,
            ),
        ]
        db.add_all(default_users)
        db.commit()
        logger.info("Seeded default SOC users (admin, analyst, ir.lead).")

    # 2. Seed Detection Rules
    existing_rules = {r.rule_id: r for r in db.query(DetectionRule).all()}
    rules_added = 0
    rules_updated = 0
    for rule_def in DEFAULT_DETECTION_RULES:
        rid = rule_def["rule_id"]
        if rid not in existing_rules:
            db.add(DetectionRule(**rule_def))
            rules_added += 1
        else:
            existing_rule = existing_rules[rid]
            if (
                existing_rule.mitre_tactic != rule_def.get("mitre_tactic")
                or existing_rule.mitre_technique_id != rule_def.get("mitre_technique_id")
                or existing_rule.mitre_technique_name != rule_def.get("mitre_technique_name")
            ):
                existing_rule.mitre_tactic = rule_def.get("mitre_tactic")
                existing_rule.mitre_technique_id = rule_def.get("mitre_technique_id")
                existing_rule.mitre_technique_name = rule_def.get("mitre_technique_name")
                rules_updated += 1
    if rules_added or rules_updated:
        db.commit()
        logger.info("Seeded %d detection rules (%d updated).", rules_added, rules_updated)

    # 3. Seed Threat Indicators (IOCs)
    existing_iocs = {i[0] for i in db.query(ThreatIndicator.indicator_value).all()}
    iocs_added = 0
    now = datetime.now(timezone.utc)
    for ioc_def in INITIAL_THREAT_INDICATORS:
        if ioc_def["indicator_value"] not in existing_iocs:
            db.add(
                ThreatIndicator(
                    **ioc_def,
                    is_active=True,
                    first_seen=now,
                    last_seen=now,
                    hit_count=0,
                )
            )
            iocs_added += 1
    if iocs_added:
        db.commit()
        logger.info("Seeded %d threat intelligence IOCs.", iocs_added)

    # 4. Seed Initial Synthetic Telemetry & Investigation Workflow on empty DB
    if seed_telemetry and db.query(SecurityEvent).count() == 0:
        pipeline = EventIngestionPipeline(db)
        suite_events = generate_full_simulation_suite(base_time=now)
        res = pipeline.ingest_bulk(suite_events, run_detections=True)
        logger.info(
            "Seeded %d synthetic security events and generated %d alerts.",
            res.accepted_count,
            res.generated_alerts_count,
        )

        # Create a sample active Incident linking high/critical alerts so Incident Investigation is pre-populated
        alerts: List[Alert] = (
            db.query(Alert)
            .order_by(Alert.created_at.asc())
            .all()
        )
        if alerts and db.query(Incident).count() == 0:
            # Mark one alert as Investigating and one as Resolved to demonstrate realistic lifecycle
            primary_alerts = [a for a in alerts if a.rule_code in ("RULE-003", "RULE-005", "RULE-007")]
            if not primary_alerts:
                primary_alerts = alerts[:2]

            for pa in primary_alerts:
                pa.status = "Investigating"
                pa.assigned_to = "analyst"
                db.add(
                    InvestigationNote(
                        alert_id=pa.id,
                        author="analyst",
                        content=(
                            f"Triaged alert {pa.alert_id} ({pa.rule_name}). "
                            f"Correlating source IP {pa.source_ip} across authentication and network logs."
                        ),
                        note_type="triage_note",
                    )
                )

            inc = Incident(
                incident_id="INC-2026-0001",
                title="Multi-Stage Credential Compromise & Privilege Escalation Investigation",
                severity="critical",
                status="Investigating",
                description=(
                    "Correlated investigation of repeated authentication failures followed by "
                    "account compromise, unauthorized root privilege elevation, and outbound C2 activity "
                    "(synthetic telemetry baseline scenario)."
                ),
                assigned_analyst="analyst",
                created_by="admin",
                timeline_events=[
                    {
                        "timestamp": now.isoformat(),
                        "actor": "ThreatLens Detection Engine",
                        "action": "Alerts Generated",
                        "detail": f"Correlated {len(primary_alerts)} high/critical alerts from synthetic telemetry stream.",
                    },
                    {
                        "timestamp": now.isoformat(),
                        "actor": "analyst",
                        "action": "Incident Opened",
                        "detail": "Escalated correlated alerts to active incident INC-2026-0001 for containment analysis.",
                    },
                ],
                evidence_references=[
                    {
                        "type": "alert",
                        "reference": a.alert_id,
                        "description": f"{a.rule_code}: {a.title}",
                    }
                    for a in primary_alerts
                ],
            )
            db.add(inc)
            db.flush()

            for a in primary_alerts:
                db.add(
                    IncidentAlert(
                        incident_id=inc.id,
                        alert_id=a.id,
                        linked_by="analyst",
                    )
                )

            db.add(
                InvestigationNote(
                    incident_id=inc.id,
                    author="analyst",
                    content=(
                        "Initial forensic review confirms synthetic attack chain spanning "
                        "T1078 (Valid Accounts), T1548 (Privilege Escalation), and T1071 (C2 Protocol). "
                        "Host isolation workflow ready for execution."
                    ),
                    note_type="investigation_note",
                )
            )
            db.commit()

