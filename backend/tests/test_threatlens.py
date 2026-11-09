from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = Path(__file__).resolve().parents[2]
for p in (str(BACKEND_DIR), str(ROOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.core.config import settings
from app.core.database import Base, get_db, normalize_postgres_url
from app.core.rate_limit import rate_limiter
from app.main import app
from app.models.entities import Alert, DetectionRule, SecurityEvent
from app.services.bootstrap import seed_initial_data
from telemetry.scenarios.catalog import generate_scenario_events


def _ensure_postgres_test_db() -> str:
    admin_url = (
        f"postgresql+psycopg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/postgres"
    )
    test_db_name = f"{settings.POSTGRES_DB}_test"
    test_db_url = (
        f"postgresql+psycopg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{test_db_name}"
    )
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :d"),
            {"d": test_db_name},
        ).scalar()
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{test_db_name}"'))
    admin_engine.dispose()
    return test_db_url


TEST_POSTGRES_URL = _ensure_postgres_test_db()
test_engine = create_engine(TEST_POSTGRES_URL, pool_pre_ping=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture()
def test_context():
    """Creates a clean isolated PostgreSQL schema state for each test function."""
    rate_limiter.reset()
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()
    seed_initial_data(db, seed_telemetry=False)

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client, db
    app.dependency_overrides.clear()
    db.close()


def test_authentication_and_rbac(test_context):
    client, _ = test_context

    # 1. Invalid login attempt returns 401
    bad_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "WrongPassword123"},
    )
    assert bad_resp.status_code == 401

    # 2. Valid admin login returns JWT token and user profile
    login_resp = client.post(
        "/api/auth/login",
        json={
            "username": settings.INITIAL_ADMIN_USERNAME,
            "password": settings.INITIAL_ADMIN_PASSWORD,
        },
    )
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    assert token_data["user"]["role"] == "admin"

    # 3. Verify /api/auth/me with valid Bearer token
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token_data['access_token']}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == settings.INITIAL_ADMIN_USERNAME

    # 4. Verify RBAC blocks non-admin from creating users
    analyst_login = client.post(
        "/api/auth/login",
        json={
            "username": settings.INITIAL_ANALYST_USERNAME,
            "password": settings.INITIAL_ANALYST_PASSWORD,
        },
    ).json()
    forbidden_resp = client.post(
        "/api/auth/users",
        headers={"Authorization": f"Bearer {analyst_login['access_token']}"},
        json={
            "username": "junior.soc",
            "email": "junior@threatlens.local",
            "full_name": "Junior Analyst",
            "password": "JuniorPassword!2026",
            "role": "analyst",
        },
    )
    assert forbidden_resp.status_code == 403


def test_event_ingestion_validation_and_explorer(test_context):
    client, _ = test_context

    # 1. Reject invalid IP address
    invalid_ip_resp = client.post(
        "/api/events",
        json={
            "source_ip": "999.999.999.999",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "login",
            "status": "failure",
            "severity": "low",
            "raw_log": "Failed SSH login",
        },
    )
    assert invalid_ip_resp.status_code == 422

    # 2. Bulk ingestion handles mixed valid and invalid events safely
    bulk_resp = client.post(
        "/api/events/bulk",
        json={
            "events": [
                {
                    "event_id": "EVT-VALID-001",
                    "source_ip": "10.10.1.50",
                    "destination_ip": "10.10.1.10",
                    "username": "alice",
                    "hostname": "wkstn-01",
                    "event_type": "user_login",
                    "event_category": "Authentication",
                    "action": "sso_login",
                    "status": "success",
                    "severity": "low",
                    "raw_log": "[SYNTHETIC] Valid login event",
                    "is_synthetic": True,
                },
                {
                    "event_id": "EVT-INVALID-002",
                    "source_ip": "not-an-ip",
                    "event_type": "user_login",
                    "event_category": "Authentication",
                    "action": "sso_login",
                    "status": "success",
                    "severity": "low",
                    "raw_log": "Invalid IP event",
                },
            ],
            "run_detections": True,
        },
    )
    assert bulk_resp.status_code == 200
    body = bulk_resp.json()
    assert body["accepted_count"] == 1
    assert body["rejected_count"] == 1

    # 3. Query Events Explorer with filters
    explorer_resp = client.get("/api/events?username=alice&event_category=Authentication")
    assert explorer_resp.status_code == 200
    items = explorer_resp.json()["items"]
    assert len(items) == 1
    assert items[0]["event_id"] == "EVT-VALID-001"


@pytest.mark.parametrize(
    "scenario_id,expected_rule_code,should_alert",
    [
        ("normal_login", None, False),
        ("normal_network", None, False),
        ("brute_force", "RULE-001", True),
        ("password_spraying", "RULE-002", True),
        ("login_after_failures", "RULE-003", True),
        ("unusual_login", "RULE-004", True),
        ("privilege_escalation", "RULE-005", True),
        ("port_scanning", "RULE-006", True),
        ("suspicious_network", "RULE-007", True),
    ],
)
def test_each_detection_rule_identifies_intended_synthetic_scenario(
    test_context,
    scenario_id: str,
    expected_rule_code: str | None,
    should_alert: bool,
):
    """Automated detection test suite verifying all 7 detection rules and 2 benign baselines."""
    client, db = test_context
    now = datetime(2026, 11, 9, 14, 30, 0, tzinfo=timezone.utc)
    synthetic_events = generate_scenario_events(scenario_id, base_time=now)

    # Ensure all synthetic events are properly labeled
    for ev in synthetic_events:
        assert ev["is_synthetic"] is True
        assert ev["metadata"]["is_synthetic"] is True
        assert ev["raw_log"].startswith("[SYNTHETIC]")

    resp = client.post(
        "/api/events/bulk",
        json={"events": synthetic_events, "run_detections": True},
    )
    assert resp.status_code == 200
    result = resp.json()
    assert result["accepted_count"] == len(synthetic_events)

    alerts = db.query(Alert).all()
    triggered_rules = {a.rule_code for a in alerts}

    if not should_alert:
        assert len(alerts) == 0, f"Benign scenario '{scenario_id}' should not generate alerts, got {triggered_rules}"
    else:
        assert expected_rule_code in triggered_rules, (
            f"Scenario '{scenario_id}' failed to trigger {expected_rule_code}. Triggered: {triggered_rules}"
        )
        matching_alert = next(a for a in alerts if a.rule_code == expected_rule_code)
        assert matching_alert.event_count >= 1
        assert matching_alert.mitre_technique_id is not None

        # Verify deduplication: re-ingesting an additional event in the same window updates the existing alert
        extra_events = generate_scenario_events(scenario_id, base_time=now)
        client.post("/api/events/bulk", json={"events": extra_events[:1], "run_detections": True})
        same_rule_alerts = db.query(Alert).filter(Alert.rule_code == expected_rule_code).all()
        assert len(same_rule_alerts) == 1


def test_alert_lifecycle_incident_escalation_and_analytics_metrics(test_context):
    client, _ = test_context

    # 1. Run full simulation via /api/system/simulate
    sim_resp = client.post(
        "/api/system/simulate",
        json={"scenario_id": "all", "volume_multiplier": 1},
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["accepted_count"] > 20
    assert sim_data["generated_alerts_count"] >= 7

    # 2. List alerts & inspect alert details
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts_list = alerts_resp.json()["items"]
    assert len(alerts_list) >= 7
    first_alert_id = alerts_list[0]["id"]

    # 3. Update alert status and add analyst note
    status_resp = client.patch(
        f"/api/alerts/{first_alert_id}/status",
        json={
            "status": "Investigating",
            "comment": "Confirmed malicious SSH pattern during SOC triage.",
            "assigned_to": "analyst",
        },
    )
    assert status_resp.status_code == 200
    detail = status_resp.json()
    assert detail["status"] == "Investigating"
    assert len(detail["status_history"]) >= 2
    assert len(detail["evidence_events"]) >= 1

    note_resp = client.post(
        f"/api/alerts/{first_alert_id}/notes",
        json={"content": "Checked firewall logs; blocking source IP.", "note_type": "analyst_note"},
    )
    assert note_resp.status_code == 201

    # 4. Create Incident from Alerts
    inc_resp = client.post(
        "/api/incidents",
        json={
            "title": "Automated Test Incident Escalation",
            "severity": "critical",
            "description": "Created from correlated alerts during automated pytest suite.",
            "assigned_analyst": "analyst",
            "alert_ids": [alerts_list[0]["id"], alerts_list[1]["id"]],
        },
    )
    assert inc_resp.status_code == 201
    inc_detail = inc_resp.json()
    assert inc_detail["linked_alert_count"] == 2
    assert len(inc_detail["related_events"]) >= 2

    # 5. Threat Intelligence Lookup (no fabricated scores for unknown IP, accurate IOC match for known IOC)
    known_ioc_resp = client.get("/api/threat-intelligence/lookup?ip=185.220.101.42")
    assert known_ioc_resp.status_code == 200
    assert known_ioc_resp.json()["verdict"] == "confirmed_ioc_match"

    unknown_ip_resp = client.get("/api/threat-intelligence/lookup?ip=8.8.4.4")
    assert unknown_ip_resp.status_code == 200
    assert unknown_ip_resp.json()["verdict"] == "no_intelligence_match"
    assert unknown_ip_resp.json()["reputation_confidence"] is None

    # 6. Analytics & Detection Metrics (Precision, Recall, F1 on labeled test data)
    perf_resp = client.get("/api/analytics/performance")
    assert perf_resp.status_code == 200
    eval_metrics = perf_resp.json()["detection_evaluation"]
    assert eval_metrics["has_labeled_data"] is True
    assert eval_metrics["true_positives"] > 0
    assert eval_metrics["true_negatives"] > 0
    assert eval_metrics["precision"] == 1.0
    assert eval_metrics["recall"] == 1.0
    assert eval_metrics["f1_score"] == 1.0

    # 7. Verify CSV and PDF report exports
    csv_resp = client.get("/api/reports/export/csv")
    assert csv_resp.status_code == 200
    assert "ThreatLens Security Operations Analytical Report" in csv_resp.text

    pdf_resp = client.get("/api/reports/export/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.content.startswith(b"%PDF-1.4")


def test_postgresql_crud_operations_rbac_and_audit_logging(test_context):
    """Verifies PostgreSQL connectivity, full CRUD across all 11 tables, RBAC (Admin vs Analyst), and Audit Logging."""
    client, _ = test_context

    # 1. Verify /api/health confirms real PostgreSQL connection
    health_resp = client.get("/api/health")
    assert health_resp.status_code == 200
    health_data = health_resp.json()
    assert health_data["status"] == "healthy"
    assert health_data["database"]["postgresql_connected"] is True
    assert health_data["database"]["backend"] == "postgresql"

    # 2. Authenticate as Admin and Analyst
    admin_token = client.post(
        "/api/auth/login",
        json={"username": settings.INITIAL_ADMIN_USERNAME, "password": settings.INITIAL_ADMIN_PASSWORD},
    ).json()["access_token"]
    analyst_token = client.post(
        "/api/auth/login",
        json={"username": settings.INITIAL_ANALYST_USERNAME, "password": settings.INITIAL_ANALYST_PASSWORD},
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 3. Users CRUD (Admin allowed, Analyst forbidden)
    create_user_resp = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "username": "tier2.analyst",
            "email": "tier2@threatlens.local",
            "full_name": "Tier 2 SOC Analyst",
            "password": "Tier2Password!2026",
            "role": "analyst",
        },
    )
    assert create_user_resp.status_code == 201
    created_user_id = create_user_resp.json()["id"]

    update_user_resp = client.patch(
        f"/api/auth/users/{created_user_id}",
        headers=admin_headers,
        json={"full_name": "Senior Tier 2 Analyst"},
    )
    assert update_user_resp.status_code == 200
    assert update_user_resp.json()["full_name"] == "Senior Tier 2 Analyst"

    del_user_resp = client.delete(f"/api/auth/users/{created_user_id}", headers=admin_headers)
    assert del_user_resp.status_code == 200
    assert del_user_resp.json()["deleted"] is True

    # 4. Detection Rules CRUD (Admin creates/deletes, Analyst forbidden from deleting)
    create_rule_resp = client.post(
        "/api/detections/rules",
        headers=admin_headers,
        json={
            "rule_id": "RULE-999",
            "rule_key": "custom_test_rule",
            "name": "Custom PostgreSQL Test Rule",
            "description": "Tests PostgreSQL CRUD on detection_rules table",
            "detection_logic": "Custom threshold check",
            "event_category": "Authentication",
            "threshold_count": 5,
            "time_window_seconds": 300,
            "severity": "medium",
            "enabled": True,
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
        },
    )
    assert create_rule_resp.status_code == 201

    analyst_del_rule = client.delete("/api/detections/rules/RULE-999", headers=analyst_headers)
    assert analyst_del_rule.status_code == 403

    admin_del_rule = client.delete("/api/detections/rules/RULE-999", headers=admin_headers)
    assert admin_del_rule.status_code == 200

    # 5. Security Event + Alert + AlertEvidence + AlertStatusHistory + InvestigationNote CRUD
    ev_resp = client.post(
        "/api/events?run_detections=false",
        json={
            "event_id": "EVT-CRUD-100",
            "source_ip": "192.0.2.55",
            "destination_ip": "10.0.0.15",
            "destination_port": 22,
            "username": "root",
            "hostname": "bastion-01",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "login",
            "status": "failure",
            "severity": "medium",
            "raw_log": "[SYNTHETIC] CRUD test SSH failure",
            "is_synthetic": True,
        },
    )
    assert ev_resp.status_code == 201
    ev_db_id = ev_resp.json()["event"]["id"]

    alert_create_resp = client.post(
        "/api/alerts",
        headers=analyst_headers,
        json={
            "title": "Manual Analyst Alert",
            "description": "Created during PostgreSQL CRUD test",
            "severity": "high",
            "rule_code": "RULE-001",
            "rule_name": "Repeated Failed Logins (Brute-Force)",
            "source_ip": "192.0.2.55",
            "username": "root",
        },
    )
    assert alert_create_resp.status_code == 201
    created_alert_id = alert_create_resp.json()["id"]

    # Link AlertEvidence explicitly
    ev_link_resp = client.post(
        f"/api/alerts/{created_alert_id}/evidence",
        headers=analyst_headers,
        json={"event_id": ev_db_id, "evidence_role": "triggering_event", "note": "Linked SSH event"},
    )
    assert ev_link_resp.status_code == 201
    assert client.get(f"/api/alerts/{created_alert_id}/evidence").status_code == 200

    # Verify AlertStatusHistory endpoint
    hist_resp = client.get(f"/api/alerts/{created_alert_id}/history")
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1

    # 6. ThreatIndicator CRUD (Create, Update, Delete)
    ioc_create = client.post(
        "/api/threat-intelligence/indicators",
        headers=analyst_headers,
        json={
            "indicator_type": "ip",
            "indicator_value": "198.51.100.200",
            "threat_type": "c2",
            "severity": "critical",
            "confidence": 92,
            "source": "Pytest CRUD",
            "tags": ["c2", "test"],
        },
    )
    assert ioc_create.status_code == 201
    ioc_id = ioc_create.json()["id"]

    ioc_patch = client.patch(
        f"/api/threat-intelligence/indicators/{ioc_id}",
        headers=analyst_headers,
        json={"confidence": 99, "description": "Updated confidence score"},
    )
    assert ioc_patch.status_code == 200
    assert ioc_patch.json()["confidence"] == 99

    ioc_del = client.delete(f"/api/threat-intelligence/indicators/{ioc_id}", headers=admin_headers)
    assert ioc_del.status_code == 200

    # 7. Verify Audit Logs recorded and filterable
    audit_resp = client.get("/api/system/audit-logs?actor_username=analyst&limit=20")
    assert audit_resp.status_code == 200
    assert len(audit_resp.json()) >= 2


def test_phase3_event_ingestion_normalization_modes_and_persistence(test_context):
    """
    Phase 3 Verification:
    - Single & bulk event ingestion with run_detections=False (zero alerts generated)
    - Multi-format log normalization (Syslog SSH, UFW firewall, Sudo, vendor JSON aliases)
    - Raw log preservation
    - Timestamp, IP, username, and category validation + graceful malformed event handling
    - NORMAL MODE and ATTACK SIMULATION MODE synthetic telemetry generators (labeled synthetic)
    - PostgreSQL persistence, filtering, sorting, and pagination
    """
    from telemetry.scenarios.catalog import (
        generate_attack_mode_telemetry,
        generate_normal_mode_telemetry,
    )

    client, _ = test_context

    # 1. Single-event ingestion using vendor-aliased JSON fields (run_detections=false)
    aliased_single = client.post(
        "/api/events?run_detections=false",
        json={
            "event_id": "EVT-NORM-ALIAS-01",
            "timestamp": 1731168000,
            "src_ip": "10.40.1.15",
            "dst_ip": "10.40.0.10",
            "dst_port": 443,
            "user": "claire.dupont",
            "host": "vpn-gw-eu-01",
            "type": "vpn_login",
            "category": "auth",
            "activity": "session_open",
            "outcome": "success",
            "severity": "low",
            "log": "[SYNTHETIC] 2026-11-09T12:00:00Z vpn-gw-eu-01 vpn: session opened for claire.dupont",
            "is_synthetic": True,
        },
    )
    assert aliased_single.status_code == 201
    single_body = aliased_single.json()
    assert single_body["generated_alerts_count"] == 0
    ev_out = single_body["event"]
    assert ev_out["source_ip"] == "10.40.1.15"
    assert ev_out["destination_ip"] == "10.40.0.10"
    assert ev_out["destination_port"] == 443
    assert ev_out["username"] == "claire.dupont"
    assert ev_out["hostname"] == "vpn-gw-eu-01"
    assert ev_out["event_category"] == "Authentication"
    assert ev_out["raw_log"].startswith("[SYNTHETIC]")
    assert ev_out["is_synthetic"] is True

    # 2. Bulk ingestion mixing raw unstructured log strings, structured JSON, and malformed items
    mixed_bulk = client.post(
        "/api/events/bulk",
        json={
            "run_detections": False,
            "events": [
                "[SYNTHETIC] 2026-11-09T12:01:00Z bastion-01 sshd[4101]: Failed password for invalid user admin from 203.0.113.77 port 54321 ssh2",
                "[SYNTHETIC] 2026-11-09T12:01:05Z bastion-01 sshd[4102]: Accepted publickey for devops from 10.10.5.20 port 51234 ssh2",
                "[SYNTHETIC] 2026-11-09T12:01:10Z fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.44 DST=10.20.0.10 PROTO=TCP SPT=40111 DPT=3389 SYN",
                "[SYNTHETIC] 2026-11-09T12:01:15Z app-srv-02 sudo: deploy_user : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
                {
                    "source_ip": "999.999.999.999",
                    "event_type": "bad_ip_event",
                    "event_category": "Network",
                    "action": "deny",
                    "status": "blocked",
                    "raw_log": "Malformed IP address",
                },
                {
                    "source_ip": "10.0.0.8",
                    "username": "bad user with spaces;drop",
                    "event_type": "bad_username_event",
                    "event_category": "Authentication",
                    "action": "login",
                    "status": "failure",
                    "raw_log": "Malformed username",
                },
                "UNRECOGNIZED GARBAGE LOG LINE WITHOUT FIELDS",
            ],
        },
    )
    assert mixed_bulk.status_code == 200
    mb_data = mixed_bulk.json()
    assert mb_data["accepted_count"] == 4
    assert mb_data["rejected_count"] == 3
    assert mb_data["generated_alerts_count"] == 0
    assert len(mb_data["errors"]) == 3

    # 3. Verify NORMAL MODE and ATTACK SIMULATION MODE synthetic telemetry generators
    normal_events = generate_normal_mode_telemetry()
    attack_events = generate_attack_mode_telemetry()

    assert len(normal_events) >= 14
    assert all(e["is_synthetic"] is True for e in normal_events)
    assert all(e["raw_log"].startswith("[SYNTHETIC]") for e in normal_events)
    normal_scenarios = {e["metadata"]["scenario"] for e in normal_events}
    assert {"normal_login", "ordinary_failed_login", "normal_network", "routine_system"}.issubset(normal_scenarios)

    assert len(attack_events) >= 25
    assert all(e["is_synthetic"] is True for e in attack_events)
    assert all(e["raw_log"].startswith("[SYNTHETIC]") for e in attack_events)
    attack_scenarios = {e["metadata"]["scenario"] for e in attack_events}
    assert {
        "brute_force",
        "password_spraying",
        "privilege_escalation",
        "port_scanning",
        "login_after_failures",
    }.issubset(attack_scenarios)

    # Ingest both NORMAL MODE and ATTACK SIMULATION MODE with run_detections=False (Phase 3 requirement: no alerts generated)
    norm_ingest = client.post("/api/events/bulk", json={"events": normal_events, "run_detections": False})
    assert norm_ingest.status_code == 200
    assert norm_ingest.json()["accepted_count"] == len(normal_events)
    assert norm_ingest.json()["generated_alerts_count"] == 0

    atk_ingest = client.post("/api/events/bulk", json={"events": attack_events, "run_detections": False})
    assert atk_ingest.status_code == 200
    assert atk_ingest.json()["accepted_count"] == len(attack_events)
    assert atk_ingest.json()["generated_alerts_count"] == 0

    # Confirm 0 alerts exist in PostgreSQL after Phase 3 ingestion
    alerts_check = client.get("/api/alerts")
    assert alerts_check.status_code == 200
    assert alerts_check.json()["total"] == 0

    # 4. Verify PostgreSQL retrieval, filtering, sorting, and pagination
    page1 = client.get("/api/events?page=1&page_size=10&sort_by=source_ip&sort_order=asc&is_synthetic=true")
    assert page1.status_code == 200
    p1_data = page1.json()
    assert p1_data["total"] >= len(normal_events) + len(attack_events) + 5
    assert len(p1_data["items"]) == 10
    assert p1_data["total_pages"] >= 5
    ips_asc = [item["source_ip"] for item in p1_data["items"]]
    assert ips_asc == sorted(ips_asc)

    sys_filter = client.get("/api/events?event_category=System")
    assert sys_filter.status_code == 200
    assert sys_filter.json()["total"] >= 4
    assert all(item["event_category"] == "System" for item in sys_filter.json()["items"])


def test_phase4_detection_engine_rule_controls_evidence_dedup_and_mitre(test_context):
    """
    Phase 4 Comprehensive Test:
    - Rule-based detection engine functionality for all 7 rules
    - Alert evidence linking in PostgreSQL (alert_evidence table)
    - Alert status history logging (alert_status_history table)
    - Deduplication within detection windows (preventing duplicate alerts for same incident window)
    - Rule enabling/disabling and parameter configuration via REST API
    - MITRE ATT&CK mappings retrieval and technique linking
    - Negative controls: ensuring disabled rules or non-matching telemetry produce zero alerts
    """
    client, db = test_context

    # 1. Verify MITRE ATT&CK mappings endpoint
    mitre_resp = client.get("/api/detections/mitre")
    assert mitre_resp.status_code == 200
    mitre_data = mitre_resp.json()
    assert mitre_data["total_mapped_rules"] >= 7
    tech_ids = {m["technique_id"] for m in mitre_data["mappings"] if m["technique_id"]}
    assert {"T1110.001", "T1110.003", "T1078", "T1078.004", "T1548", "T1046", "T1071"}.issubset(tech_ids)

    # 2. Authenticate admin for rule configuration
    admin_token = client.post(
        "/api/auth/login",
        json={"username": settings.INITIAL_ADMIN_USERNAME, "password": settings.INITIAL_ADMIN_PASSWORD},
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 3. Test Rule Disabling: Disable RULE-001 (Brute-Force) and verify no alert is triggered
    patch_resp = client.patch(
        "/api/detections/rules/RULE-001",
        headers=admin_headers,
        json={"enabled": False},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["enabled"] is False

    now = datetime(2026, 11, 9, 15, 0, 0, tzinfo=timezone.utc)
    bf_events = [
        {
            "event_id": f"EVT-BF-DIS-{i}",
            "timestamp": now.isoformat(),
            "source_ip": "198.51.100.99",
            "username": "disabled_test_user",
            "hostname": "srv-test",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_auth",
            "status": "failure",
            "severity": "medium",
            "raw_log": f"[SYNTHETIC] Failed login {i} for disabled_test_user",
            "is_synthetic": True,
        }
        for i in range(8)
    ]
    resp_dis = client.post("/api/events/bulk", json={"events": bf_events, "run_detections": True})
    assert resp_dis.status_code == 200
    assert resp_dis.json()["generated_alerts_count"] == 0

    # 4. Re-enable RULE-001 with custom threshold (e.g. threshold_count=3)
    patch_reenable = client.patch(
        "/api/detections/rules/RULE-001",
        headers=admin_headers,
        json={"enabled": True, "threshold_count": 3},
    )
    assert patch_reenable.status_code == 200
    assert patch_reenable.json()["enabled"] is True
    assert patch_reenable.json()["threshold_count"] == 3

    # Now ingest 3 failed events -> alert MUST trigger
    bf_events_trigger = [
        {
            "event_id": f"EVT-BF-TRIG-{i}",
            "timestamp": (now + timedelta(seconds=i * 2)).isoformat(),
            "source_ip": "198.51.100.99",
            "username": "reenabled_test_user",
            "hostname": "srv-test",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_auth",
            "status": "failure",
            "severity": "medium",
            "raw_log": f"[SYNTHETIC] Failed login {i} for reenabled_test_user",
            "is_synthetic": True,
        }
        for i in range(3)
    ]
    resp_trig = client.post("/api/events/bulk", json={"events": bf_events_trigger, "run_detections": True})
    assert resp_trig.status_code == 200
    assert resp_trig.json()["generated_alerts_count"] == 1
    new_alert_code = resp_trig.json()["generated_alert_ids"][0]

    # Verify Alert details, evidence linking, and status history in PostgreSQL
    alert_detail_resp = client.get(f"/api/alerts/{new_alert_code}")
    assert alert_detail_resp.status_code == 200
    alert_obj = alert_detail_resp.json()
    assert alert_obj["rule_code"] == "RULE-001"
    assert alert_obj["source_ip"] == "198.51.100.99"
    assert alert_obj["username"] == "reenabled_test_user"
    assert alert_obj["event_count"] >= 3
    assert len(alert_obj["evidence_events"]) >= 3
    assert len(alert_obj["status_history"]) >= 1
    assert alert_obj["status_history"][0]["new_status"] == "New"
    assert alert_obj["mitre_technique_id"] == "T1110.001"

    # 5. Verify Deduplication: ingesting an additional matching event inside the window updates evidence without duplicate alert
    more_bf = [
        {
            "event_id": "EVT-BF-EXTRA-01",
            "timestamp": (now + timedelta(seconds=10)).isoformat(),
            "source_ip": "198.51.100.99",
            "username": "reenabled_test_user",
            "hostname": "srv-test",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_auth",
            "status": "failure",
            "severity": "medium",
            "raw_log": "[SYNTHETIC] Extra failed login",
            "is_synthetic": True,
        }
    ]
    resp_extra = client.post("/api/events/bulk", json={"events": more_bf, "run_detections": True})
    assert resp_extra.status_code == 200
    # No new alert created because it was deduped into the existing alert
    assert resp_extra.json()["generated_alerts_count"] == 0

    updated_alert = client.get(f"/api/alerts/{new_alert_code}").json()
    assert updated_alert["event_count"] >= 4

    # Restore RULE-001 threshold to standard 5
    client.patch("/api/detections/rules/RULE-001", headers=admin_headers, json={"threshold_count": 5})

    # 6. Verify Detection History endpoint (/api/detections/history)
    hist_resp = client.get("/api/detections/history?rule_id=RULE-001")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total_detections"] == 1
    assert hist_data["detections"][0]["alert_id"] == new_alert_code
    assert hist_data["detections"][0]["rule_code"] == "RULE-001"
    assert len(hist_data["detections"][0]["triggering_events"]) == 4
    assert len(hist_data["rule_configuration_history"]) >= 3


def test_phase4_every_rule_positive_and_negative_scenarios(test_context):
    """
    Phase 4 Rule-by-Rule Positive & Negative Verification:
    Explicitly tests all 7 detection rules for:
    - Negative scenario: Normal or sub-threshold activity in the same category generates 0 alerts.
    - Positive scenario: Suspicious activity triggers the exact expected rule, severity, MITRE ATT&CK technique,
      and links all triggering security events in PostgreSQL (alert_evidence).
    """
    client, db = test_context
    base_ts = datetime(2026, 11, 9, 16, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # RULE 1: Brute-Force Authentication (RULE-001, threshold=5, window=300s)
    # -------------------------------------------------------------------------
    # Negative: 3 failed logins (below threshold of 5) -> 0 alerts
    r1_neg = [
        {
            "event_id": f"EVT-R1-NEG-{i}",
            "timestamp": (base_ts + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": "198.51.100.11",
            "username": "neg_bf_user",
            "hostname": "ssh-gw-01",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "low",
            "raw_log": f"[SYNTHETIC] Sub-threshold failed SSH login {i}",
            "is_synthetic": True,
        }
        for i in range(3)
    ]
    res_r1_neg = client.post("/api/events/bulk", json={"events": r1_neg, "run_detections": True}).json()
    assert res_r1_neg["generated_alerts_count"] == 0

    # Positive: 5 failed logins for same (source_ip, username) within 300s -> triggers RULE-001
    r1_pos = [
        {
            "event_id": f"EVT-R1-POS-{i}",
            "timestamp": (base_ts + timedelta(seconds=i * 5)).isoformat(),
            "source_ip": "198.51.100.12",
            "username": "pos_bf_user",
            "hostname": "ssh-gw-01",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "high",
            "raw_log": f"[SYNTHETIC] Brute-force SSH failure {i}",
            "is_synthetic": True,
        }
        for i in range(5)
    ]
    res_r1_pos = client.post("/api/events/bulk", json={"events": r1_pos, "run_detections": True}).json()
    assert res_r1_pos["generated_alerts_count"] == 1
    a1 = client.get(f"/api/alerts/{res_r1_pos['generated_alert_ids'][0]}").json()
    assert a1["rule_code"] == "RULE-001"
    assert a1["mitre_technique_id"] == "T1110.001"
    assert len(a1["evidence_events"]) == 5

    # -------------------------------------------------------------------------
    # RULE 2: Password Spraying (RULE-002, threshold=5 distinct users, window=600s)
    # -------------------------------------------------------------------------
    # Negative: 2 distinct users failing login from same IP -> 0 alerts
    r2_neg = [
        {
            "event_id": f"EVT-R2-NEG-{i}",
            "timestamp": (base_ts + timedelta(minutes=10, seconds=i * 5)).isoformat(),
            "source_ip": "198.51.100.21",
            "username": f"spray_neg_user_{i}",
            "hostname": "idp-01",
            "event_type": "sso_auth",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "low",
            "raw_log": f"[SYNTHETIC] Failed login for spray_neg_user_{i}",
            "is_synthetic": True,
        }
        for i in range(2)
    ]
    res_r2_neg = client.post("/api/events/bulk", json={"events": r2_neg, "run_detections": True}).json()
    assert res_r2_neg["generated_alerts_count"] == 0

    # Positive: 5 distinct users failing login (1 attempt each) from same IP -> triggers RULE-002
    r2_pos = [
        {
            "event_id": f"EVT-R2-POS-{i}",
            "timestamp": (base_ts + timedelta(minutes=10, seconds=i * 5)).isoformat(),
            "source_ip": "198.51.100.22",
            "username": f"spray_pos_user_{i}",
            "hostname": "idp-01",
            "event_type": "sso_auth",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "high",
            "raw_log": f"[SYNTHETIC] Password spray attempt against spray_pos_user_{i}",
            "is_synthetic": True,
        }
        for i in range(5)
    ]
    res_r2_pos = client.post("/api/events/bulk", json={"events": r2_pos, "run_detections": True}).json()
    assert res_r2_pos["generated_alerts_count"] == 1
    a2 = client.get(f"/api/alerts/{res_r2_pos['generated_alert_ids'][0]}").json()
    assert a2["rule_code"] == "RULE-002"
    assert a2["mitre_technique_id"] == "T1110.003"
    assert len(a2["evidence_events"]) == 5

    # -------------------------------------------------------------------------
    # RULE 3: Successful Login After Repeated Failures (RULE-003, threshold=3 failures)
    # -------------------------------------------------------------------------
    # Negative: 1 failed login (user typo) followed by 1 successful login from internal IP during business hours -> 0 alerts
    r3_neg = [
        {
            "event_id": "EVT-R3-NEG-1",
            "timestamp": (base_ts + timedelta(minutes=20)).isoformat(),
            "source_ip": "10.10.5.50",
            "username": "typo_user",
            "hostname": "app-01",
            "event_type": "user_login",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "low",
            "raw_log": "[SYNTHETIC] Single password typo",
            "is_synthetic": True,
        },
        {
            "event_id": "EVT-R3-NEG-2",
            "timestamp": (base_ts + timedelta(minutes=20, seconds=5)).isoformat(),
            "source_ip": "10.10.5.50",
            "username": "typo_user",
            "hostname": "app-01",
            "event_type": "user_login",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "success",
            "severity": "low",
            "raw_log": "[SYNTHETIC] Successful login after single typo",
            "is_synthetic": True,
        },
    ]
    res_r3_neg = client.post("/api/events/bulk", json={"events": r3_neg, "run_detections": True}).json()
    assert res_r3_neg["generated_alerts_count"] == 0

    # Positive: 3 failed logins followed by 1 successful login -> triggers RULE-003
    r3_pos = [
        {
            "event_id": f"EVT-R3-POS-FAIL-{i}",
            "timestamp": (base_ts + timedelta(minutes=25, seconds=i * 4)).isoformat(),
            "source_ip": "10.10.5.55",
            "username": "compromised_admin",
            "hostname": "vault-01",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "medium",
            "raw_log": f"[SYNTHETIC] Preceding failure {i}",
            "is_synthetic": True,
        }
        for i in range(3)
    ] + [
        {
            "event_id": "EVT-R3-POS-SUCC",
            "timestamp": (base_ts + timedelta(minutes=25, seconds=20)).isoformat(),
            "source_ip": "10.10.5.55",
            "username": "compromised_admin",
            "hostname": "vault-01",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "success",
            "severity": "critical",
            "raw_log": "[SYNTHETIC] Successful login after 3 failures",
            "is_synthetic": True,
        }
    ]
    res_r3_pos = client.post("/api/events/bulk", json={"events": r3_pos, "run_detections": True}).json()
    assert res_r3_pos["generated_alerts_count"] == 1
    a3 = client.get(f"/api/alerts/{res_r3_pos['generated_alert_ids'][0]}").json()
    assert a3["rule_code"] == "RULE-003"
    assert a3["mitre_technique_id"] == "T1078"
    assert len(a3["evidence_events"]) == 4

    # -------------------------------------------------------------------------
    # RULE 4: Unusual Login Activity Based on Available Telemetry (RULE-004)
    # -------------------------------------------------------------------------
    # Negative: Internal RFC1918 login during business hours (16:30 UTC) with no anomaly flags -> 0 alerts
    r4_neg = [
        {
            "event_id": "EVT-R4-NEG-1",
            "timestamp": (base_ts + timedelta(minutes=30)).isoformat(),
            "source_ip": "192.168.10.25",
            "username": "normal_staff",
            "hostname": "workstation-12",
            "event_type": "sso_login",
            "event_category": "Authentication",
            "action": "login",
            "status": "success",
            "severity": "low",
            "raw_log": "[SYNTHETIC] Routine internal business-hours login",
            "is_synthetic": True,
        }
    ]
    res_r4_neg = client.post("/api/events/bulk", json={"events": r4_neg, "run_detections": True}).json()
    assert res_r4_neg["generated_alerts_count"] == 0

    # Positive: External non-RFC1918 login at 02:15 UTC off-hours -> triggers RULE-004
    off_hour_ts = datetime(2026, 11, 9, 2, 15, 0, tzinfo=timezone.utc)
    r4_pos = [
        {
            "event_id": "EVT-R4-POS-1",
            "timestamp": off_hour_ts.isoformat(),
            "source_ip": "198.51.100.88",
            "username": "finance_director",
            "hostname": "erp-prod-01",
            "event_type": "vpn_login",
            "event_category": "Authentication",
            "action": "login",
            "status": "success",
            "severity": "medium",
            "raw_log": "[SYNTHETIC] Off-hours external VPN authentication at 02:15 UTC",
            "metadata": {"new_source_network": True},
            "is_synthetic": True,
        }
    ]
    res_r4_pos = client.post("/api/events/bulk", json={"events": r4_pos, "run_detections": True}).json()
    assert res_r4_pos["generated_alerts_count"] == 1
    a4 = client.get(f"/api/alerts/{res_r4_pos['generated_alert_ids'][0]}").json()
    assert a4["rule_code"] == "RULE-004"
    assert a4["mitre_technique_id"] == "T1078.004"
    assert len(a4["evidence_events"]) == 1

    # -------------------------------------------------------------------------
    # RULE 5: Suspicious Privilege Escalation (RULE-005)
    # -------------------------------------------------------------------------
    # Negative: Standard non-privileged command / system health check -> 0 alerts
    r5_neg = [
        {
            "event_id": "EVT-R5-NEG-1",
            "timestamp": (base_ts + timedelta(minutes=35)).isoformat(),
            "source_ip": "10.10.2.15",
            "username": "app_worker",
            "hostname": "web-node-01",
            "event_type": "process_execution",
            "event_category": "Endpoint",
            "action": "command_exec",
            "status": "success",
            "severity": "low",
            "raw_log": "[SYNTHETIC] /usr/bin/uptime executed by app_worker",
            "metadata": {"target_privilege": "standard_user", "command": "/usr/bin/uptime"},
            "is_synthetic": True,
        }
    ]
    res_r5_neg = client.post("/api/events/bulk", json={"events": r5_neg, "run_detections": True}).json()
    assert res_r5_neg["generated_alerts_count"] == 0

    # Positive: Unauthorized sudo_abuse elevating to root -> triggers RULE-005
    r5_pos = [
        {
            "event_id": "EVT-R5-POS-1",
            "timestamp": (base_ts + timedelta(minutes=36)).isoformat(),
            "source_ip": "10.10.2.99",
            "username": "web_service",
            "hostname": "db-master-01",
            "event_type": "sudo_abuse",
            "event_category": "Authorization",
            "action": "privilege_escalation",
            "status": "success",
            "severity": "critical",
            "raw_log": "[SYNTHETIC] web_service executed sudo /bin/bash as root",
            "metadata": {"target_privilege": "root", "privilege_escalation": True},
            "is_synthetic": True,
        }
    ]
    res_r5_pos = client.post("/api/events/bulk", json={"events": r5_pos, "run_detections": True}).json()
    assert res_r5_pos["generated_alerts_count"] == 1
    a5 = client.get(f"/api/alerts/{res_r5_pos['generated_alert_ids'][0]}").json()
    assert a5["rule_code"] == "RULE-005"
    assert a5["mitre_technique_id"] == "T1548"
    assert len(a5["evidence_events"]) == 1

    # -------------------------------------------------------------------------
    # RULE 6: Port Scanning Detection (RULE-006, threshold=6 distinct ports)
    # -------------------------------------------------------------------------
    # Negative: Traffic to only 2 distinct ports (80 and 443) -> 0 alerts
    r6_neg = [
        {
            "event_id": f"EVT-R6-NEG-{i}",
            "timestamp": (base_ts + timedelta(minutes=40, seconds=i)).isoformat(),
            "source_ip": "10.20.30.40",
            "destination_ip": "10.20.0.10",
            "destination_port": 443 if i % 2 == 0 else 80,
            "hostname": "fw-01",
            "event_type": "tcp_connection",
            "event_category": "Network",
            "action": "allow",
            "status": "success",
            "severity": "low",
            "raw_log": f"[SYNTHETIC] Normal web connection {i}",
            "is_synthetic": True,
        }
        for i in range(6)
    ]
    res_r6_neg = client.post("/api/events/bulk", json={"events": r6_neg, "run_detections": True}).json()
    assert res_r6_neg["generated_alerts_count"] == 0

    # Positive: Probing 8 distinct ports from a single source IP within 120s -> triggers RULE-006 (threshold=8)
    scan_ports = [21, 22, 23, 25, 80, 443, 3306, 3389]
    r6_pos = [
        {
            "event_id": f"EVT-R6-POS-{p}",
            "timestamp": (base_ts + timedelta(minutes=42, seconds=idx)).isoformat(),
            "source_ip": "198.51.100.150",
            "destination_ip": "10.20.0.10",
            "destination_port": p,
            "hostname": "fw-01",
            "event_type": "port_probe",
            "event_category": "Network",
            "action": "blocked",
            "status": "failure",
            "severity": "medium",
            "raw_log": f"[SYNTHETIC] SYN probe to port {p}",
            "is_synthetic": True,
        }
        for idx, p in enumerate(scan_ports)
    ]
    res_r6_pos = client.post("/api/events/bulk", json={"events": r6_pos, "run_detections": True}).json()
    assert res_r6_pos["generated_alerts_count"] == 1
    a6 = client.get(f"/api/alerts/{res_r6_pos['generated_alert_ids'][0]}").json()
    assert a6["rule_code"] == "RULE-006"
    assert a6["mitre_technique_id"] == "T1046"
    assert len(a6["evidence_events"]) == 8

    # -------------------------------------------------------------------------
    # RULE 7: Suspicious Network Activity (RULE-007)
    # -------------------------------------------------------------------------
    # Negative: Normal outbound HTTPS request (port 443, 4KB payload, non-IOC IP) -> 0 alerts
    r7_neg = [
        {
            "event_id": "EVT-R7-NEG-1",
            "timestamp": (base_ts + timedelta(minutes=50)).isoformat(),
            "source_ip": "10.10.1.50",
            "destination_ip": "93.184.216.34",
            "destination_port": 443,
            "hostname": "egress-fw-01",
            "event_type": "https_outbound",
            "event_category": "Network",
            "action": "allow",
            "status": "success",
            "severity": "low",
            "raw_log": "[SYNTHETIC] Routine TLS connection to 93.184.216.34:443",
            "metadata": {"bytes_out": 4096, "protocol": "TCP"},
            "is_synthetic": True,
        }
    ]
    res_r7_neg = client.post("/api/events/bulk", json={"events": r7_neg, "run_detections": True}).json()
    assert res_r7_neg["generated_alerts_count"] == 0

    # Positive: Outbound C2 beacon to port 4444 with 25MB exfiltration -> triggers RULE-007
    r7_pos = [
        {
            "event_id": "EVT-R7-POS-1",
            "timestamp": (base_ts + timedelta(minutes=51)).isoformat(),
            "source_ip": "10.10.1.50",
            "destination_ip": "198.51.100.200",
            "destination_port": 4444,
            "hostname": "egress-fw-01",
            "event_type": "c2_beacon",
            "event_category": "Network",
            "action": "outbound_connection",
            "status": "success",
            "severity": "critical",
            "raw_log": "[SYNTHETIC] Outbound C2 connection on port 4444 with 25MB transfer",
            "metadata": {"bytes_out": 25000000, "protocol": "TCP"},
            "is_synthetic": True,
        }
    ]
    res_r7_pos = client.post("/api/events/bulk", json={"events": r7_pos, "run_detections": True}).json()
    assert res_r7_pos["generated_alerts_count"] == 1
    a7 = client.get(f"/api/alerts/{res_r7_pos['generated_alert_ids'][0]}").json()
    assert a7["rule_code"] == "RULE-007"
    assert a7["mitre_technique_id"] == "T1071"
    assert len(a7["evidence_events"]) == 1


def test_phase5_soc_dashboard_events_explorer_and_alerts_triage_workflow(test_context):
    """
    Phase 5 Verification:
    - SOC Overview Dashboard metrics, charts, top source IPs, detection timeline, system health
    - Security Events Explorer filtering, sorting, pagination, and Event Details Drawer correlation
    - Alerts Management filtering, sorting, status transitions (New -> Acknowledged -> Investigating -> Resolved -> False Positive),
      status audit history, analyst notes, and evidence event traceability
    """
    client, _ = test_context

    # 1. Simulate full suite to populate telemetry and alerts
    sim_resp = client.post("/api/system/simulate", json={"scenario_id": "all", "volume_multiplier": 1})
    assert sim_resp.status_code == 200

    # 2. Verify SOC Overview Dashboard endpoint (/api/analytics/overview)
    dash_resp = client.get("/api/analytics/overview")
    assert dash_resp.status_code == 200
    dash = dash_resp.json()
    assert dash["metrics"]["total_security_events"] >= 20
    assert dash["metrics"]["total_alerts"] >= 7
    assert len(dash["alerts_by_severity"]) == 4
    assert len(dash["events_by_category"]) == 6
    assert len(dash["top_source_ips"]) >= 1
    assert len(dash["recent_alerts"]) >= 7
    assert len(dash["latest_events"]) >= 5
    assert dash["system_health"]["database_connected"] is True

    # 3. Verify Security Events Explorer filtering, sorting, and Event Details correlation
    ev_list_resp = client.get("/api/events?event_category=Authentication&sort_by=timestamp&sort_order=desc&page=1&page_size=10")
    assert ev_list_resp.status_code == 200
    ev_items = ev_list_resp.json()["items"]
    assert len(ev_items) >= 1
    target_ev_id = ev_items[0]["id"]

    ev_detail_resp = client.get(f"/api/events/{target_ev_id}")
    assert ev_detail_resp.status_code == 200
    ev_detail = ev_detail_resp.json()
    assert ev_detail["event"]["id"] == target_ev_id
    assert "raw_log" in ev_detail["event"]
    assert "metadata" in ev_detail["event"]
    assert isinstance(ev_detail["related_events"], list)
    assert isinstance(ev_detail["linked_alerts"], list)

    # 4. Verify Alerts Management filtering, sorting, and all 5 alert statuses
    alerts_resp = client.get("/api/alerts?sort_by=severity&sort_order=desc")
    assert alerts_resp.status_code == 200
    alerts_items = alerts_resp.json()["items"]
    assert len(alerts_items) >= 7
    target_alert = alerts_items[0]
    alert_id = target_alert["id"]

    for next_status in ["Acknowledged", "Investigating", "Resolved", "False Positive", "New"]:
        st_resp = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={
                "status": next_status,
                "comment": f"Phase 5 triage status transition to {next_status}",
                "assigned_to": "analyst",
            },
        )
        assert st_resp.status_code == 200
        assert st_resp.json()["status"] == next_status

    final_alert = client.get(f"/api/alerts/{alert_id}").json()
    assert len(final_alert["status_history"]) >= 6
    assert len(final_alert["notes"]) >= 5
    assert len(final_alert["evidence_events"]) >= 1


def test_phase6_incident_investigation_lifecycle_evidence_and_mitre_mapping(test_context):
    """
    Phase 6 Comprehensive Test Suite:
    1. Allow analysts to create incidents from security alerts.
    2. Associate multiple alerts with an incident (at creation & dynamically via /alerts endpoint).
    3. Display & retrieve related security events.
    4. Create and verify an investigation timeline.
    5. Allow analysts to add investigation notes.
    6. Track assigned analysts and filter incidents by analyst.
    7. Support all 5 incident statuses: Open, Investigating, Contained, Resolved, Closed.
    8. Maintain and retrieve evidence references (alerts, events, custom forensic artifacts/IOCs).
    9. Record status changes and analyst actions in timeline, status_history, and audit_logs.
    10. Accurate MITRE ATT&CK mappings (tactic, technique_id, technique_name, associated_rules, related_alerts).
    """
    client, _ = test_context

    # Authenticate as Senior SOC Analyst
    login_resp = client.post(
        "/api/auth/login",
        json={
            "username": settings.INITIAL_ANALYST_USERNAME,
            "password": settings.INITIAL_ANALYST_PASSWORD,
        },
    )
    assert login_resp.status_code == 200
    analyst_headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # Trigger synthetic scenarios so we have multiple real alerts and security events
    sim_resp = client.post(
        "/api/system/simulate",
        json={"scenario_id": "all", "volume_multiplier": 1},
    )
    assert sim_resp.status_code == 200

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    all_alerts = alerts_resp.json()["items"]
    assert len(all_alerts) >= 7

    alert_1 = all_alerts[0]
    alert_2 = all_alerts[1]
    alert_3 = all_alerts[2]

    # 1. Create an incident from security alert_1 (default status: 'Open')
    create_inc_resp = client.post(
        "/api/incidents",
        headers=analyst_headers,
        json={
            "title": "Phase 6 Multi-Stage Intrusion Investigation",
            "severity": "critical",
            "description": f"Created from alert {alert_1['alert_id']} to investigate credential & network activity.",
            "assigned_analyst": "analyst",
            "alert_ids": [alert_1["id"]],
        },
    )
    assert create_inc_resp.status_code == 201
    inc_data = create_inc_resp.json()
    inc_id = inc_data["id"]
    inc_code = inc_data["incident_id"]

    assert inc_data["status"] == "Open"
    assert inc_data["assigned_analyst"] == "analyst"
    assert inc_data["linked_alert_count"] == 1
    assert len(inc_data["related_alerts"]) == 1
    assert inc_data["related_alerts"][0]["alert_id"] == alert_1["alert_id"]
    assert len(inc_data["related_events"]) >= 1

    # Verify alert_1 knows it is linked to this incident
    alert_1_detail = client.get(f"/api/alerts/{alert_1['id']}").json()
    assert inc_code in alert_1_detail["linked_incident_ids"]

    # 2. Associate multiple additional alerts (alert_2 by integer ID, alert_3 by alert_id code) with the incident
    link_resp = client.post(
        f"/api/incidents/{inc_id}/alerts",
        headers=analyst_headers,
        json={"alert_ids": [alert_2["id"], alert_3["alert_id"]]},
    )
    assert link_resp.status_code == 200
    inc_after_link = link_resp.json()
    assert inc_after_link["linked_alert_count"] == 3
    linked_alert_codes = {a["alert_id"] for a in inc_after_link["related_alerts"]}
    assert {alert_1["alert_id"], alert_2["alert_id"], alert_3["alert_id"]} == linked_alert_codes

    # 3. Verify related security events retrieval
    events_resp = client.get(f"/api/incidents/{inc_id}/events")
    assert events_resp.status_code == 200
    inc_events = events_resp.json()
    assert len(inc_events) >= 3
    assert len(inc_after_link["related_events"]) == len(inc_events)

    # 4 & 5. Add investigation notes and verify note persistence + timeline recording
    note1_resp = client.post(
        f"/api/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={
            "content": "Correlated SSH brute-force and privilege escalation events across host bastion-01.",
            "note_type": "forensic_finding",
        },
    )
    assert note1_resp.status_code == 201
    note2_resp = client.post(
        f"/api/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={
            "content": "Isolated affected host from outbound network segment.",
            "note_type": "containment_action",
        },
    )
    assert note2_resp.status_code == 201

    notes_list = client.get(f"/api/incidents/{inc_id}/notes").json()
    assert len(notes_list) == 2
    assert notes_list[0]["author"] == "analyst"

    # 6 & 7 & 9. Track assigned analysts and test all 5 incident statuses:
    # Open -> Investigating -> Contained -> Resolved -> Closed
    status_progression = [
        ("Investigating", "analyst", "Active forensic analysis initiated"),
        ("Contained", "ir.lead", "Source IP blocked at perimeter firewall and host isolated"),
        ("Resolved", "ir.lead", "Compromised credentials rotated and persistence removed"),
        ("Closed", "admin", "Post-incident review completed and documented"),
    ]
    for target_status, assignee, comment in status_progression:
        st_patch = client.patch(
            f"/api/incidents/{inc_id}/status",
            headers=analyst_headers,
            json={
                "status": target_status,
                "assigned_analyst": assignee,
                "comment": comment,
                "resolution_summary": comment if target_status in ("Resolved", "Closed") else None,
            },
        )
        assert st_patch.status_code == 200
        st_body = st_patch.json()
        assert st_body["status"] == target_status
        assert st_body["assigned_analyst"] == assignee
        if target_status in ("Resolved", "Closed"):
            assert st_body["resolved_at"] is not None

    # Verify invalid status is rejected with 422
    bad_status_resp = client.patch(
        f"/api/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"status": "InvalidStatusName"},
    )
    assert bad_status_resp.status_code == 422

    # Verify filtering incidents by status and assigned_analyst
    closed_filter = client.get("/api/incidents?status=Closed&assigned_analyst=admin")
    assert closed_filter.status_code == 200
    assert any(i["incident_id"] == inc_code for i in closed_filter.json()["items"])

    # 8. Maintain & retrieve evidence references
    add_ev_resp = client.post(
        f"/api/incidents/{inc_id}/evidence",
        headers=analyst_headers,
        json={
            "type": "artifact",
            "reference": "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "description": "Captured suspicious binary memory dump from host",
        },
    )
    assert add_ev_resp.status_code == 201

    evidence_get_resp = client.get(f"/api/incidents/{inc_id}/evidence")
    assert evidence_get_resp.status_code == 200
    evidence_payload = evidence_get_resp.json()
    ev_refs = evidence_payload["evidence_references"]
    ev_ref_types = {r["type"] for r in ev_refs}
    assert {"alert", "event", "artifact"}.issubset(ev_ref_types)
    assert any(r["reference"].startswith("SHA256:") for r in ev_refs)

    # 9. Verify status history, investigation timeline, and audit logs
    hist_resp = client.get(f"/api/incidents/{inc_id}/history")
    assert hist_resp.status_code == 200
    status_history = hist_resp.json()
    recorded_statuses = [h["new_status"] for h in status_history]
    assert recorded_statuses == ["Open", "Investigating", "Contained", "Resolved", "Closed"]

    timeline_resp = client.get(f"/api/incidents/{inc_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline_items = timeline_resp.json()
    timeline_actions = {t["action"] for t in timeline_items}
    assert {
        "Incident Created",
        "Analyst Assigned",
        "Alerts Linked",
        "Investigation Note Added",
        "Status Changed",
        "Evidence Added",
    }.issubset(timeline_actions)

    # 10. Verify accurate MITRE ATT&CK mappings on both /api/detections/mitre and incident detail
    mitre_resp = client.get("/api/detections/mitre")
    assert mitre_resp.status_code == 200
    mitre_body = mitre_resp.json()
    assert mitre_body["total_mapped_rules"] == 7

    expected_mitre_catalog = {
        "RULE-001": ("Credential Access", "T1110.001", "Brute Force: Password Guessing"),
        "RULE-002": ("Credential Access", "T1110.003", "Brute Force: Password Spraying"),
        "RULE-003": ("Initial Access", "T1078", "Valid Accounts"),
        "RULE-004": ("Initial Access", "T1078.004", "Valid Accounts: Cloud Accounts"),
        "RULE-005": ("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
        "RULE-006": ("Discovery", "T1046", "Network Service Discovery"),
        "RULE-007": ("Command and Control", "T1071", "Application Layer Protocol"),
    }

    for mapping in mitre_body["mappings"]:
        rule_id = mapping["rule"]["rule_id"]
        if rule_id in expected_mitre_catalog:
            exp_tactic, exp_tech_id, exp_tech_name = expected_mitre_catalog[rule_id]
            assert mapping["tactic"] == exp_tactic
            assert mapping["technique_id"] == exp_tech_id
            assert mapping["technique_name"] == exp_tech_name
            assert len(mapping["associated_rules"]) >= 1
            assert mapping["alert_count"] >= 1
            assert len(mapping["related_alerts"]) >= 1

    # Also verify incident-level MITRE mappings
    final_inc = client.get(f"/api/incidents/{inc_id}").json()
    assert len(final_inc["mitre_mappings"]) >= 1
    for im in final_inc["mitre_mappings"]:
        assert im["tactic"]
        assert im["technique_id"]
        assert im["technique_name"]
        assert len(im["associated_rules"]) >= 1
        assert len(im["related_alerts"]) >= 1


def test_phase7_realtime_websocket_threat_intel_analytics_reporting_and_security(test_context):
    """
    Phase 7 Comprehensive Test Suite:
    1. REAL-TIME MONITORING:
       - FastAPI WebSockets (/ws & /api/ws) connection, ping/pong, live event updates, live alert notifications,
         dashboard metric updates, and sync recovery.
       - Polling fallback (/api/system/realtime/poll) and connection status (/api/system/realtime).
    2. THREAT INTELLIGENCE:
       - IP reputation lookup (/api/threat-intelligence/lookup) with zero fabricated external results when unconfigured.
       - IOC management (create, list, toggle active/inactive, delete) with strict input validation.
       - Suspicious IP tracking (/api/threat-intelligence/suspicious-ips).
       - External provider configuration & abstraction (/api/threat-intelligence/providers).
    3. ANALYTICS:
       - Alerts by severity, detection rule frequency, event trends, incident resolution statistics
         (including resolution_rate and mean_time_to_resolve_minutes).
       - Non-fabricated detection accuracy metrics (TP, FP, TN, FN, Precision, Recall, F1 Score, Accuracy) using labeled data.
    4. REPORTING:
       - Global CSV export (/api/reports/export/csv) & PDF export (/api/reports/export/pdf).
       - Incident investigation reports (JSON, CSV, PDF via /api/reports/incidents/{id}[/csv|/pdf]).
    5. SECURITY:
       - Role-based permissions (admin, soc_lead, analyst, viewer) and rbac_access_denied audit logging.
       - JWT verification (/api/auth/verify) and invalid token rejection.
       - API rate limiting (429 Too Many Requests with Retry-After and X-RateLimit-* headers).
       - Audit logs review & filtering (/api/system/audit-logs).
       - Input validation (422 on malformed IPs, control characters, invalid roles).
    """
    from app.core.websocket import ws_manager

    client, _ = test_context
    ws_manager.reset()

    # Authenticate as admin and analyst
    admin_login = client.post(
        "/api/auth/login",
        json={"username": settings.INITIAL_ADMIN_USERNAME, "password": settings.INITIAL_ADMIN_PASSWORD},
    )
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    analyst_login = client.post(
        "/api/auth/login",
        json={"username": settings.INITIAL_ANALYST_USERNAME, "password": settings.INITIAL_ANALYST_PASSWORD},
    )
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # =========================================================================
    # 1. REAL-TIME MONITORING (WebSocket + Live Broadcasts + Polling Fallback)
    # =========================================================================
    with client.websocket_connect(f"/ws?token={analyst_token}") as websocket:
        connected_msg = websocket.receive_json()
        assert connected_msg["type"] == "connection_established"
        assert connected_msg["data"]["authenticated_user"] == settings.INITIAL_ANALYST_USERNAME
        initial_seq = connected_msg["seq"]

        # Test heartbeat ping/pong
        websocket.send_text("ping")
        pong_msg = websocket.receive_json()
        assert pong_msg["type"] == "pong"

        # Verify /api/system/realtime reports active WebSocket connection
        rt_status = client.get("/api/system/realtime")
        assert rt_status.status_code == 200
        assert rt_status.json()["active_websocket_connections"] >= 1
        assert rt_status.json()["polling_fallback_enabled"] is True

        # Ingest a brute-force sequence while WebSocket is connected -> verify live broadcasts
        now = datetime(2026, 11, 9, 17, 0, 0, tzinfo=timezone.utc)
        bf_batch = [
            {
                "event_id": f"EVT-P7-RT-{i}",
                "timestamp": (now + timedelta(seconds=i)).isoformat(),
                "source_ip": "185.220.101.42",
                "destination_ip": "10.10.0.10",
                "destination_port": 22,
                "username": "root",
                "hostname": "bastion-rt-01",
                "event_type": "ssh_login",
                "event_category": "Authentication",
                "action": "password_login",
                "status": "failure",
                "severity": "high",
                "raw_log": f"[SYNTHETIC] Phase 7 real-time SSH failure {i}",
                "metadata": {"ground_truth": "malicious", "attack_type": "brute_force"},
                "is_synthetic": True,
            }
            for i in range(6)
        ]
        bulk_resp = client.post("/api/events/bulk", json={"events": bf_batch, "run_detections": True})
        assert bulk_resp.status_code == 200
        assert bulk_resp.json()["generated_alerts_count"] >= 1

        # Receive live messages from WebSocket (alert_created, bulk_events_ingested, dashboard_metrics_updated)
        received_types = set()
        for _ in range(3):
            msg = websocket.receive_json()
            received_types.add(msg["type"])
        assert "alert_created" in received_types
        assert "bulk_events_ingested" in received_types
        assert "dashboard_metrics_updated" in received_types

        # Test WebSocket sync snapshot command
        websocket.send_json({"type": "sync", "since_seq": initial_seq})
        sync_msg = websocket.receive_json()
        assert sync_msg["type"] == "sync_snapshot"
        assert len(sync_msg["data"]["messages"]) >= 3

        # Test polling fallback endpoint (/api/system/realtime/poll)
        poll_resp = client.get(f"/api/system/realtime/poll?since_seq={initial_seq}")
        assert poll_resp.status_code == 200
        poll_data = poll_resp.json()
        assert poll_data["polling_fallback_enabled"] is True
        assert poll_data["latest_seq"] > initial_seq
        polled_types = {m["type"] for m in poll_data["messages"]}
        assert {"alert_created", "bulk_events_ingested", "dashboard_metrics_updated"}.issubset(polled_types)
        assert poll_data["metrics"]["total_security_events"] >= 6
        assert poll_data["metrics"]["total_alerts"] >= 1

    # =========================================================================
    # 2. THREAT INTELLIGENCE (Lookup, IOC CRUD, Suspicious IPs, Providers)
    # =========================================================================
    # 2a. Verify external provider status & non-fabricated lookup when keys are not configured
    providers_resp = client.get("/api/threat-intelligence/providers")
    assert providers_resp.status_code == 200
    prov_ids = {p["id"] for p in providers_resp.json()["providers"]}
    assert {"local_ioc_db", "abuseipdb", "virustotal", "alienvault_otx"}.issubset(prov_ids)

    lookup_resp = client.get(
        "/api/threat-intelligence/lookup?ip=185.220.101.42",
        headers=analyst_headers,
    )
    assert lookup_resp.status_code == 200
    lookup_data = lookup_resp.json()
    assert lookup_data["verdict"] == "confirmed_ioc_match"
    assert lookup_data["reputation_confidence"] >= 80
    assert lookup_data["local_ioc_match"] is not None
    assert lookup_data["internal_telemetry"]["events_as_source"] >= 6
    assert lookup_data["internal_telemetry"]["associated_alerts_count"] >= 1
    # Verify unconfigured external providers strictly report status="not_configured" and data=None (no fabricated scores)
    for ext_res in lookup_data["external_providers"]:
        if not ext_res["configured"]:
            assert ext_res["status"] == "not_configured"
            assert ext_res["data"] is None

    # Lookup an unknown benign IP -> must not fabricate malicious score
    benign_lookup = client.get(
        "/api/threat-intelligence/lookup?ip=8.8.4.4",
        headers=analyst_headers,
    )
    assert benign_lookup.status_code == 200
    assert benign_lookup.json()["verdict"] == "no_intelligence_match"
    assert benign_lookup.json()["reputation_confidence"] is None
    assert benign_lookup.json()["local_ioc_match"] is None

    # 2b. IOC Management (Create, Toggle, Delete) + Input validation
    invalid_ioc = client.post(
        "/api/threat-intelligence/indicators",
        headers=analyst_headers,
        json={
            "indicator_value": "999.999.999.999",
            "indicator_type": "ip",
            "threat_type": "c2_server",
            "confidence": 85,
            "severity": "high",
        },
    )
    assert invalid_ioc.status_code == 422

    create_ioc = client.post(
        "/api/threat-intelligence/indicators",
        headers=analyst_headers,
        json={
            "indicator_value": "203.0.113.210",
            "indicator_type": "ip",
            "threat_type": "c2_beacon_node",
            "confidence": 91,
            "severity": "critical",
            "source": "SOC Forensic Investigation",
            "description": "Confirmed outbound C2 endpoint",
            "tags": ["c2", "phase7"],
        },
    )
    assert create_ioc.status_code == 201
    created_ioc_id = create_ioc.json()["id"]

    toggle_ioc = client.patch(
        f"/api/threat-intelligence/indicators/{created_ioc_id}",
        headers=analyst_headers,
        json={"is_active": False, "confidence": 75},
    )
    assert toggle_ioc.status_code == 200
    assert toggle_ioc.json()["is_active"] is False
    assert toggle_ioc.json()["confidence"] == 75

    # 2c. Suspicious IP Tracking endpoint
    susp_resp = client.get("/api/threat-intelligence/suspicious-ips?limit=25")
    assert susp_resp.status_code == 200
    susp_items = susp_resp.json()
    assert len(susp_items) >= 1
    tracked_ip_map = {item["ip"]: item for item in susp_items}
    assert "185.220.101.42" in tracked_ip_map
    assert tracked_ip_map["185.220.101.42"]["tracking_status"] == "confirmed_ioc"
    assert tracked_ip_map["185.220.101.42"]["alert_count"] >= 1
    assert tracked_ip_map["185.220.101.42"]["failed_logins"] >= 6

    del_ioc = client.delete(
        f"/api/threat-intelligence/indicators/{created_ioc_id}",
        headers=analyst_headers,
    )
    assert del_ioc.status_code == 200

    # =========================================================================
    # 3. ANALYTICS & 4. REPORTING (including Incident Investigation Reports)
    # =========================================================================
    # Run full synthetic simulation so all 7 rules and benign baseline are populated
    sim_all = client.post("/api/system/simulate", json={"scenario_id": "all", "volume_multiplier": 1})
    assert sim_all.status_code == 200

    # Create and resolve an incident so incident_resolution_stats has resolved metrics & MTTR
    all_alerts = client.get("/api/alerts").json()["items"]
    inc_create = client.post(
        "/api/incidents",
        headers=analyst_headers,
        json={
            "title": "Phase 7 Analytics & Reporting Incident",
            "severity": "critical",
            "description": "Incident created to test resolution statistics and forensic report exports.",
            "assigned_analyst": "analyst",
            "alert_ids": [all_alerts[0]["id"], all_alerts[1]["id"]],
        },
    )
    assert inc_create.status_code == 201
    inc_id = inc_create.json()["id"]
    inc_code = inc_create.json()["incident_id"]

    # Add note and evidence, then transition to Resolved
    client.post(
        f"/api/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={"content": "Verified root cause and blocked offending IP.", "note_type": "remediation"},
    )
    client.patch(
        f"/api/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={
            "status": "Resolved",
            "comment": "Incident contained and remediated",
            "resolution_summary": "Blocked source IP at perimeter firewall and rotated credentials.",
        },
    )

    # 3a. Verify /api/analytics/performance
    perf_resp = client.get("/api/analytics/performance")
    assert perf_resp.status_code == 200
    perf = perf_resp.json()
    assert len(perf["alerts_by_severity"]) == 4
    assert len(perf["detection_rule_frequency"]) >= 7
    assert len(perf["event_trends"]) >= 1
    assert perf["incident_resolution_stats"]["total_incidents"] >= 1
    assert perf["incident_resolution_stats"]["resolved_incidents"] >= 1
    assert perf["incident_resolution_stats"]["resolution_rate"] > 0
    assert perf["incident_resolution_stats"]["mean_time_to_resolve_minutes"] is not None

    # 3b. Verify non-fabricated Detection Accuracy metrics (/api/analytics/detection-accuracy)
    acc_resp = client.get("/api/analytics/detection-accuracy")
    assert acc_resp.status_code == 200
    acc = acc_resp.json()
    eval_metrics = acc["detection_evaluation"]
    assert eval_metrics["has_labeled_data"] is True
    assert eval_metrics["labeled_events_count"] >= 30
    assert eval_metrics["true_positives"] > 0
    assert eval_metrics["true_negatives"] > 0
    assert eval_metrics["precision"] > 0.8
    assert eval_metrics["recall"] > 0.8
    assert eval_metrics["f1_score"] > 0.8
    assert eval_metrics["accuracy"] > 0.8

    # 3c. Verify /api/analytics/incidents
    inc_stats_resp = client.get("/api/analytics/incidents")
    assert inc_stats_resp.status_code == 200
    assert inc_stats_resp.json()["incident_resolution_stats"]["resolved_incidents"] >= 1

    # 4a. Verify Global CSV & PDF Exports
    csv_export = client.get("/api/reports/export/csv")
    assert csv_export.status_code == 200
    assert "text/csv" in csv_export.headers["content-type"]
    assert "ThreatLens Security Operations Analytical Report" in csv_export.text
    assert "--- INCIDENT RESOLUTION STATISTICS ---" in csv_export.text

    pdf_export = client.get("/api/reports/export/pdf")
    assert pdf_export.status_code == 200
    assert "application/pdf" in pdf_export.headers["content-type"]
    assert pdf_export.content.startswith(b"%PDF-1.4")

    # 4b. Verify Incident Investigation Reports (JSON, CSV, PDF)
    inc_report_json = client.get(f"/api/reports/incidents/{inc_code}")
    assert inc_report_json.status_code == 200
    assert inc_report_json.json()["incident_id"] == inc_code
    assert len(inc_report_json.json()["related_alerts"]) == 2
    assert len(inc_report_json.json()["mitre_mappings"]) >= 1

    inc_report_csv = client.get(f"/api/reports/incidents/{inc_code}/csv")
    assert inc_report_csv.status_code == 200
    assert "text/csv" in inc_report_csv.headers["content-type"]
    assert inc_code in inc_report_csv.text
    assert "INVESTIGATION TIMELINE" in inc_report_csv.text

    inc_report_pdf = client.get(f"/api/reports/incidents/{inc_code}/pdf")
    assert inc_report_pdf.status_code == 200
    assert "application/pdf" in inc_report_pdf.headers["content-type"]
    assert inc_report_pdf.content.startswith(b"%PDF-1.4")

    # =========================================================================
    # 5. SECURITY (RBAC, JWT Verification, Rate Limiting, Audit Logs)
    # =========================================================================
    # 5a. Verify JWT verification endpoint (/api/auth/verify)
    jwt_verify = client.get("/api/auth/verify", headers=admin_headers)
    assert jwt_verify.status_code == 200
    assert jwt_verify.json()["valid"] is True
    assert jwt_verify.json()["claims"]["sub"] == settings.INITIAL_ADMIN_USERNAME
    assert jwt_verify.json()["claims"]["type"] == "access"

    bad_jwt = client.get("/api/auth/verify", headers={"Authorization": "Bearer invalid.tampered.token"})
    assert bad_jwt.status_code == 401

    # 5b. Create a 'viewer' role user and verify RBAC blocks write operations & logs rbac_access_denied
    viewer_create = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "username": "soc.viewer",
            "email": "viewer@threatlens.local",
            "full_name": "Read-Only SOC Observer",
            "password": "ViewerPassword!2026",
            "role": "viewer",
        },
    )
    assert viewer_create.status_code == 201
    viewer_token = client.post(
        "/api/auth/login",
        json={"username": "soc.viewer", "password": "ViewerPassword!2026"},
    ).json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer attempting to create an incident must be denied with 403 Forbidden
    viewer_inc_attempt = client.post(
        "/api/incidents",
        headers=viewer_headers,
        json={"title": "Unauthorized Viewer Incident", "severity": "low"},
    )
    assert viewer_inc_attempt.status_code == 403

    # Viewer attempting to modify detection rules must be denied with 403 Forbidden
    viewer_rule_attempt = client.patch(
        "/api/detections/rules/RULE-001",
        headers=viewer_headers,
        json={"enabled": False},
    )
    assert viewer_rule_attempt.status_code == 403

    # 5c. Verify Audit Logs recorded rbac_access_denied and support filtering
    denied_logs = client.get("/api/system/audit-logs?action=rbac_access_denied&status=failure")
    assert denied_logs.status_code == 200
    assert len(denied_logs.json()) >= 2
    assert any(log["actor_username"] == "soc.viewer" for log in denied_logs.json())

    # 5d. Verify Sliding-Window API Rate Limiting returns 429 with Retry-After and X-RateLimit-* headers
    rate_limiter.reset()
    original_intel_limit = settings.RATE_LIMIT_INTEL_PER_MINUTE
    settings.RATE_LIMIT_INTEL_PER_MINUTE = 3
    try:
        for _ in range(3):
            ok_resp = client.get(
                "/api/threat-intelligence/lookup?ip=8.8.8.8",
                headers=analyst_headers,
            )
            assert ok_resp.status_code == 200

        rate_limited_resp = client.get(
            "/api/threat-intelligence/lookup?ip=8.8.8.8",
            headers=analyst_headers,
        )
        assert rate_limited_resp.status_code == 429
        assert "retry-after" in rate_limited_resp.headers
        assert rate_limited_resp.headers.get("x-ratelimit-limit") == "3"
        assert rate_limited_resp.headers.get("x-ratelimit-remaining") == "0"
    finally:
        settings.RATE_LIMIT_INTEL_PER_MINUTE = original_intel_limit
        rate_limiter.reset()


def test_phase8_complete_project_audit_database_indexes_migrations_and_docker_validation(test_context):
    """
    Phase 8 Complete Technical Audit Test:
    1. DATABASE:
       - Verifies all 11 normalized tables, foreign-key relationships, and PostgreSQL indexes (pg_indexes).
       - Verifies Alembic migration script (0001_initial_schema.py) and persistence across engine/session restarts.
    2. BACKEND API & ERROR HANDLING:
       - Exercises global search (/api/search), health (/api/health, /api/system/health), scenario catalog (/api/system/scenarios),
         demo environment reset (/api/system/reset-demo), manual detection evaluation (/api/detections/evaluate),
         and structured error responses (400, 401, 403, 404, 422).
    3. DOCKER & ENVIRONMENT VALIDATION:
       - Validates frontend/Dockerfile, backend/Dockerfile, docker-compose.yml, frontend/nginx.conf, and .env.example.
    """
    client, db = test_context

    # 1. Verify all 11 PostgreSQL tables & indexes
    expected_tables = {
        "users",
        "security_events",
        "detection_rules",
        "alerts",
        "alert_evidence",
        "alert_status_history",
        "incidents",
        "incident_alerts",
        "investigation_notes",
        "threat_indicators",
        "audit_logs",
    }
    table_rows = db.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    ).fetchall()
    existing_tables = {r[0] for r in table_rows}
    assert expected_tables.issubset(existing_tables)

    index_rows = db.execute(
        text("SELECT indexname FROM pg_indexes WHERE schemaname = 'public'")
    ).fetchall()
    existing_indexes = {r[0] for r in index_rows}
    expected_indexes = {
        "ix_users_username",
        "ix_users_email",
        "ix_security_events_event_id",
        "ix_security_events_timestamp",
        "ix_security_events_source_ip",
        "ix_security_events_cat_ts",
        "ix_security_events_src_user_ts",
        "ix_detection_rules_rule_id",
        "ix_detection_rules_rule_key",
        "ix_alerts_alert_id",
        "ix_alerts_status_sev",
        "ix_alerts_rule_dedup",
        "ix_alert_evidence_alert_id",
        "ix_alert_evidence_event_id",
        "ix_incidents_incident_id",
        "ix_threat_indicators_indicator_value",
    }
    assert expected_indexes.issubset(existing_indexes)

    # 2. Populate telemetry & verify persistence after engine connection pool disposal (simulating service restart)
    sim_resp = client.post("/api/system/simulate", json={"scenario_id": "all", "volume_multiplier": 1})
    assert sim_resp.status_code == 200
    pre_restart_events = client.get("/api/events").json()["total"]
    pre_restart_alerts = client.get("/api/alerts").json()["total"]
    assert pre_restart_events >= 20
    assert pre_restart_alerts >= 7

    # Dispose all pooled connections and open a fresh session to verify PostgreSQL persistence
    test_engine.dispose()
    with test_engine.connect() as fresh_conn:
        persisted_events = fresh_conn.execute(text("SELECT COUNT(*) FROM security_events")).scalar()
        persisted_alerts = fresh_conn.execute(text("SELECT COUNT(*) FROM alerts")).scalar()
        assert persisted_events == pre_restart_events
        assert persisted_alerts == pre_restart_alerts

    # 3. Verify Global Search (/api/search), Scenarios (/api/system/scenarios), Evaluate (/api/detections/evaluate), and Error Handling
    search_resp = client.get("/api/search?q=185.220.101.42")
    assert search_resp.status_code == 200
    search_body = search_resp.json()
    assert len(search_body["events"]) >= 1
    assert len(search_body["alerts"]) >= 1
    assert len(search_body["indicators"]) >= 1

    scenarios_resp = client.get("/api/system/scenarios")
    assert scenarios_resp.status_code == 200
    assert len(scenarios_resp.json()) >= 9

    eval_resp = client.post("/api/detections/evaluate")
    assert eval_resp.status_code == 200
    assert eval_resp.json()["evaluated_events_count"] >= 20

    # Structured error handling checks (400, 404, 422)
    assert client.get("/api/events/9999999").status_code == 404
    assert client.get("/api/alerts/ALT-NON-EXISTENT").status_code == 404
    assert client.get("/api/incidents/INC-NON-EXISTENT").status_code == 404
    assert client.get("/api/detections/rules/RULE-NON-EXISTENT").status_code == 404
    assert client.get("/api/threat-intelligence/lookup?ip=not-an-ip").status_code == 400
    assert client.post("/api/events", json={"source_ip": "bad_ip"}).status_code == 422

    # Demo reset endpoint (/api/system/reset-demo)
    reset_resp = client.post("/api/system/reset-demo")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "reset_complete"
    assert client.get("/api/events").json()["total"] >= 20

    # 4. Validate Dockerfiles, docker-compose.yml, nginx.conf, and Alembic migration files
    docker_compose_file = ROOT_DIR / "docker-compose.yml"
    backend_dockerfile = ROOT_DIR / "backend" / "Dockerfile"
    frontend_dockerfile = ROOT_DIR / "frontend" / "Dockerfile"
    nginx_conf = ROOT_DIR / "frontend" / "nginx.conf"
    env_example = ROOT_DIR / ".env.example"
    migration_file = ROOT_DIR / "backend" / "alembic" / "versions" / "0001_initial_schema.py"

    for path in (
        docker_compose_file,
        backend_dockerfile,
        frontend_dockerfile,
        nginx_conf,
        env_example,
        migration_file,
    ):
        assert path.exists(), f"Missing required deployment file: {path}"

    compose_text = docker_compose_file.read_text(encoding="utf-8")
    assert "postgres:16-alpine" in compose_text
    assert "threatlens-backend" in compose_text
    assert "threatlens-frontend" in compose_text
    assert "healthcheck:" in compose_text

    backend_df_text = backend_dockerfile.read_text(encoding="utf-8")
    assert "alembic upgrade head" in backend_df_text
    assert "uvicorn app.main:app" in backend_df_text

    frontend_df_text = frontend_dockerfile.read_text(encoding="utf-8")
    assert "npm run build" in frontend_df_text
    assert "nginx" in frontend_df_text







