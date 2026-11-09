from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from telemetry.generators.event_factory import build_synthetic_event


SCENARIO_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "id": "normal_login",
        "name": "Normal Authentication Traffic",
        "category": "Authentication",
        "mode": "normal",
        "is_attack": False,
        "expected_rule_id": None,
        "description": "Routine employee SSH/SSO/Workstation logins from internal RFC1918 subnets.",
    },
    {
        "id": "ordinary_failed_login",
        "name": "Ordinary Failed Logins (Benign Typos)",
        "category": "Authentication",
        "mode": "normal",
        "is_attack": False,
        "expected_rule_id": None,
        "description": "Isolated 1-2 failed password attempts caused by benign user credential typos from internal workstations.",
    },
    {
        "id": "normal_network",
        "name": "Normal Internal & Web Network Traffic",
        "category": "Network",
        "mode": "normal",
        "is_attack": False,
        "expected_rule_id": None,
        "description": "Benign HTTPS (443), DNS (53), and internal microservice requests.",
    },
    {
        "id": "routine_system",
        "name": "Routine System & Host Events",
        "category": "System",
        "mode": "normal",
        "is_attack": False,
        "expected_rule_id": None,
        "description": "Routine systemd service checks, cron job completions, logrotate runs, and NTP clock synchronization.",
    },
    {
        "id": "brute_force",
        "name": "SSH / Portal Brute-Force Attack",
        "category": "Authentication",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-001",
        "mitre_technique_id": "T1110.001",
        "description": "Repeated rapid failed authentication attempts against a single target account.",
    },
    {
        "id": "password_spraying",
        "name": "Enterprise Password Spraying",
        "category": "Authentication",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-002",
        "mitre_technique_id": "T1110.003",
        "description": "Low-frequency failed logins across multiple distinct accounts from one external IP.",
    },
    {
        "id": "login_after_failures",
        "name": "Account Compromise After Failed Attempts",
        "category": "Authentication",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-003",
        "mitre_technique_id": "T1078",
        "description": "Multiple failed authentication attempts followed by a successful login from the same IP.",
    },
    {
        "id": "unusual_login",
        "name": "Off-Hours Anomalous External Login",
        "category": "Authentication",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-004",
        "mitre_technique_id": "T1078.004",
        "description": "Successful login from an external non-RFC1918 source IP during off-hours with anomaly flags.",
    },
    {
        "id": "privilege_escalation",
        "name": "Unauthorized Privilege Escalation",
        "category": "Authorization",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-005",
        "mitre_technique_id": "T1548",
        "description": "Suspicious sudoers modification and root elevation on a production server.",
    },
    {
        "id": "port_scanning",
        "name": "Horizontal TCP SYN Port Scan",
        "category": "Network",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-006",
        "mitre_technique_id": "T1046",
        "description": "Single source IP probing 12 distinct service ports on an internal server within 60s.",
    },
    {
        "id": "suspicious_network",
        "name": "C2 Beaconing & High-Volume Exfiltration",
        "category": "Network",
        "mode": "attack",
        "is_attack": True,
        "expected_rule_id": "RULE-007",
        "mitre_technique_id": "T1071",
        "description": "Outbound C2 connection on port 4444 and large anomalous outbound data transfer.",
    },
]


def generate_scenario_events(
    scenario_id: str,
    base_time: Optional[datetime] = None,
    volume_multiplier: int = 1,
) -> List[Dict[str, Any]]:
    """Generates reproducible synthetic security events for the requested scenario."""
    now = base_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    vol = max(1, min(volume_multiplier, 20))
    events: List[Dict[str, Any]] = []

    if scenario_id == "normal_login":
        users = [
            ("alice.chen", "10.10.20.14", "wkstn-eng-01"),
            ("marcus.vance", "10.10.20.22", "wkstn-fin-04"),
            ("priya.nair", "10.10.21.19", "wkstn-sec-02"),
            ("david.kim", "192.168.10.45", "wkstn-ops-07"),
        ]
        for i in range(4 * vol):
            user, src_ip, host = users[i % len(users)]
            ts = now - timedelta(seconds=(4 * vol - i) * 12)
            # Set hour to normal business hour (14:00 UTC) if needed, or preserve relative ordering
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip="10.10.1.10",
                    destination_port=443,
                    username=user,
                    hostname=host,
                    event_type="user_login",
                    event_category="Authentication",
                    action="sso_authenticate",
                    status="success",
                    severity="low",
                    raw_log=(
                        f"Oct/Nov {ts.isoformat()} auth-gw01 sshd[2190]: Accepted publickey for "
                        f"{user} from {src_ip} port 52410 ssh2"
                    ),
                    scenario="normal_login",
                    ground_truth="benign",
                    expected_rule_id=None,
                    extra_metadata={"auth_method": "sso_mfa", "session_type": "workstation"},
                )
            )

    elif scenario_id == "brute_force":
        src_ip = "185.220.101.42"
        target_user = "svc_backup_admin"
        target_host = "prod-vault-01"
        attempt_count = 6 * vol
        for i in range(attempt_count):
            ts = now - timedelta(seconds=(attempt_count - i) * 8)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip="10.20.0.15",
                    destination_port=22,
                    username=target_user,
                    hostname=target_host,
                    event_type="ssh_auth_failure",
                    event_category="Authentication",
                    action="password_login",
                    status="failure",
                    severity="medium",
                    raw_log=(
                        f"{ts.isoformat()} {target_host} sshd[{3400 + i}]: Failed password for "
                        f"{target_user} from {src_ip} port {49100 + i} ssh2"
                    ),
                    scenario="brute_force",
                    ground_truth="malicious",
                    expected_rule_id="RULE-001",
                    extra_metadata={
                        "protocol": "SSH",
                        "attempt_number": i + 1,
                        "failure_reason": "invalid_credentials",
                    },
                )
            )

    elif scenario_id == "password_spraying":
        src_ip = "91.240.118.172"
        spray_users = [
            "j.anderson",
            "s.martinez",
            "k.thompson",
            "r.patel",
            "m.oconnor",
            "l.zhang",
        ]
        for idx, uname in enumerate(spray_users):
            ts = now - timedelta(seconds=(len(spray_users) - idx) * 15)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip="10.20.0.5",
                    destination_port=443,
                    username=uname,
                    hostname="idp-portal-prod-01",
                    event_type="oauth_password_auth",
                    event_category="Authentication",
                    action="password_spray_attempt",
                    status="failure",
                    severity="medium",
                    raw_log=(
                        f"{ts.isoformat()} idp-portal-prod-01 auth-service: Authentication failed "
                        f"for user='{uname}' src_ip={src_ip} user_agent='Mozilla/5.0 (Python-Requests)'"
                    ),
                    scenario="password_spraying",
                    ground_truth="malicious",
                    expected_rule_id="RULE-002",
                    extra_metadata={
                        "auth_endpoint": "/oauth2/token",
                        "user_agent": "python-requests/2.31.0",
                        "spray_batch": True,
                    },
                )
            )

    elif scenario_id == "login_after_failures":
        src_ip = "45.155.205.109"
        compromised_user = "devops.deployer"
        target_host = "ci-runner-prod-02"
        for i in range(4):
            ts = now - timedelta(seconds=(5 - i) * 10)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip="10.20.1.30",
                    destination_port=22,
                    username=compromised_user,
                    hostname=target_host,
                    event_type="ssh_login_attempt",
                    event_category="Authentication",
                    action="ssh_password_auth",
                    status="failure",
                    severity="medium",
                    raw_log=(
                        f"{ts.isoformat()} {target_host} sshd[{5100 + i}]: Failed password for "
                        f"{compromised_user} from {src_ip} port {55100 + i} ssh2"
                    ),
                    scenario="login_after_failures",
                    ground_truth="malicious",
                    expected_rule_id="RULE-003",
                    extra_metadata={"phase": "credential_stuffing_failure", "attempt": i + 1},
                )
            )
        events.append(
            build_synthetic_event(
                timestamp=now,
                source_ip=src_ip,
                destination_ip="10.20.1.30",
                destination_port=22,
                username=compromised_user,
                hostname=target_host,
                event_type="ssh_login_success",
                event_category="Authentication",
                action="ssh_password_auth",
                status="success",
                severity="high",
                raw_log=(
                    f"{now.isoformat()} {target_host} sshd[5109]: Accepted password for "
                    f"{compromised_user} from {src_ip} port 55109 ssh2"
                ),
                scenario="login_after_failures",
                ground_truth="malicious",
                expected_rule_id="RULE-003",
                extra_metadata={"phase": "post_failure_compromise", "mfa_used": False},
            )
        )

    elif scenario_id == "unusual_login":
        # Construct an off-hours UTC timestamp (e.g. 03:15 UTC) or explicit anomalous telemetry
        off_hours_ts = now.replace(hour=3, minute=15, second=0, microsecond=0)
        if off_hours_ts > now:
            off_hours_ts = off_hours_ts - timedelta(days=1)
        src_ip = "198.51.100.88"
        events.append(
            build_synthetic_event(
                timestamp=off_hours_ts,
                source_ip=src_ip,
                destination_ip="10.20.0.10",
                destination_port=443,
                username="db.admin",
                hostname="bastion-core-01",
                event_type="remote_vpn_login",
                event_category="Authentication",
                action="vpn_session_established",
                status="success",
                severity="medium",
                raw_log=(
                    f"{off_hours_ts.isoformat()} bastion-core-01 openvpn[8812]: "
                    f"TLS-Auth session established for user='db.admin' from untrusted external IP {src_ip} at 03:15 UTC"
                ),
                scenario="unusual_login",
                ground_truth="malicious",
                expected_rule_id="RULE-004",
                extra_metadata={
                    "unusual_login": True,
                    "anomalous_pattern": True,
                    "new_source_network": True,
                    "anomaly_reason": "External non-RFC1918 source IP login for privileged account during 03:15 UTC window",
                },
            )
        )

    elif scenario_id == "privilege_escalation":
        src_ip = "10.10.30.55"
        for i in range(vol):
            ts = now - timedelta(seconds=(vol - i) * 5)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip="10.20.4.12",
                    destination_port=None,
                    username="web_worker",
                    hostname="app-node-prod-03",
                    event_type="privilege_escalation",
                    event_category="Authorization",
                    action="sudo_abuse",
                    status="success",
                    severity="critical",
                    raw_log=(
                        f"{ts.isoformat()} app-node-prod-03 sudo: web_worker : TTY=pts/1 ; "
                        f"PWD=/tmp ; USER=root ; COMMAND=/bin/chmod u+s /bin/bash"
                    ),
                    scenario="privilege_escalation",
                    ground_truth="malicious",
                    expected_rule_id="RULE-005",
                    extra_metadata={
                        "privilege_escalation": True,
                        "previous_privilege": "www-data",
                        "target_privilege": "root",
                        "command": "/bin/chmod u+s /bin/bash",
                        "mitre_technique": "T1548",
                    },
                )
            )

    elif scenario_id == "port_scanning":
        src_ip = "172.16.99.204"
        dst_ip = "10.20.0.100"
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389]
        for idx, port in enumerate(ports):
            ts = now - timedelta(seconds=(len(ports) - idx) * 2)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=port,
                    username=None,
                    hostname="fw-perimeter-01",
                    event_type="port_probe",
                    event_category="Network",
                    action="tcp_syn_probe",
                    status="blocked",
                    severity="low",
                    raw_log=(
                        f"{ts.isoformat()} fw-perimeter-01 kernel: [UFW BLOCK] IN=eth0 OUT= "
                        f"SRC={src_ip} DST={dst_ip} PROTO=TCP SPT={42000 + idx} DPT={port} SYN"
                    ),
                    scenario="port_scanning",
                    ground_truth="malicious",
                    expected_rule_id="RULE-006",
                    extra_metadata={
                        "protocol": "TCP",
                        "tcp_flags": "SYN",
                        "destination_port": port,
                        "scan_type": "horizontal_port_sweep",
                    },
                )
            )

    elif scenario_id == "normal_network":
        flows = [
            ("10.10.20.14", "10.20.0.50", 443, "https_request", 2400),
            ("10.10.20.22", "10.20.0.53", 53, "dns_query", 180),
            ("10.10.21.19", "10.20.0.80", 8080, "internal_api_call", 4120),
            ("10.10.20.31", "10.20.0.50", 443, "https_request", 1950),
        ]
        for i in range(4 * vol):
            src, dst, port, ev_type, b_out = flows[i % len(flows)]
            ts = now - timedelta(seconds=(4 * vol - i) * 7)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src,
                    destination_ip=dst,
                    destination_port=port,
                    username=None,
                    hostname="core-switch-01",
                    event_type=ev_type,
                    event_category="Network",
                    action="allow",
                    status="allowed",
                    severity="info",
                    raw_log=(
                        f"{ts.isoformat()} core-switch-01 netflow: ALLOW TCP {src} -> {dst}:{port} "
                        f"bytes_out={b_out} status=ESTABLISHED"
                    ),
                    scenario="normal_network",
                    ground_truth="benign",
                    expected_rule_id=None,
                    extra_metadata={"protocol": "TCP", "bytes_out": b_out},
                )
            )

    elif scenario_id == "ordinary_failed_login":
        typo_attempts = [
            ("elena.ross", "10.10.25.101", "wkstn-hr-03"),
            ("thomas.wright", "10.10.25.102", "wkstn-mkt-05"),
        ]
        for idx, (user, src_ip, host) in enumerate(typo_attempts):
            ts = now - timedelta(seconds=(len(typo_attempts) - idx) * 20)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip="10.10.1.10",
                    destination_port=443,
                    username=user,
                    hostname=host,
                    event_type="user_login_failure",
                    event_category="Authentication",
                    action="sso_authenticate",
                    status="failure",
                    severity="low",
                    raw_log=(
                        f"{ts.isoformat()} {host} sso-agent[1420]: Failed password for {user} "
                        f"from {src_ip} port 51200 (reason=benign_password_typo)"
                    ),
                    scenario="ordinary_failed_login",
                    ground_truth="benign",
                    expected_rule_id=None,
                    extra_metadata={
                        "mode": "NORMAL",
                        "failure_reason": "single_password_typo",
                        "attempt_count": 1,
                    },
                )
            )

    elif scenario_id == "routine_system":
        sys_tasks = [
            ("10.10.1.50", "core-chrony-01", "ntp_clock_sync", "chronyd_sync", "System clock synchronized with stratum-2 pool"),
            ("10.10.1.51", "app-node-prod-01", "systemd_service_check", "health_check", "systemd[1]: Started ThreatLens Node Health Check"),
            ("10.10.1.52", "db-replica-01", "logrotate_execution", "log_rotation", "logrotate[812]: Rotated /var/log/syslog successfully"),
            ("10.10.1.53", "backup-scheduler-01", "cron_job_complete", "scheduled_task", "CRON[4412]: (root) CMD (/usr/local/bin/snapshot-verify --quiet)"),
        ]
        for i in range(4 * vol):
            src_ip, host, ev_type, act, msg = sys_tasks[i % len(sys_tasks)]
            ts = now - timedelta(seconds=(4 * vol - i) * 9)
            events.append(
                build_synthetic_event(
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip=None,
                    destination_port=None,
                    username="system",
                    hostname=host,
                    event_type=ev_type,
                    event_category="System",
                    action=act,
                    status="success",
                    severity="info",
                    raw_log=f"{ts.isoformat()} {host} {msg}",
                    scenario="routine_system",
                    ground_truth="benign",
                    expected_rule_id=None,
                    extra_metadata={"mode": "NORMAL", "subsystem": "os_maintenance"},
                )
            )

    elif scenario_id in ("normal_mode", "normal"):
        return generate_normal_mode_telemetry(base_time=now, volume_multiplier=vol)

    elif scenario_id in ("attack_mode", "attack"):
        return generate_attack_mode_telemetry(base_time=now, volume_multiplier=vol)

    elif scenario_id == "suspicious_network":
        src_ip = "10.10.30.55"
        c2_ip = "203.0.113.250"
        events.append(
            build_synthetic_event(
                timestamp=now - timedelta(seconds=15),
                source_ip=src_ip,
                destination_ip=c2_ip,
                destination_port=4444,
                username="web_worker",
                hostname="app-node-prod-03",
                event_type="c2_beacon",
                event_category="Network",
                action="suspicious_outbound",
                status="allowed",
                severity="critical",
                raw_log=(
                    f"{(now - timedelta(seconds=15)).isoformat()} fw-perimeter-01 suricata[1102]: "
                    f"[ALERT] Outbound connection to suspected C2 channel {src_ip}:51822 -> {c2_ip}:4444"
                ),
                scenario="suspicious_network",
                ground_truth="malicious",
                expected_rule_id="RULE-007",
                extra_metadata={
                    "protocol": "TCP",
                    "destination_port": 4444,
                    "bytes_out": 24500000,
                    "ja3_fingerprint": "e7d705a3286e19ea42f587b344ee6865",
                    "threat_category": "Command and Control / Exfiltration",
                },
            )
        )

    else:
        raise ValueError(f"Unknown synthetic scenario '{scenario_id}'")

    return events


def generate_normal_mode_telemetry(
    base_time: Optional[datetime] = None,
    volume_multiplier: int = 1,
) -> List[Dict[str, Any]]:
    """
    NORMAL MODE synthetic telemetry generator:
    - Successful logins (normal_login)
    - Ordinary failed logins (ordinary_failed_login)
    - Normal network connections (normal_network)
    - Routine system events (routine_system)
    All generated events are explicitly labeled as synthetic (is_synthetic=True).
    """
    ref = base_time or datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []
    normal_scenarios = [
        ("normal_login", -600),
        ("ordinary_failed_login", -450),
        ("normal_network", -300),
        ("routine_system", -120),
    ]
    for scen_id, offset in normal_scenarios:
        scen_ts = ref + timedelta(seconds=offset)
        batch = generate_scenario_events(scen_id, base_time=scen_ts, volume_multiplier=volume_multiplier)
        for ev in batch:
            ev["is_synthetic"] = True
            ev.setdefault("metadata", {})["telemetry_mode"] = "NORMAL_MODE"
        events.extend(batch)
    return events


def generate_attack_mode_telemetry(
    base_time: Optional[datetime] = None,
    volume_multiplier: int = 1,
) -> List[Dict[str, Any]]:
    """
    ATTACK SIMULATION MODE synthetic telemetry generator:
    - Repeated failed logins (brute_force)
    - Password spraying (password_spraying)
    - Suspicious privilege changes (privilege_escalation)
    - Port scanning (port_scanning)
    - Successful login after multiple failures (login_after_failures)
    All generated events are explicitly labeled as synthetic (is_synthetic=True).
    """
    ref = base_time or datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []
    attack_scenarios = [
        ("brute_force", -900),
        ("password_spraying", -700),
        ("privilege_escalation", -500),
        ("port_scanning", -300),
        ("login_after_failures", -100),
    ]
    for scen_id, offset in attack_scenarios:
        scen_ts = ref + timedelta(seconds=offset)
        batch = generate_scenario_events(scen_id, base_time=scen_ts, volume_multiplier=volume_multiplier)
        for ev in batch:
            ev["is_synthetic"] = True
            ev.setdefault("metadata", {})["telemetry_mode"] = "ATTACK_SIMULATION_MODE"
        events.extend(batch)
    return events


def generate_full_simulation_suite(base_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Generates a balanced dataset across all benign (NORMAL MODE) and malicious (ATTACK MODE) scenarios."""
    ref = base_time or datetime.now(timezone.utc)
    all_events: List[Dict[str, Any]] = []
    offsets = [
        ("normal_login", -1800),
        ("ordinary_failed_login", -1650),
        ("normal_network", -1500),
        ("routine_system", -1350),
        ("brute_force", -1200),
        ("password_spraying", -950),
        ("login_after_failures", -700),
        ("unusual_login", -500),
        ("privilege_escalation", -350),
        ("port_scanning", -200),
        ("suspicious_network", -60),
    ]
    for scen_id, sec_offset in offsets:
        scen_time = ref + timedelta(seconds=sec_offset)
        all_events.extend(generate_scenario_events(scen_id, base_time=scen_time))
    return all_events

