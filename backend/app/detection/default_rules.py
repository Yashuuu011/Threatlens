from typing import Any, Dict, List

DEFAULT_DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "RULE-001",
        "rule_key": "brute_force",
        "name": "Brute-Force Authentication Attack",
        "description": (
            "Detects repeated failed authentication attempts against the same user account "
            "originating from a single source IP address within the configured time window."
        ),
        "detection_logic": (
            "SELECT source_ip, username, COUNT(*) FROM security_events "
            "WHERE event_category = 'Authentication' AND status = 'failure' "
            "GROUP BY source_ip, username HAVING COUNT(*) >= threshold_count WITHIN time_window_seconds"
        ),
        "event_category": "Authentication",
        "threshold_count": 5,
        "time_window_seconds": 300,
        "parameters": {
            "target_status": "failure",
            "group_by": ["source_ip", "username"],
        },
        "severity": "high",
        "enabled": True,
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
    },
    {
        "rule_id": "RULE-002",
        "rule_key": "password_spraying",
        "name": "Password Spraying Attack",
        "description": (
            "Detects failed authentication attempts targeting multiple distinct usernames "
            "from a single source IP within a short time window, distinguishing horizontal "
            "account enumeration/spraying from single-account brute-force."
        ),
        "detection_logic": (
            "SELECT source_ip, COUNT(DISTINCT username) FROM security_events "
            "WHERE event_category = 'Authentication' AND status = 'failure' "
            "GROUP BY source_ip HAVING COUNT(DISTINCT username) >= threshold_count "
            "AND MAX(attempts_per_user) <= max_attempts_per_user WITHIN time_window_seconds"
        ),
        "event_category": "Authentication",
        "threshold_count": 4,
        "time_window_seconds": 600,
        "parameters": {
            "min_distinct_users": 4,
            "max_attempts_per_user": 3,
        },
        "severity": "high",
        "enabled": True,
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110.003",
        "mitre_technique_name": "Brute Force: Password Spraying",
    },
    {
        "rule_id": "RULE-003",
        "rule_key": "login_after_failures",
        "name": "Successful Login After Multiple Failures",
        "description": (
            "Identifies a successful authentication event immediately following repeated failed "
            "login attempts for the same username and source IP within the correlation window."
        ),
        "detection_logic": (
            "Correlate Authentication status='success' WITH preceding status='failure' events "
            "matching (source_ip, username) WHERE preceding_failures >= threshold_count "
            "WITHIN time_window_seconds"
        ),
        "event_category": "Authentication",
        "threshold_count": 3,
        "time_window_seconds": 600,
        "parameters": {
            "require_same_source_ip": True,
            "require_same_username": True,
        },
        "severity": "critical",
        "enabled": True,
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
    },
    {
        "rule_id": "RULE-004",
        "rule_key": "unusual_login",
        "name": "Unusual Login Activity",
        "description": (
            "Detects successful logins from external/non-RFC1918 source IPs or abnormal "
            "authentication telemetry patterns (such as unseen source networks, off-hours "
            "privileged logins, or untrusted auth methods) based strictly on observed event data."
        ),
        "detection_logic": (
            "Evaluate Authentication status='success' WHERE source_ip NOT IN internal_cidrs "
            "AND (hour_utc IN off_hours OR metadata.anomalous_pattern = true OR source_ip IN threat_indicators)"
        ),
        "event_category": "Authentication",
        "threshold_count": 1,
        "time_window_seconds": 900,
        "parameters": {
            "internal_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
            "off_hours_utc": [0, 1, 2, 3, 4, 5, 22, 23],
        },
        "severity": "medium",
        "enabled": True,
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078.004",
        "mitre_technique_name": "Valid Accounts: Cloud Accounts",
    },
    {
        "rule_id": "RULE-005",
        "rule_key": "privilege_escalation",
        "name": "Suspicious Privilege Escalation",
        "description": (
            "Identifies unauthorized privilege elevation, suspicious sudo/root executions, "
            "administrative group modifications, or token manipulation events."
        ),
        "detection_logic": (
            "Match events in (Authorization, Endpoint, System) WHERE event_type OR action IN "
            "['privilege_escalation', 'sudo_abuse', 'admin_group_modification', 'role_elevation', "
            "'unauthorized_admin_access', 'setuid_execution', 'token_manipulation']"
        ),
        "event_category": "Authorization",
        "threshold_count": 1,
        "time_window_seconds": 300,
        "parameters": {
            "suspicious_actions": [
                "privilege_escalation",
                "sudo_abuse",
                "admin_group_modification",
                "role_elevation",
                "unauthorized_admin_access",
                "setuid_execution",
                "token_manipulation",
                "sudo_to_root",
            ]
        },
        "severity": "critical",
        "enabled": True,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique_id": "T1548",
        "mitre_technique_name": "Abuse Elevation Control Mechanism",
    },
    {
        "rule_id": "RULE-006",
        "rule_key": "port_scanning",
        "name": "Network Port Scanning Activity",
        "description": (
            "Detects a single source IP attempting connections across multiple distinct "
            "destination ports within a short configurable reconnaissance window."
        ),
        "detection_logic": (
            "SELECT source_ip, COUNT(DISTINCT destination_port) FROM security_events "
            "WHERE event_category = 'Network' AND destination_port IS NOT NULL "
            "GROUP BY source_ip HAVING COUNT(DISTINCT destination_port) >= threshold_count "
            "WITHIN time_window_seconds"
        ),
        "event_category": "Network",
        "threshold_count": 8,
        "time_window_seconds": 120,
        "parameters": {
            "min_distinct_ports": 8,
        },
        "severity": "medium",
        "enabled": True,
        "mitre_tactic": "Discovery",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
    },
    {
        "rule_id": "RULE-007",
        "rule_key": "suspicious_network",
        "name": "Suspicious Network Activity & C2 Pattern",
        "description": (
            "Identifies network events matching configurable suspicious behavior patterns, "
            "including connections to known C2 ports, high-volume outbound transfers, "
            "DNS tunneling indicators, or active threat intelligence IOCs."
        ),
        "detection_logic": (
            "Match Network events WHERE destination_port IN suspicious_ports "
            "OR metadata.bytes_out >= exfil_bytes_threshold "
            "OR event_type IN ['c2_beacon', 'data_exfiltration', 'suspicious_outbound', 'dns_tunneling']"
        ),
        "event_category": "Network",
        "threshold_count": 1,
        "time_window_seconds": 300,
        "parameters": {
            "suspicious_ports": [4444, 1337, 6667, 9001, 31337, 5555],
            "exfil_bytes_threshold": 10000000,
            "suspicious_event_types": [
                "c2_beacon",
                "data_exfiltration",
                "suspicious_outbound",
                "dns_tunneling",
                "lateral_movement_smb",
            ],
        },
        "severity": "high",
        "enabled": True,
        "mitre_tactic": "Command and Control",
        "mitre_technique_id": "T1071",
        "mitre_technique_name": "Application Layer Protocol",
    },
]

