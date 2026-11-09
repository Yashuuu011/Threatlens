# ThreatLens — Detection Rules & MITRE ATT&CK Catalog

ThreatLens implements a modular 7-rule Python correlation engine (`backend/app/detection/engine.py`) backed by PostgreSQL (`detection_rules`, `alerts`, `alert_evidence`, `alert_status_history`).

---

## 1. Detection Rule Summary Matrix

| Rule ID | Rule Key | Name | Category | Default Threshold | Window (s) | Severity | MITRE Tactic | Technique ID & Name |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE-001` | `brute_force` | Brute-Force Authentication Attack | `Authentication` | `5` failed events | `300` | `high` | Credential Access (`TA0006`) | `T1110.001` — Brute Force: Password Guessing |
| `RULE-002` | `password_spraying` | Password Spraying Attack | `Authentication` | `4` distinct users | `600` | `high` | Credential Access (`TA0006`) | `T1110.003` — Brute Force: Password Spraying |
| `RULE-003` | `login_after_failures` | Successful Login After Multiple Failures | `Authentication` | `3` preceding failures | `600` | `critical` | Initial Access (`TA0001`) | `T1078` — Valid Accounts |
| `RULE-004` | `unusual_login` | Unusual Login Activity | `Authentication` | `1` matching login | `900` | `medium` | Initial Access (`TA0001`) | `T1078.004` — Valid Accounts: Cloud Accounts |
| `RULE-005` | `privilege_escalation` | Suspicious Privilege Escalation | `Authorization` / `Endpoint` / `System` | `1` elevation event | `300` | `critical` | Privilege Escalation (`TA0004`) | `T1548` — Abuse Elevation Control Mechanism |
| `RULE-006` | `port_scanning` | Network Port Scanning Activity | `Network` | `8` distinct ports | `120` | `medium` | Discovery (`TA0007`) | `T1046` — Network Service Discovery |
| `RULE-007` | `suspicious_network` | Suspicious Network Activity & C2 Pattern | `Network` | `1` matching event | `300` | `high` | Command and Control (`TA0011`) | `T1071` — Application Layer Protocol |

---

## 2. Detailed Rule Logic & Deduplication Keys

### RULE-001: Brute-Force Authentication Attack (`brute_force`)
- **Trigger Condition**: `event_category == "Authentication"`, `status == "failure"`, and `username` is present.
- **Correlation Query**: Counts failed authentication events with the same `(source_ip, username)` within `[event.timestamp - time_window_seconds, event.timestamp]`. Fires when `count >= threshold_count` (default `5` within `300s`).
- **Deduplication Key**: `bf:{source_ip}:{username}`
- **Evidence Stored**: Links all matching failed authentication events as `triggering_event` in `alert_evidence`.

### RULE-002: Password Spraying Attack (`password_spraying`)
- **Trigger Condition**: `event_category == "Authentication"`, `status == "failure"`, and `username` is present.
- **Correlation Query**: Groups failed authentication events from `source_ip` within `time_window_seconds` (default `600s`) by `username`. Fires when the number of distinct usernames with `<= max_attempts_per_user` (default `3`) attempts is `>= threshold_count` (default `4`).
- **Deduplication Key**: `spray:{source_ip}`
- **Evidence Stored**: Links all failed spray events across the targeted accounts in `alert_evidence`.

### RULE-003: Successful Login After Multiple Failures (`login_after_failures`)
- **Trigger Condition**: `event_category == "Authentication"`, `status == "success"`, and `username` is present.
- **Correlation Query**: Queries preceding `Authentication` events with `status == "failure"` for the same `(source_ip, username)` within `time_window_seconds` (default `600s`). Fires when `len(preceding_failures) >= threshold_count` (default `3`).
- **Deduplication Key**: `succ_after_fail:{source_ip}:{username}`
- **Evidence Stored**: Links all preceding failure events (`evidence_role="triggering_event"`) and the final successful login (`evidence_role="compromise_event"`).

### RULE-004: Unusual Login Activity (`unusual_login`)
- **Trigger Condition**: `event_category == "Authentication"` and `status == "success"`.
- **Correlation Query**: Strictly evaluates observed telemetry without fabricating geolocation:
  1. `source_ip` matches an active Indicator of Compromise (`threat_indicators`), OR
  2. `metadata.unusual_login == true` / `metadata.anomalous_pattern == true`, OR
  3. `source_ip` is outside configured `internal_cidrs` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) AND occurs during `off_hours_utc` (`[0, 1, 2, 3, 4, 5, 22, 23]`) or has `metadata.new_source_network == true`.
- **Deduplication Key**: `unusual_login:{source_ip}:{username}`

### RULE-005: Suspicious Privilege Escalation (`privilege_escalation`)
- **Trigger Condition**: `event_category` in `{"Authorization", "Endpoint", "System"}`.
- **Correlation Query**: Matches `event_type` or `action` in `suspicious_actions` (`privilege_escalation`, `sudo_abuse`, `admin_group_modification`, `role_elevation`, `unauthorized_admin_access`, `setuid_execution`, `token_manipulation`, `sudo_to_root`), `metadata.privilege_escalation == true`, or `metadata.target_privilege` in `{"root", "SYSTEM", "Domain Admins", "sudoers", "Administrator"}`.
- **Deduplication Key**: `privesc:{source_ip}:{username}:{hostname}`

### RULE-006: Network Port Scanning Activity (`port_scanning`)
- **Trigger Condition**: `event_category == "Network"` and `destination_port` is present.
- **Correlation Query**: Queries all `Network` events from `source_ip` within `time_window_seconds` (default `120s`) and counts distinct `destination_port` values. Fires when `len(distinct_ports) >= threshold_count` (default `8`).
- **Deduplication Key**: `portscan:{source_ip}:{destination_ip}`

### RULE-007: Suspicious Network Activity & C2 Pattern (`suspicious_network`)
- **Trigger Condition**: `event_category == "Network"` (excluding pure `port_probe`/`syn_scan` events).
- **Correlation Query**: Fires when:
  1. `destination_port` is in `suspicious_ports` (`[4444, 1337, 6667, 9001, 31337, 5555]`), OR
  2. `metadata.bytes_out >= exfil_bytes_threshold` (default `10,000,000` bytes / 10 MB), OR
  3. `event_type` or `action` is in `suspicious_event_types` (`c2_beacon`, `data_exfiltration`, `suspicious_outbound`, `dns_tunneling`, `lateral_movement_smb`), OR
  4. `source_ip` or `destination_ip` matches an active IOC in `threat_indicators`.
- **Deduplication Key**: `susp_net:{source_ip}:{destination_ip}:{event_type}`

---

## 3. Known Detection Limitations

1. **Distributed Rotating-IP Attacks**: `RULE-001`, `RULE-002`, `RULE-003`, and `RULE-006` correlate events by `source_ip` within a sliding window. Highly distributed botnets rotating source IPs on every request (where no single IP reaches `threshold_count`) will evade per-IP thresholds.
2. **Low-and-Slow Attacks**: Activity spaced further apart than `time_window_seconds` (e.g., 1 failed login every 15 minutes) will not accumulate enough events inside the sliding window.
3. **Encrypted C2 Over Standard Ports**: Low-volume C2 traffic over TCP port `443` to an uncatalogued external IP (not in `threat_indicators`) will not trigger `RULE-007` unless accompanied by high outbound byte transfer or explicit C2 telemetry metadata.
4. **Telemetry-Bound Anomaly Detection (`RULE-004`)**: Because ThreatLens never fabricates GeoIP coordinates, `RULE-004` relies on RFC1918 vs. external IP classification, UTC login hour, local IOC matches, and supplied telemetry metadata.

