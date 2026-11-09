# ThreatLens — REST & WebSocket API Documentation

## 1. Interactive OpenAPI / Swagger Endpoints
When the FastAPI backend is running on port `8000`:
- **Swagger UI (Interactive API Explorer)**: `http://localhost:8000/docs`
- **ReDoc Reference**: `http://localhost:8000/redoc`
- **OpenAPI JSON Schema**: `http://localhost:8000/openapi.json`
- **Base API Prefix**: `http://localhost:8000/api` (proxied via `/api` on the Nginx/Vite frontend)

---

## 2. Authentication & User Management (`/api/auth`)

All protected write endpoints accept a `Bearer <JWT>` token in the `Authorization` header. Tokens include `sub` (username), `role`, `uid`, `iat`, `exp`, and `type: "access"` claims signed with `HS256`.

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Public (Rate-limited) | Authenticates `username` and `password`, updates `last_login`, records an `audit_logs` entry, and returns `{ access_token, token_type, expires_in, user }`. |
| `GET` | `/api/auth/me` | Authenticated | Returns the authenticated user's profile (`id`, `username`, `email`, `full_name`, `role`, `is_active`, `last_login`). |
| `GET` | `/api/auth/verify` | Authenticated | Verifies JWT signature and required claims (`sub`, `exp`, `iat`, `type`) and returns `{ valid: true, claims, user }`. |
| `GET` | `/api/auth/users` | Public / SOC | Lists registered SOC operators ordered by ID. |
| `POST` | `/api/auth/users` | `admin` | Creates a new SOC user with role in `admin`, `soc_lead`, `analyst`, or `viewer`. |

---

## 3. Security Event Ingestion & Explorer (`/api/events`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/events` | Public / Agent (Rate-limited) | Ingests a single structured JSON event or `{ "raw_log_line": "...", "is_synthetic": true }`, normalizes UTC timestamp and IPv4/IPv6 fields, stores in PostgreSQL, evaluates detection rules, and broadcasts `event_ingested` + `dashboard_metrics_updated`. |
| `POST` | `/api/events/bulk` | Public / Agent (Rate-limited) | Ingests up to `5,000` events in one batch (`events: [...]`, `run_detections: true|false`). Safely rejects malformed events into an `errors` list while persisting all valid events. |
| `GET` | `/api/events` | Public / SOC | Paginated event explorer supporting query parameters: `page`, `page_size`, `search`, `event_category`, `severity`, `status`, `source_ip`, `username`, `hostname`, `event_type`, `is_synthetic`, `start_time`, `end_time`, `sort_by`, `sort_order`. |
| `GET` | `/api/events/{event_identifier}` | Public / SOC | Retrieves full forensic event details (by integer `id` or `event_id` string), including `raw_log`, `metadata`, `related_events` from the same source IP, and `linked_alerts`. |

---

## 4. Alerts Management & Triage (`/api/alerts`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/alerts` | Public / SOC | Paginated alerts queue with filters (`status`, `severity`, `rule_code`, `source_ip`, `search`, `sort_by`, `sort_order`). |
| `GET` | `/api/alerts/{alert_identifier}` | Public / SOC | Returns full alert detail including triggering `evidence_events`, `status_history`, analyst `notes`, and `linked_incidents` (`linked_incident_ids`). |
| `PATCH` | `/api/alerts/{alert_identifier}/status` | `admin`, `soc_lead`, `analyst` | Updates alert triage status (`New`, `Acknowledged`, `Investigating`, `Resolved`, `False Positive`), appends to `alert_status_history`, optionally records a comment note, writes to `audit_logs`, and broadcasts `alert_status_updated`. |
| `POST` | `/api/alerts/{alert_identifier}/notes` | `admin`, `soc_lead`, `analyst` | Attaches an analyst investigation note (`content`, `note_type`) to the alert. |

---

## 5. Threat Detection Rules & MITRE ATT&CK (`/api/detections`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/detections/rules` | Public / SOC | Lists all detection rules ordered by `rule_id` along with triggered `alert_count`. |
| `GET` | `/api/detections/rules/{rule_identifier}` | Public / SOC | Returns rule configuration and up to 20 recent alerts triggered by the rule. |
| `POST` | `/api/detections/rules` | `admin` | Creates a new custom detection rule (`409 Conflict` if `rule_id`, `rule_key`, or `name` already exists). |
| `PATCH` | `/api/detections/rules/{rule_identifier}` | `admin`, `soc_lead`, `analyst` | Enables/disables a rule (`enabled`) or updates `threshold_count`, `time_window_seconds`, `severity`, `parameters`, `name`, or `description`. |
| `DELETE` | `/api/detections/rules/{rule_identifier}` | `admin` | Deletes a detection rule and logs the action in `audit_logs`. |
| `GET` | `/api/detections/mitre` | Public / SOC | Returns MITRE ATT&CK mappings (`tactic`, `tactic_id`, `technique_id`, `technique_name`, `reference_url`, `associated_rules`, `related_alerts`, `tactic_summary`). |
| `GET` | `/api/detections/history` | Public / SOC | Returns chronological detection history (triggered alerts + `triggering_events` evidence + `rule_configuration_history`). |
| `POST` | `/api/detections/evaluate` | Public / SOC | Re-evaluates recent stored security events against all enabled detection rules. |

---

## 6. Incident Investigation Workflows (`/api/incidents`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/incidents` | Public / SOC | Lists incidents with pagination and filters (`status`, `severity`, `assigned_analyst`, `search`). |
| `POST` | `/api/incidents` | `admin`, `soc_lead`, `analyst` | Creates a new incident (`Open`, `Investigating`, `Contained`, `Resolved`, `Closed`), associates initial `alert_ids`, populates `evidence_references` and `timeline_events`, and broadcasts `incident_created`. |
| `GET` | `/api/incidents/{incident_identifier}` | Public / SOC | Returns complete incident dossier: `related_alerts`, `related_events`, `timeline_events`, `status_history`, `evidence_references`, `notes`, and `mitre_mappings`. |
| `PATCH` | `/api/incidents/{incident_identifier}` | `admin`, `soc_lead`, `analyst` | Updates incident metadata, status, assigned analyst, or resolution summary. |
| `PATCH` | `/api/incidents/{incident_identifier}/status` | `admin`, `soc_lead`, `analyst` | Transitions incident status (`Open`, `Investigating`, `Contained`, `Resolved`, `Closed`), updates `resolved_at` when resolved/closed, and appends to `timeline_events`. |
| `POST` | `/api/incidents/{incident_identifier}/alerts` | `admin`, `soc_lead`, `analyst` | Associates one or more additional alerts (by integer ID or `alert_id` code) with the incident. |
| `DELETE` | `/api/incidents/{incident_identifier}/alerts/{alert_identifier}` | `admin`, `soc_lead`, `analyst` | Unlinks an alert from the incident and records the action in the timeline. |
| `GET` | `/api/incidents/{incident_identifier}/events` | Public / SOC | Lists all correlated `SecurityEvent` records linked via the incident's alerts or evidence references. |
| `GET` | `/api/incidents/{incident_identifier}/timeline` | Public / SOC | Returns the chronological investigation timeline for the incident. |
| `GET` | `/api/incidents/{incident_identifier}/history` | Public / SOC | Returns all status transitions for the incident. |
| `GET` | `/api/incidents/{incident_identifier}/evidence` | Public / SOC | Returns all structured evidence references (`alert`, `event`, `ioc`, `artifact`, `log`). |
| `POST` | `/api/incidents/{incident_identifier}/evidence` | `admin`, `soc_lead`, `analyst` | Adds a forensic evidence reference to the incident and logs to `timeline_events`. |
| `GET` | `/api/incidents/{incident_identifier}/notes` | Public / SOC | Lists analyst investigation notes for the incident. |
| `POST` | `/api/incidents/{incident_identifier}/notes` | `admin`, `soc_lead`, `analyst` | Adds a timestamped investigation note (`investigation_note`, `forensic_finding`, `containment_action`, `remediation`) to the incident. |

---

## 7. Threat Intelligence & IOC Management (`/api/threat-intelligence`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/threat-intelligence/lookup?ip={ip}` | Public / SOC (Rate-limited) | Performs IPv4/IPv6 reputation lookup across local PostgreSQL IOCs, internal SIEM telemetry (`events_as_source`, `failed_authentications`, `associated_alerts_count`), and configured external providers (`AbuseIPDB`, `VirusTotal`, `AlienVault OTX`). Never fabricates scores when external keys are unconfigured. |
| `GET` | `/api/threat-intelligence/suspicious-ips` | Public / SOC | Returns tracked suspicious IPs correlated from SIEM events, triggered alerts, and local IOCs (`confirmed_ioc`, `alert_source`, `repeated_auth_failures`, `active_telemetry`). |
| `GET` | `/api/threat-intelligence/indicators` | Public / SOC | Lists local Threat Indicators (`threat_indicators`) with filters (`search`, `indicator_type`, `threat_type`, `severity`, `active_only`). |
| `POST` | `/api/threat-intelligence/indicators` | `admin`, `soc_lead`, `analyst` | Creates or updates a Threat Indicator with strict validation of IP/CIDR/domain/hash values. |
| `PATCH` | `/api/threat-intelligence/indicators/{id}` | `admin`, `soc_lead`, `analyst` | Updates IOC `confidence`, `severity`, `threat_type`, `tags`, or `is_active` status. |
| `DELETE` | `/api/threat-intelligence/indicators/{id}` | `admin`, `soc_lead`, `analyst` | Deletes a Threat Indicator from PostgreSQL. |
| `GET` | `/api/threat-intelligence/providers` | Public / SOC | Returns configuration status and masked keys for `ThreatLens Local IOC Database`, `AbuseIPDB`, `VirusTotal`, and `AlienVault OTX`. |
| `PUT` | `/api/threat-intelligence/providers` | `admin`, `soc_lead` | Updates runtime API keys (`abuseipdb_api_key`, `virustotal_api_key`, `otx_api_key`) and `enable_external_lookup`. |

---

## 8. Analytics & Reporting (`/api/analytics`, `/api/reports`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/analytics/overview` | Public / SOC | Returns SOC Overview Dashboard KPIs, time-series event trends, severity/category breakdowns, top source IPs, recent alerts/incidents, and system health. |
| `GET` | `/api/analytics/performance` | Public / SOC | Returns full SOC analytics: `alerts_by_severity`, `detection_rule_frequency`, `event_trends`, `incident_resolution_stats` (`resolution_rate`, `mean_time_to_resolve_minutes`), and ground-truth `detection_evaluation`. |
| `GET` | `/api/analytics/detection-accuracy` | Public / SOC | Returns ground-truth Confusion Matrix metrics (`true_positives`, `false_positives`, `true_negatives`, `false_negatives`, `precision`, `recall`, `f1_score`, `accuracy`, `false_positive_rate`) and per-rule performance. |
| `GET` | `/api/analytics/incidents` | Public / SOC | Returns incident resolution statistics and incident summary breakdown. |
| `GET` | `/api/reports/export/csv` | Public / SOC (Rate-limited) | Exports a downloadable CSV SOC analytical report. |
| `GET` | `/api/reports/export/pdf` | Public / SOC (Rate-limited) | Exports a downloadable standards-compliant PDF 1.4 SOC analytical report. |
| `GET` | `/api/reports/incidents/{incident_identifier}` | Public / SOC | Returns the structured JSON Incident Investigation Report for a specific incident. |
| `GET` | `/api/reports/incidents/{incident_identifier}/csv` | Public / SOC (Rate-limited) | Exports a downloadable CSV Incident Investigation Report (overview, MITRE mappings, alerts, timeline, notes, and evidence). |
| `GET` | `/api/reports/incidents/{incident_identifier}/pdf` | Public / SOC (Rate-limited) | Exports a downloadable PDF 1.4 Incident Investigation Report. |

---

## 9. System Health, Real-Time Polling, Search & Simulation (`/api/system`, `/ws`)

| Method | Endpoint | Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` & `/api/system/health` | Public | Returns live PostgreSQL connectivity (`SELECT 1`, version string), detection engine status, WebSocket connection count, table counters, and rate-limiter statistics. |
| `GET` | `/api/search?q={query}` | Public / SOC | Global search across `alerts`, `events`, `incidents`, `rules`, and `indicators`. |
| `WS` | `/ws` & `/api/ws` | Public / JWT (`?token=`) | Real-time WebSocket stream pushing `connection_established`, `event_ingested`, `bulk_events_ingested`, `alert_created`, `alert_status_updated`, `incident_created`, `incident_updated`, and `dashboard_metrics_updated`. |
| `GET` | `/api/system/realtime/poll?since_seq={n}` | Public / SOC | HTTP polling fallback returning sequence-numbered messages after `since_seq` and live dashboard KPIs. |
| `GET` | `/api/system/audit-logs` | Public / SOC | Queries PostgreSQL `audit_logs` with filters (`search`, `actor_username`, `action`, `resource_type`, `status`, `page`, `limit`). |
| `GET` | `/api/system/scenarios` | Public / SOC | Lists all 9 synthetic telemetry scenarios (`normal_login`, `normal_network`, and 7 attack scenarios). |
| `POST` | `/api/system/simulate` | Public / SOC | Generates and ingests synthetic telemetry for a specific `scenario_id` (or `"all"`) with configurable `volume_multiplier`. |
| `POST` | `/api/system/reset-demo` | Public / SOC | Resets synthetic demo data and re-seeds clean baseline telemetry, alerts, and sample incident. |

