# ThreatLens — PostgreSQL Database Schema & Migration Reference

## 1. Entity-Relationship Diagram (11 Normalized Tables)

```mermaid
erDiagram
    USERS {
        int id PK
        string username UK
        string email UK
        string full_name
        string hashed_password
        string role
        boolean is_active
        datetime last_login
        datetime created_at
        datetime updated_at
    }

    SECURITY_EVENTS {
        int id PK
        string event_id UK
        datetime timestamp
        string source_ip
        string destination_ip
        int destination_port
        string username
        string hostname
        string event_type
        string event_category
        string action
        string status
        string severity
        text raw_log
        json metadata
        boolean is_synthetic
        datetime created_at
        datetime updated_at
    }

    DETECTION_RULES {
        int id PK
        string rule_id UK
        string rule_key UK
        string name UK
        text description
        text detection_logic
        string event_category
        int threshold_count
        int time_window_seconds
        json parameters
        string severity
        boolean enabled
        string mitre_tactic
        string mitre_technique_id
        string mitre_technique_name
        datetime created_at
        datetime updated_at
    }

    ALERTS {
        int id PK
        string alert_id UK
        string title
        text description
        string severity
        string status
        int rule_id_fk FK
        string rule_code
        string rule_name
        string source_ip
        string username
        string hostname
        datetime first_seen
        datetime last_seen
        int event_count
        string dedup_key
        string mitre_tactic
        string mitre_technique_id
        string mitre_technique_name
        json evidence_summary
        string assigned_to
        boolean is_synthetic
        datetime created_at
        datetime updated_at
    }

    ALERT_EVIDENCE {
        int id PK
        int alert_id FK
        int event_id FK
        string evidence_role
        string note
        datetime created_at
        datetime updated_at
    }

    ALERT_STATUS_HISTORY {
        int id PK
        int alert_id FK
        string previous_status
        string new_status
        string changed_by
        text comment
        datetime created_at
        datetime updated_at
    }

    INCIDENTS {
        int id PK
        string incident_id UK
        string title
        string severity
        string status
        text description
        string assigned_analyst
        json timeline_events
        json evidence_references
        text resolution_summary
        datetime resolved_at
        string created_by
        datetime created_at
        datetime updated_at
    }

    INCIDENT_ALERTS {
        int id PK
        int incident_id FK
        int alert_id FK
        string linked_by
        datetime created_at
        datetime updated_at
    }

    INVESTIGATION_NOTES {
        int id PK
        int alert_id FK
        int incident_id FK
        string author
        text content
        string note_type
        datetime created_at
        datetime updated_at
    }

    THREAT_INDICATORS {
        int id PK
        string indicator_type
        string indicator_value UK
        string threat_type
        string severity
        int confidence
        string source
        text description
        json tags
        boolean is_active
        datetime first_seen
        datetime last_seen
        int hit_count
        datetime created_at
        datetime updated_at
    }

    AUDIT_LOGS {
        int id PK
        string actor_username
        string actor_role
        string action
        string resource_type
        string resource_id
        string ip_address
        string status
        json details
        datetime created_at
        datetime updated_at
    }

    DETECTION_RULES ||--o{ ALERTS : "triggers (rule_id_fk)"
    ALERTS ||--o{ ALERT_EVIDENCE : "links (ON DELETE CASCADE)"
    SECURITY_EVENTS ||--o{ ALERT_EVIDENCE : "referenced by (ON DELETE CASCADE)"
    ALERTS ||--o{ ALERT_STATUS_HISTORY : "tracks (ON DELETE CASCADE)"
    ALERTS ||--o{ INVESTIGATION_NOTES : "has notes (ON DELETE CASCADE)"
    INCIDENTS ||--o{ INCIDENT_ALERTS : "associates (ON DELETE CASCADE)"
    ALERTS ||--o{ INCIDENT_ALERTS : "linked to (ON DELETE CASCADE)"
    INCIDENTS ||--o{ INVESTIGATION_NOTES : "has notes (ON DELETE CASCADE)"
```

---

## 2. Foreign Keys & Referential Integrity Constraints

| Child Table | Column | Parent Table | `ON DELETE` Policy | Uniqueness Constraint |
| :--- | :--- | :--- | :--- | :--- |
| `alerts` | `rule_id_fk` | `detection_rules.id` | `SET NULL` | `ix_alerts_alert_id` (Unique) |
| `alert_evidence` | `alert_id` | `alerts.id` | `CASCADE` | `uq_alert_evidence_pair (alert_id, event_id)` |
| `alert_evidence` | `event_id` | `security_events.id` | `CASCADE` | `uq_alert_evidence_pair (alert_id, event_id)` |
| `alert_status_history` | `alert_id` | `alerts.id` | `CASCADE` | — |
| `incident_alerts` | `incident_id` | `incidents.id` | `CASCADE` | `uq_incident_alert_pair (incident_id, alert_id)` |
| `incident_alerts` | `alert_id` | `alerts.id` | `CASCADE` | `uq_incident_alert_pair (incident_id, alert_id)` |
| `investigation_notes` | `alert_id` | `alerts.id` | `CASCADE` | — |
| `investigation_notes` | `incident_id` | `incidents.id` | `CASCADE` | — |

---

## 3. Database Indexes (`0001_initial_schema.py`)

| Table | Index Name | Indexed Columns | Purpose |
| :--- | :--- | :--- | :--- |
| `users` | `ix_users_username` (Unique) | `(username)` | Fast authentication lookup |
| `users` | `ix_users_email` (Unique) | `(email)` | Operator email uniqueness |
| `users` | `ix_users_role` | `(role)` | Role filtering |
| `security_events` | `ix_security_events_event_id` (Unique) | `(event_id)` | Idempotent event lookup |
| `security_events` | `ix_security_events_timestamp` | `(timestamp)` | Time-series sorting & windowing |
| `security_events` | `ix_security_events_source_ip` | `(source_ip)` | IP correlation & explorer filtering |
| `security_events` | `ix_security_events_cat_ts` | `(event_category, timestamp)` | Category time-window queries |
| `security_events` | `ix_security_events_src_user_ts` | `(source_ip, username, timestamp)` | Brute-force & login-after-failure correlation |
| `detection_rules` | `ix_detection_rules_rule_id` (Unique) | `(rule_id)` | Rule lookup by code (`RULE-001`..`RULE-007`) |
| `detection_rules` | `ix_detection_rules_rule_key` (Unique) | `(rule_key)` | Engine evaluator binding |
| `alerts` | `ix_alerts_alert_id` (Unique) | `(alert_id)` | Alert code lookup |
| `alerts` | `ix_alerts_status_sev` | `(status, severity)` | SOC queue triage filtering |
| `alerts` | `ix_alerts_rule_dedup` | `(rule_code, dedup_key)` | In-window deduplication lookup |
| `alert_evidence` | `ix_alert_evidence_alert_id` | `(alert_id)` | Alert evidence retrieval |
| `alert_evidence` | `ix_alert_evidence_event_id` | `(event_id)` | Reverse event-to-alert lookup |
| `alert_status_history` | `ix_alert_status_history_alert_id` | `(alert_id)` | Alert audit timeline query |
| `incidents` | `ix_incidents_incident_id` (Unique) | `(incident_id)` | Incident code lookup |
| `threat_indicators` | `ix_threat_indicators_indicator_value` (Unique) | `(indicator_value)` | Real-time IOC matching during ingestion & lookup |

---

## 4. Alembic Migration Commands

```bash
cd backend

# Check current migration revision applied to PostgreSQL
python -m alembic current

# Apply all migrations up to head
python -m alembic upgrade head

# Roll back one migration revision (development/testing only)
python -m alembic downgrade -1
```

