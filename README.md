# ThreatLens — Intelligent Security Operations & Threat Detection Platform

**ThreatLens** is a full-stack, modular Security Information and Event Management (SIEM) and Security Operations Center (SOC) platform built with **React + TypeScript + Vite + Tailwind CSS + Recharts** on the frontend and **Python + FastAPI + SQLAlchemy + Alembic + PostgreSQL + WebSockets** on the backend.

It provides end-to-end security telemetry ingestion, normalized storage, a 7-rule MITRE ATT&CK-mapped correlation engine, real-time WebSocket alerting (with automatic polling fallback), alert triage, multi-alert incident investigation workflows, evidence-based threat intelligence lookup, ground-truth detection efficacy analytics (TP/FP/TN/FN, Precision, Recall, F1 Score), and CSV/PDF reporting.

---

## 1. Key Capabilities

1. **SOC Overview Dashboard (`/`)**
   - Live KPIs queried directly from PostgreSQL: Total Security Events, Total Alerts, Critical Alerts, High-Severity Alerts, Active Incidents, and Resolved Incidents.
   - Interactive Recharts visualizations: Security Events Over Time, Alerts Grouped by Severity, Event Distribution by Category, Top Source IPs (with IOC badges), Authentication Failure Trends, and Recent Incidents.
   - Live Detection Activity Timeline, System Health Diagnostics, and Event Ingestion Statistics.

2. **Security Event Ingestion Engine (`/api/events`, `/api/events/bulk`)**
   - Supports `Authentication`, `Authorization`, `Network`, `Endpoint`, `System`, and `Application` categories.
   - Validates IPv4/IPv6 addresses, normalizes timestamps to UTC, preserves raw log evidence (`raw_log`) and structured JSON `metadata`, and handles malformed events in bulk batches safely without dropping valid telemetry.

3. **Python Rule-Based Threat Detection Engine (`backend/app/detection/engine.py`)**
   - **RULE-001 (`brute_force`)**: Repeated failed logins grouped by `(source_ip, username)` within a configurable time window (`MITRE T1110.001`).
   - **RULE-002 (`password_spraying`)**: Horizontal failed authentication attempts across multiple distinct usernames from a single `source_ip` with low per-user attempt count (`MITRE T1110.003`).
   - **RULE-003 (`login_after_failures`)**: Successful authentication following repeated preceding failures for the same `(source_ip, username)` (`MITRE T1078`).
   - **RULE-004 (`unusual_login`)**: Logins from external/non-RFC1918 networks during off-hours or with explicit anomaly telemetry (`MITRE T1078.004`) — strictly factual based on supplied telemetry without fabricated geolocation claims.
   - **RULE-005 (`privilege_escalation`)**: Unauthorized privilege elevation, `sudo_abuse`, `setuid` execution, or administrative group modifications (`MITRE T1548`).
   - **RULE-006 (`port_scanning`)**: Single source IP probing multiple distinct destination ports within a reconnaissance window (`MITRE T1046`).
   - **RULE-007 (`suspicious_network`)**: Outbound connections to known C2 ports (`4444`, `1337`, `6667`, `9001`, `31337`), high-volume data exfiltration (`bytes_out >= threshold`), or active IOC destinations (`MITRE T1071`).
   - Includes in-window deduplication (`dedup_key`), automatic `AlertEvidence` linking, and initial `AlertStatusHistory` auditing.

4. **Alerts Management (`/alerts`) & Incident Investigation (`/incidents`)**
   - Full lifecycle transitions (`New`, `Acknowledged`, `Investigating`, `Resolved`, `False Positive`) persisted in PostgreSQL with full `alert_status_history`.
   - Analyst investigation notes, triggering event evidence traceability, and one-click escalation from alerts into multi-alert `Incidents` (`Open`, `Investigating`, `Contained`, `Resolved`, `Closed`).
   - Per-incident forensic report exports in **JSON** (`/api/reports/incidents/{id}`), **CSV** (`/api/reports/incidents/{id}/csv`), and **PDF** (`/api/reports/incidents/{id}/pdf`).

5. **Real-Time Monitoring (`/ws`, `/api/ws`, `/api/system/realtime/poll`)**
   - FastAPI WebSockets streaming live event ingestion (`event_ingested`, `bulk_events_ingested`), live alert notifications (`alert_created`, `alert_status_updated`), incident updates (`incident_created`, `incident_updated`), and live dashboard KPI snapshots (`dashboard_metrics_updated`).
   - Sequence-numbered ring buffer with automatic HTTP polling fallback (`/api/system/realtime/poll?since_seq=...`) and connection status indicators (`websocket_live`, `polling_fallback`, `connecting`).

6. **Threat Intelligence (`/threat-intelligence`)**
   - IP reputation lookup (`/api/threat-intelligence/lookup`), local PostgreSQL Indicator of Compromise (`threat_indicators`) CRUD management, and Suspicious IP tracking (`/api/threat-intelligence/suspicious-ips`) correlating local IOCs, triggered alerts, and repeated authentication failures.
   - Pluggable provider abstraction (`ExternalThreatIntelProvider`) supporting **AbuseIPDB API v2**, **VirusTotal API v3**, and **AlienVault OTX API v1**. Never fabricates reputation scores when external API keys are not configured (`status: "not_configured"`, `data: null`).

7. **Analytics, Confusion Matrix & Reporting (`/analytics`)**
   - Alerts by severity, detection rule frequency, event & authentication trends, and incident resolution statistics (`resolution_rate`, `mean_time_to_resolve_minutes`).
   - Calculates **True Positives (TP)**, **False Positives (FP)**, **True Negatives (TN)**, **False Negatives (FN)**, **Precision**, **Recall**, **F1 Score**, **Accuracy**, and **False Positive Rate** over ground-truth labeled telemetry without fabrication (`/api/analytics/performance`, `/api/analytics/detection-accuracy`).
   - Exports executive & technical reports in **CSV** (`/api/reports/export/csv`) and **PDF** (`/api/reports/export/pdf`) formats, plus dedicated **Incident Investigation Reports** (`/api/reports/incidents/{id}/csv`, `/api/reports/incidents/{id}/pdf`).

8. **Security & Governance (`/configuration`)**
   - Role-Based Access Control (`admin`, `soc_lead`, `analyst`, `viewer`) with automatic `rbac_access_denied` audit logging.
   - Hardened JWT verification (`/api/auth/verify`) enforcing `sub`, `exp`, `iat`, and `type` claims.
   - Sliding-window API rate limiting (`Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining` headers) across authentication, ingestion, threat intelligence lookups, and report exports.
   - Comprehensive PostgreSQL audit logs (`/api/system/audit-logs`) and strict Pydantic input validation.

---

## 2. External Threat Intelligence API Credentials (Optional)

ThreatLens works out-of-the-box using its PostgreSQL Indicator of Compromise (`threat_indicators`) database and live SIEM event/alert correlation. When external provider keys are not configured, ThreatLens explicitly reports `status: "not_configured"` and **never fabricates external threat scores**.

To enable live external enrichment, provide any of the following optional credentials via `.env` or runtime configuration (`PUT /api/threat-intelligence/providers`):

| Provider | Environment Variable | Upstream Endpoint | Credential Source |
| :--- | :--- | :--- | :--- |
| **AbuseIPDB API v2** | `ABUSEIPDB_API_KEY` | `https://api.abuseipdb.com/api/v2/check` | https://www.abuseipdb.com/account/api |
| **VirusTotal API v3** | `VIRUSTOTAL_API_KEY` | `https://www.virustotal.com/api/v3/ip_addresses/{ip}` | https://www.virustotal.com/gui/my-apikey |
| **AlienVault OTX v1** | `OTX_API_KEY` | `https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general` | https://otx.alienvault.com/api |

---

## 3. Project Structure

```text
ThreatLens/
├── frontend/
│   ├── src/
│   │   ├── components/         # Shared SOC badges and UI primitives
│   │   ├── pages/              # 9 full-featured SOC operational pages
│   │   ├── layouts/            # Persistent sidebar, topbar, global search, notifications
│   │   ├── hooks/              # WebSocket real-time stream + polling fallback hook
│   │   ├── services/           # Typed REST API client
│   │   ├── types/              # TypeScript interfaces
│   │   └── utils/              # UTC formatters and severity helpers
│   ├── nginx.conf              # Production reverse proxy for /api and /ws
│   └── Dockerfile
│
├── backend/
│   ├── app/
│   │   ├── api/                # FastAPI routers (/auth, /events, /alerts, /detections, etc.)
│   │   ├── core/               # Config, JWT/bcrypt security, DB engine, WebSockets, rate limiter
│   │   ├── models/             # 11 normalized SQLAlchemy tables
│   │   ├── schemas/            # Pydantic v2 validation & serialization schemas
│   │   ├── services/           # Seeding, audit logging, analytics, CSV/PDF report builders
│   │   ├── detection/          # 7-rule Python correlation engine & MITRE mappings
│   │   ├── ingestion/          # Single & bulk event ingestion pipeline
│   │   ├── intelligence/       # IOC lookup & external provider abstraction
│   │   └── main.py             # FastAPI application entrypoint
│   ├── tests/                  # Automated Pytest suite verifying all 7 rules & APIs
│   ├── alembic/                # Alembic database migrations (0001_initial_schema.py)
│   └── Dockerfile
│
├── telemetry/
│   ├── generators/             # Synthetic event factory with ground-truth labels
│   ├── scenarios/              # 9 reproducible attack & benign baseline scenarios
│   └── cli.py                  # Command-line synthetic traffic generator
│
├── docker-compose.yml
├── .env.example
├── README.md
├── ARCHITECTURE.md
├── API_DOCUMENTATION.md
├── DATABASE_SCHEMA.md
├── DETECTION_RULES.md
├── INSTALLATION_GUIDE.md
└── TESTING_REPORT.md
```

### Documentation Index
- [System & Security Architecture (`ARCHITECTURE.md`)](./ARCHITECTURE.md)
- [REST & WebSocket API Reference (`API_DOCUMENTATION.md`)](./API_DOCUMENTATION.md)
- [PostgreSQL Database Schema & Migrations (`DATABASE_SCHEMA.md`)](./DATABASE_SCHEMA.md)
- [Detection Rules & MITRE ATT&CK Catalog (`DETECTION_RULES.md`)](./DETECTION_RULES.md)
- [Installation & Deployment Guide (`INSTALLATION_GUIDE.md`)](./INSTALLATION_GUIDE.md)
- [Technical Audit & Testing Report (`TESTING_REPORT.md`)](./TESTING_REPORT.md)

---

## 3. Running with Docker Compose (Recommended)

1. Copy the environment configuration template:
   ```bash
   cp .env.example .env
   ```
2. Build and launch PostgreSQL, the FastAPI backend (which automatically runs `alembic upgrade head` and seeds initial rules/users/telemetry), and the Nginx/React frontend:
   ```bash
   docker compose up --build
   ```
3. Access the platform:
   - **Frontend SOC Console**: http://localhost:3000 (or http://localhost:80)
   - **Backend OpenAPI / Swagger Docs**: http://localhost:8000/docs
   - **Health Diagnostics**: http://localhost:8000/api/system/health

---

## 4. Running Locally (Development Mode)

### Backend Setup
```bash
cd backend
python -m pip install -r requirements.txt

# Run Alembic database migrations
python -m alembic upgrade head

# Launch FastAPI server with hot reload on port 8000
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173 in your browser. Vite proxies `/api` and `/ws` directly to `http://127.0.0.1:8000`.

### Default Seeded SOC Operator Credentials
| Username | Password | Role |
| :--- | :--- | :--- |
| `admin` | `ThreatLens!Admin2026` | `admin` (SOC Director) |
| `analyst` | `ThreatLens!Analyst2026` | `analyst` (Senior SOC Analyst) |
| `ir.lead` | `ThreatLens!Lead2026` | `soc_lead` (Incident Response Lead) |

---

## 5. Synthetic Telemetry Generator & Automated Testing

### Trigger Synthetic Scenarios via CLI
```bash
# Run all 9 scenarios (benign + 7 attack scenarios) against the running backend
python -m telemetry.cli --scenario all

# Run a specific scenario with 2x event volume
python -m telemetry.cli --scenario brute_force --volume 2

# Dry-run output to inspect raw synthetic event JSON
python -m telemetry.cli --scenario port_scanning --dry-run
```

### Run Automated Tests
```bash
# Backend Pytest suite (Auth, RBAC, Ingestion, all 7 Detection Rules, Incidents, Analytics, Exports)
cd backend
python -m pytest -v

# Frontend Vitest suite (Components, Loading/Error states, Dashboard API integration)
cd ../frontend
npm test
```

