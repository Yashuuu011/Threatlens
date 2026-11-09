# ThreatLens — Complete Installation & Deployment Guide

## 1. Prerequisites
- **Docker & Docker Compose** (Docker Engine 24+ / Docker Desktop) for containerized deployment, OR:
- **Local Development Stack**:
  - **Python** 3.11+ (tested on Python 3.12 / 3.14)
  - **PostgreSQL** 15+ (tested on PostgreSQL 16 / 18)
  - **Node.js** 20+ & **npm** 10+

---

## 2. Option A: Docker Compose Deployment (Recommended)

1. **Create Environment File**:
   ```bash
   cp .env.example .env
   ```
   *(Optional)* Add external Threat Intelligence API keys (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`) to `.env`. If left blank, ThreatLens uses its built-in PostgreSQL IOC repository without fabricating external scores.

2. **Build and Start All Services**:
   ```bash
   docker compose up --build -d
   ```

3. **Verify Container Status & Healthchecks**:
   ```bash
   docker compose ps
   curl http://localhost:8000/api/health
   ```

4. **Access ThreatLens**:
   - **Frontend SOC Console**: `http://localhost:3000` (or `http://localhost:80`)
   - **Backend OpenAPI / Swagger UI**: `http://localhost:8000/docs`
   - **ReDoc API Reference**: `http://localhost:8000/redoc`

5. **Verify Persistence Across Container Restart**:
   ```bash
   docker compose restart backend postgres
   curl http://localhost:8000/api/health
   ```
   PostgreSQL data is persisted in the named Docker volume `threatlens_pgdata`.

---

## 3. Option B: Local Development Setup

### Step 1: PostgreSQL Database Preparation
Ensure PostgreSQL is running on `localhost:5432` and create the database/user matching `.env`:
```sql
CREATE USER threatlens WITH PASSWORD 'threatlens_secure_pwd';
CREATE DATABASE threatlens_db OWNER threatlens;
GRANT ALL PRIVILEGES ON DATABASE threatlens_db TO threatlens;
```

### Step 2: Backend Setup & Database Migrations
```bash
cd backend
python -m pip install -r requirements.txt

# Apply Alembic schema migrations to PostgreSQL
python -m alembic upgrade head

# Start FastAPI server (automatically seeds initial rules, users, IOCs, and baseline telemetry)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Frontend Setup
```bash
cd frontend
npm install

# Start Vite development server (proxies /api and /ws to http://127.0.0.1:8000)
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 4. Default SOC Operator Accounts

| Username | Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| `admin` | `ThreatLens!Admin2026` | `admin` | Full administrative access (user creation, rule deletion, provider config, triage, incidents, exports) |
| `ir.lead` | `ThreatLens!Lead2026` | `soc_lead` | Incident response lead (provider config, rule tuning, alert triage, incident lifecycle, IOC management) |
| `analyst` | `ThreatLens!Analyst2026` | `analyst` | SOC analyst (rule tuning, alert triage, incident creation & investigation, IOC management, exports) |

---

## 5. Running Synthetic Telemetry & Automated Tests

```bash
# Run backend Pytest suite (20 automated tests against isolated PostgreSQL test database)
python -m pytest backend/tests/test_threatlens.py -v

# Run frontend Vitest test suite (9 component & integration tests)
npm --prefix frontend test -- --run

# Run frontend production build check
npm --prefix frontend run build
```

