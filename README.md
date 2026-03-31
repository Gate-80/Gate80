# GATE80: Adaptive API Deception Prototype – Digital Wallet API

## Overview
This repository contains **GATE80**, a cloud-based adaptive deception system for API endpoints.

GATE80 aims to enhance API security by intercepting API traffic, analyzing request behavior, and dynamically engaging suspicious activity using realistic decoy APIs, while allowing legitimate traffic to reach real backend services.

At a high level, the system:
- Intercepts incoming API traffic using a reverse proxy
- Analyzes request behavior using machine learning (Isolation Forest)
- Dynamically decides whether traffic is legitimate or suspicious
- Forwards legitimate traffic to real backend services
- Redirects suspicious traffic to realistic digital-twin API decoys
- Mirrors attacker sessions seamlessly so deception is undetectable
- Collects logs and attacker interaction data for analysis and correlation

This project is developed for **academic and research purposes**.

---

## System Components
The GATE80 system consists of the following components:

- **Customer Backend APIs** – Realistic backend services protected by GATE80
- **Reverse Proxy Layer** – Intercepts and controls all incoming API traffic
- **Anomaly Detection Engine** – Isolation Forest model scoring sessions in real time
- **Digital-Twin API Decoys** – Stateful APIs that replicate real endpoint behavior
- **Threat Intelligence Integration** – Enriches traffic analysis using known threat data
- **Adaptive Decision Engine** – Determines how each request is handled
- **Monitoring & Dashboard** – ELK Stack (Elasticsearch, Logstash, Kibana)

---

## Customer Backend APIs

### Digital Wallet API
A **Digital Wallet backend system** is implemented as a representative customer API.
It simulates common functionality found in fintech and financial applications.

### Available Endpoints

#### User Accounts
- View user profile
- Update user profile
- Add bank account
- View bank accounts
- Update bank account

#### Wallet Operations
- View wallet balance
- Transfer funds to another user
- Transfer funds to bank account
- Top up wallet balance
- Withdraw funds
- Pay bills

#### Payments/Transactions
- View user payments
- View payment details

#### Admin Operations
- View all registered users
- View all wallets
- View all transactions
- View system financial overview

#### User Authentication
- User sign up
- User sign in
- User sign out

#### Admin Authentication
- Admin sign in
- Admin sign out

---

## API Reference

Interactive API documentation is available through **Swagger UI** once the backend server is running.

![Swagger – User Accounts](docs/images/swagger-users.png)


---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI (Python) |
| API Style | REST |
| Documentation | OpenAPI / Swagger |
| Server | Uvicorn |
| Database | SQLite + SQLAlchemy ORM |
| Proxy | FastAPI Reverse Proxy (httpx) |
| Anomaly Detection | Isolation Forest (scikit-learn) |
| DB Migrations | Alembic |
| Monitoring | ELK Stack (Elasticsearch, Logstash, Kibana) |

---

## Architecture

```
User / Client
     │
     ▼
┌────────────────────────────────────────────────┐
│   Reverse Proxy (:8080)                        │  ← All traffic enters here
│   - Session tracking (token or IP)             │
│   - Behavioral feature extraction              │
│   - Isolation Forest anomaly scoring           │
│   - Adaptive routing decision                  │
│   - Token mirroring on flag                    │
│   - Logs to proxy_logs.db                      │
└──────────┬──────────────────┬──────────────────┘
           │ normal           │ anomalous
           ▼                  ▼
┌──────────────────┐  ┌──────────────────────────┐
│ Backend API      │  │ Decoy API (:8001)         │
│ (:8000)          │  │ - Stateful fake wallet    │
│ - Real data      │  │ - Realistic responses     │
│ - digital_       │  │ - Captures attacker       │
│   wallet.db      │  │   behavior                │
└──────────────────┘  │ - decoy_wallet.db         │
                      └──────────────────────────┘
                               │
                    ┌──────────────────────┐
                    │    proxy_logs.db      │
                    │  ┌────────────────┐  │
                    │  │ proxy_requests │  │ ← routing decisions
                    │  ├────────────────┤  │
                    │  │ decoy_requests │  │ ← attacker behavior
                    │  └────────────────┘  │
                    │  correlate by        │
                    │  session_id          │
                    └──────────────────────┘
```

**Security Model:**
- The backend is completely isolated — direct access returns `403 Forbidden`
- All requests must pass through the proxy (`X-From-Proxy: 1` header)
- Only the `/health` endpoint is accessible directly on the backend
- All state-changing operations are logged to the audit table
- Flagged sessions are silently redirected — attacker cannot detect the deception

---

## Repository Structure

```
GATE80/
│
├── backend_api/                   # Customer backend API
│   ├── main.py
│   ├── db/
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── audit_helper.py
│   │   └── seed_data.py
│   └── routers/
│       ├── user_authentication.py
│       ├── admin_authentication.py
│       ├── user_accounts.py
│       ├── wallet.py
│       └── admin_operations.py
│
├── proxy/                         # Reverse proxy + anomaly routing
│   ├── main.py                    # Proxy, detection integration, token mirroring
│   ├── db/
│   │   ├── database.py
│   │   ├── models.py
│   │   └── logger.py
│   └── __init__.py
│
├── detection/                     # Anomaly detection engine
│   ├── __init__.py
│   └── model.py                   # AnomalyDetector, SessionState, 15 features
│
├── decoy_api/                     # Digital-twin decoy API
│   ├── main.py
│   ├── seed.py
│   ├── logger.py
│   ├── db/
│   │   ├── database.py
│   │   ├── models.py
│   │   └── log_models.py
│   └── routers/
│       ├── auth.py
│       ├── admin_auth.py
│       ├── wallet.py
│       ├── user_accounts.py
│       └── admin.py
│
├── dataset/                       # Traffic generation and feature engineering
│   ├── generate_normal_traffic.py
│   ├── generate_mixed_traffic.py
│   ├── build_session.py
│   ├── feature_engineering.py
│   ├── abnormal/
│   │   ├── build_Abnormal_sessions.py
│   │   ├── feature_engineering_abnormal.py
│   │   └── output/
│   └── output/
│       ├── traffic_log.csv
│       ├── mixed_traffic_log.csv
│       ├── sessions_features.csv
│       └── baseline_sessions.csv
│
├── model/                         # Trained ML model
│   ├── isolation.py               # Training script
│   ├── testModel.py
│   ├── checkdataset.py
│   ├── isolation_forest.pkl       # Trained model
│   └── scaler.pkl                 # Fitted StandardScaler
│
├── alembic/                       # DB migration management
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       ├── 001_initial_schema.py
│       └── 002_add_detection_columns.py
│
├── logstash/                      # ELK Stack pipeline
│   └── pipeline.conf
│
├── logs/                          # Application logs
├── docs/                          # Documentation
├── alembic.ini
├── digital_wallet.db              # Backend database (auto-created)
├── proxy_logs.db                  # Unified log database (auto-created)
├── decoy_wallet.db                # Decoy wallet state (auto-created)
└── requirements.txt
```

---

## Setup & Installation

### Prerequisites
- **Python 3.14+** (required — model pkl files are version-specific)
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/WedAbdullh/GATE80_adaptive-api-deception.git
cd GATE80_adaptive-api-deception
```

### 2. Create and Activate Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
.venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Seed the Backend Database

```bash
python -m backend_api.db.seed_data
```

Expected output:
```
Creating database tables...
Seeding database with test data...
✓ Created 3 users
✓ Created 3 bank accounts
✓ Created 3 wallets
✓ Created 3 transactions
✓ Created 3 payments
✓ Created admin account
✅ Database seeded successfully!
```

### 5. Regenerate the ML Model

> The model pkl files are Python version-specific. Always regenerate after cloning.

```bash
python model/isolation.py
```

### 6. Run Database Migrations

```bash
alembic stamp 001
alembic upgrade head
```

---

## Running the System

The system requires **three terminals** running simultaneously.

### Terminal 1 — Backend API
```bash
uvicorn backend_api.main:app --reload --port 8000
```
Expected:
```
✅ Database initialized
INFO: Application startup complete.
```

### Terminal 2 — Decoy API
```bash
uvicorn decoy_api.main:app --reload --port 8001
```
Expected:
```
GATE80 🪤 Decoy databases initialised
GATE80 ✅ Seeded: 3 users, 3 wallets, 5 transactions...
GATE80 🪤 Decoy API ready on :8001
```

### Terminal 3 — Proxy
```bash
uvicorn proxy.main:app --reload --port 8080
```
Expected:
```
✅ Proxy database initialised
GATE80 ✅ detector ready — 200 estimators, contamination=0.08
GATE80 ✅ thresholds — min_requests=3, score_threshold=-0.013
✅ Backend DB connected for token mirroring
✅ Decoy DB connected for token mirroring
INFO: Application startup complete.
```

> ⚠️ **All API access must go through the proxy on port 8080.**
> Direct backend access on port 8000 will return `403 Forbidden`.

---

## Test Credentials

| Role | Credential | Value |
|------|-----------|-------|
| User | Email | `user@example.com` |
| User | Password | `password123` |
| Admin | Username | `admin` |
| Admin | Password | `admin123` |

### Test Flow

1. **Login** → `POST /api/v1/auth/sign-in` or `POST /api/v1/admin/auth/sign-in`
2. **Copy the token** from the response
3. **Use token** in the `X-User-Token` or `X-Admin-Token` header for protected endpoints
4. **Test wallet operations**, admin views, etc.

---

## Anomaly Detection Engine

The proxy integrates a trained **Isolation Forest** model that scores every session in real time based on 15 behavioral features.

### Detection Thresholds

| Threshold | Value | Justification |
|-----------|-------|---------------|
| `MIN_REQUESTS_BEFORE_SCORING` | 3 | Training data minimum — scoring below this has no comparable data |
| `ANOMALY_SCORE_THRESHOLD` | -0.013 | mean(0.077) − 2×std(0.045) — covers 95% of legitimate sessions |

### Session Identity Priority
1. `X-User-Token` header → `user:<token>`
2. `X-Admin-Token` header → `admin:<token>`
3. Client IP fallback → `ip:<address>`

### Routing Logic
- **Normal session** → forwarded to real backend (:8000)
- **Flagged session** → silently redirected to decoy (:8001)
- **Sticky flag** → once flagged, all future requests go to decoy permanently

### Token Mirroring
When a session is flagged, the proxy copies the attacker's real session token into `decoy_wallet.db` so the decoy recognizes it seamlessly — the attacker notices no disruption.

---

## Decoy API

The decoy is a stateful FastAPI application that mirrors the real backend.

### Key Design Decisions
- **Stateful** — `decoy_wallet.db` maintains real balance state across requests
- **Realistic auth** — only accepts valid credentials, rejects invalid ones with identical error messages
- **No X-From-Proxy validation** — captures all traffic including direct hits
- **Full logging** — every attacker interaction logged to `proxy_logs.db`

### Seeded Data
On startup, the decoy is pre-populated with believable data:
- 3 users with realistic Saudi names and cities
- 3 wallets with realistic SAR balances
- 5 past transactions (topups, transfers, bill payments)
- 3 bank accounts linked to Saudi banks
- 3 payment records

---

## Database Architecture

The system uses **SQLite** as its database engine, managed via **SQLAlchemy ORM**. There are three separate database files, each with a distinct purpose:

| Database | Purpose |
|----------|---------|
| `digital_wallet.db` | Real backend customer data (users, wallets, transactions, audit logs) |
| `decoy_wallet.db` | Decoy fake wallet state (mirrors real backend schema with fake data) |
| `proxy_logs.db` | Unified log database (proxy routing decisions + decoy attacker interactions) |

### Unified Log Database

`proxy_logs.db` contains two tables that can be correlated by `session_id` to reconstruct a full attack timeline:

```
proxy_logs.db
  ├── proxy_requests    ← routing decisions, anomaly scores, session tracking
  └── decoy_requests    ← attacker behavior inside the decoy
```

Both `proxy_requests` and `decoy_requests` share `session_id` for full attack timeline correlation:

```sql
SELECT p.session_id, p.anomaly_score, p.routed_to, d.path, d.response_status
FROM proxy_requests p
JOIN decoy_requests d ON p.session_id = d.session_id
WHERE p.routed_to = 'decoy';
```

### proxy_logs.db — proxy_requests Schema

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | String | Unique UUID per request |
| `timestamp` | DateTime | When request was received |
| `client_ip` | String | Client IP (supports X-Forwarded-For) |
| `session_id` | String | Session identity (token or IP) |
| `method` | String | HTTP method |
| `path` | String | Request URL path |
| `headers` | JSON | Request headers (tokens redacted) |
| `body` | Text | Request body (max 10KB) |
| `response_status` | Integer | HTTP response status code |
| `response_time_ms` | Integer | Response time in milliseconds |
| `anomaly_score` | Float | Raw Isolation Forest score |
| `routed_to` | String | `backend` / `decoy` / `error` |
| `flagged_as_suspicious` | Boolean | Whether session was flagged |

### proxy_logs.db — decoy_requests Schema

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | String | Unique UUID per request |
| `session_id` | String | Matches proxy_requests.session_id |
| `method` | String | HTTP method |
| `path` | String | Endpoint the attacker hit |
| `body` | Text | Attacker's payload |
| `response_status` | Integer | What the decoy returned |
| `response_body` | Text | Decoy's response |
| `response_time_ms` | Integer | Response time |

---

## Dataset Pipeline

Used to generate training data for the Isolation Forest model.

### Normal Traffic (for model training)
```bash
python dataset/generate_normal_traffic.py   # generates dataset/output/traffic_log.csv
python dataset/feature_engineering.py       # generates dataset/output/baseline_sessions.csv
python model/isolation.py                   # trains and saves model/isolation_forest.pkl
```

### Abnormal Traffic (for model testing)
```bash
python dataset/generate_mixed_traffic.py    # generates dataset/output/mixed_traffic_log.csv
python dataset/abnormal/build_Abnormal_sessions.py
python dataset/abnormal/feature_engineering_abnormal.py
```

---

## DB Migration Management

The project uses **Alembic** for schema version management.

```bash
# Apply all pending migrations
alembic upgrade head

# Roll back one migration
alembic downgrade -1

# Generate a new migration after changing models.py
alembic revision --autogenerate -m "describe your change"
```

---

## Elastic Stack Monitoring Setup

The GATE80 system uses the **Elastic Stack** to monitor and visualize API traffic and attacker behavior.

### Components

| Component | Purpose |
|----------|---------|
| Elasticsearch | Stores and indexes logs |
| Logstash | Extracts from proxy_logs.db and indexes into Elasticsearch |
| Kibana | Visualizes traffic, anomaly scores, and decoy interactions |

### Prerequisites

- Java 11+ (required by Elasticsearch and Logstash)
- At least 4GB RAM available

### Install

**macOS (Homebrew)**
```bash
brew tap elastic/tap
brew install elastic/tap/elasticsearch-full
brew install elastic/tap/logstash-full
brew install elastic/tap/kibana-full
```

**Linux (apt)**
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install elasticsearch logstash kibana
```

**Windows / All Platforms**

Download directly from the official site:
```
https://www.elastic.co/downloads/
```

### Start

**macOS**
```bash
brew services start elastic/tap/elasticsearch-full
brew services start elastic/tap/kibana-full
logstash -f logstash/pipeline.conf
```

**Linux**
```bash
sudo systemctl start elasticsearch
sudo systemctl start kibana
logstash -f logstash/pipeline.conf
```

**Windows**
```bash
# Run from Elasticsearch/Logstash/Kibana installation directories
bin\elasticsearch.bat
bin\kibana.bat
bin\logstash.bat -f logstash/pipeline.conf
```

### Verify Installation

**Elasticsearch:**
```
http://localhost:9200
```
Expected response:
```json
{
  "name": "localhost",
  "cluster_name": "elasticsearch"
}
```

**Kibana:**
```
http://localhost:5601
```

### Creating a Kibana Index Pattern

1. Open Kibana at `http://localhost:5601`
2. Navigate to **Stack Management → Index Patterns**
3. Click **Create Index Pattern**
4. Create two index patterns:

| Index Pattern | Description |
|--------------|-------------|
| `gate80-proxy-logs` | Proxy routing decisions and anomaly scores |
| `gate80-decoy-logs` | Attacker behavior inside the decoy |

### Index Names

| Index | Source Table | Content |
|-------|-------------|---------|
| `gate80-proxy-logs` | `proxy_requests` | Routing decisions, anomaly scores |
| `gate80-decoy-logs` | `decoy_requests` | Attacker behavior in decoy |

### Monitoring Architecture

```
Client Request
      │
      ▼
Reverse Proxy
      │
      ▼
proxy_logs.db (proxy_requests + decoy_requests)
      │
      ▼
Logstash
      │
      ▼
Elasticsearch
      │
      ▼
Kibana Dashboard
```

1. The **Reverse Proxy** intercepts all API traffic.
2. Each request is stored in **proxy_logs.db**.
3. **Logstash** extracts logs from the database.
4. Logs are indexed and stored in **Elasticsearch**.
5. **Kibana** visualizes the logs using dashboards.

---

## Authors
- Rama Alguthmi
- Wed Alotaibi
- Taif Alsaadi
- Rahaf Lamphon

---

## Acknowledgments

---

## Contact

📧 Contact information will be added.
