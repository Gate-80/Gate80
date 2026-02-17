# Adaptive API Deception Prototype – Digital Wallet API

## Overview
This repository contains **RASD**, a cloud-based adaptive deception system for API endpoints.

RASD aims to enhance API security by intercepting API traffic, analyzing request behavior, and dynamically engaging suspicious activity using realistic decoy APIs, while allowing legitimate traffic to reach real backend services.

At a high level, the system:
- Intercepts incoming API traffic using a reverse proxy
- Analyzes request behavior using machine learning and threat intelligence
- Dynamically decides whether traffic is legitimate or suspicious
- Forwards legitimate traffic to real backend services
- Redirects suspicious traffic to realistic digital-twin API decoys
- Collects logs and attacker interaction data for analysis

This project is developed for **academic and research purposes**.

---

## System Components
The RASD system consists of the following components:

- **Customer Backend APIs** – Realistic backend services protected by RASD  
- **Reverse Proxy Layer** – Intercepts and controls all incoming API traffic  
- **Digital-Twin API Decoys** – Synthetic APIs that replicate real endpoint behavior  
- **Anomaly Detection Engine** – Identifies abnormal or suspicious API behavior  
- **Threat Intelligence Integration** – Enriches traffic analysis using known threat data  
- **Adaptive Decision Engine** – Determines how each request is handled  
- **Monitoring & Dashboard** – Provides logs, alerts, and visibility into interactions  

---

## Customer Backend APIs
Customer backend APIs represent the applications being protected by the RASD system.  
These APIs are intentionally designed to be realistic, consistent, and worth interacting with.

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
## Technology Stack (Current Phase)

| Component | Technology |
|-----------|------------|
| Framework | FastAPI (Python) |
| API Style | REST |
| Documentation | OpenAPI / Swagger |
| Server | Uvicorn |
| Database | SQLite + SQLAlchemy ORM |
| Proxy | FastAPI Reverse Proxy (httpx) |

---

## Architecture

```
User / Client
     │
     ▼
┌─────────────────────────┐
│   Reverse Proxy (:8080) │  ← All traffic enters here
│   - Logs all requests   │
│   - Forwards to backend │
│   - Adds X-From-Proxy   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│  Backend API (:8000)    │  ← Only accessible through proxy
│  - Validates proxy header│
│  - Processes requests   │
│  - Logs audit events    │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│  SQLite Database        │  ← Persistent storage
│  digital_wallet.db      │
│  - Users & Sessions     │
│  - Wallets & Transactions│
│  - Audit Logs           │
└─────────────────────────┘
```

**Security Model:**
- The backend is completely isolated — direct access returns `403 Forbidden`
- All requests must pass through the proxy (`X-From-Proxy: 1` header)
- Only the `/health` endpoint is accessible directly on the backend
- All state-changing operations are logged to the audit table

---

## Repository Structure

```
RASD_adaptive-api-deception/
│
├── backend_api/                  # Customer backend API
│   ├── main.py                   # FastAPI app, middleware, router registration
│   ├── db/
│   │   ├── database.py           # SQLAlchemy engine and session setup
│   │   ├── models.py             # ORM models (User, Wallet, Transaction, etc.)
│   │   ├── audit_helper.py       # Audit logging helper functions
│   │   └── seed_data.py          # Database seeding script
│   └── routers/
│       ├── user_authentication.py
│       ├── admin_authentication.py
│       ├── user_accounts.py
│       ├── wallet.py
│       └── admin_operations.py
│
├── proxy/                        # Reverse proxy layer
│   ├── main.py                   # Transparent reverse proxy (httpx)
│   └── __init__.py
│
├── dashboard/                    # Monitoring dashboard
├── detection/                    # Anomaly detection engine
├── decoy_api/                    # Digital-twin decoy APIs
├── logs/                         # Request and audit logs
├── digital_wallet.db             # SQLite database (auto-created on startup)
├── requirements.txt              # Python dependencies
└── README.md
```

---

## Setup & Installation

### Prerequisites
- Python 3.9 or later
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/WedAbdullh/RASD_adaptive-api-deception.git
cd RASD_adaptive-api-deception
```

### 2. Create and Activate Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install fastapi uvicorn sqlalchemy httpx pydantic[email]
```

### 4. Seed the Database

Populate the database with test data (users, wallets, transactions, admin):

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

### 5. Run the Backend Server

```bash
uvicorn backend_api.main:app --reload --port 8000
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
✅ Database initialized
INFO:     Application startup complete.
```

### 6. Run the Proxy Server

Open a new terminal window:

```bash
source venv/bin/activate
uvicorn proxy.main:app --reload --port 8080
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8080
INFO:     Application startup complete.
```

---

## Testing the API

> ⚠️ **All API access must go through the proxy on port 8080.**
> Direct backend access on port 8000 will return `403 Forbidden`.

### Swagger UI
```
http://127.0.0.1:8080/docs
```

### Health Check
```
http://127.0.0.1:8000/health
```
Expected response:
```json
{ "status": "ok", "service": "digital-wallet-api" }
```

### Test Credentials

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

## Database

The system uses **SQLite** with **SQLAlchemy ORM** for persistent storage.

### Database File
```
digital_wallet.db       ← auto-created in project root on first startup
```

### Tables

| Table | Description |
|-------|-------------|
| `users` | Registered user accounts |
| `wallets` | User wallets with balances |
| `transactions` | All wallet transactions |
| `payments` | Payment records |
| `bank_accounts` | Linked bank accounts |
| `user_sessions` | Active user session tokens |
| `admin_sessions` | Active admin session tokens |
| `admins` | Admin accounts |
| `audit_logs` | Audit trail of all state-changing actions |

### Viewing the Database

**SQLite CLI:**
```bash
sqlite3 digital_wallet.db
.mode column
.headers on
.tables
SELECT * FROM users;
SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10;
.quit
```

**VS Code:** Install the **SQLite Viewer** extension by Florian Klampfer, then click `digital_wallet.db` in the file explorer.

### Audit Logging

The following actions are logged to the `audit_logs` table:

| Category | Events Logged |
|----------|--------------|
| Authentication | User/admin login, logout, failed attempts |
| Wallet Operations | Top up, withdraw, transfer, bill payment |
| Account Changes | Profile updates, bank account changes |
| Admin Actions | View users, wallets, transactions |
| Failures | Insufficient balance, invalid credentials |

---

## API Reference

Interactive API documentation is available through Swagger UI at:
```
http://127.0.0.1:8080/docs
```
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
