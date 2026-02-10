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
The following endpoint names represent the **designed API surface** of the Digital Wallet system:

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

All data is stored in-memory and uses realistic, consistent fake data for testing and experimentation.

---

## API Reference
Interactive API documentation is available through **Swagger UI** once the backend server is running.

![Swagger – User Accounts](docs/images/swagger-users.png)

---
## Technology Stack (Current Phase)
- Framework: FastAPI (Python)
- API Style: REST
- Documentation: OpenAPI / Swagger
- Server: Uvicorn
- Storage: In-memory data structures
---

## Setup & Installation

### 1. Environment Preparation
- Python 3.9 or later
- Backend implemented using FastAPI

### 2. Install Dependencies
    pip install fastapi uvicorn

### 3. Clone the Repository
    git clone https://github.com/WedAbdullh/RASD_adaptive-api-deception.git
    cd RASD_adaptive-api-deception

### 4. Run the Backend Server
From inside the backend_api directory:
    uvicorn main:app --reload

### 5. Test the API
Swagger UI:
    http://127.0.0.1:8000/docs

Example test endpoint:
    http://127.0.0.1:8000/hello

Expected response:
    { "message": "Hello from RASD" }

---

## Repository Structure
    RASD_adaptive-api-deception/
    │
    ├── backend_api/        # Customer backend APIs
    │   ├── main.py
    │   ├── hello.py
    │   └── ...
    │
    ├── README.md
    └── ...

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
