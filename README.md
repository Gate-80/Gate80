# Digital Wallet API – Adaptive API Deception Prototype 

## Overview
This repository contains the initial implementation of a **Graduation Project focused on Adaptive API Deception**.  
The project aims to study, design, and evaluate techniques for applying deception mechanisms at the API level in order to improve security, detect malicious behavior, and mislead attackers interacting with exposed APIs.

At this stage, the project focuses on establishing a **realistic environment** that can later be used to apply and evaluate deception strategies.

---

## Project Scope
The overall project investigates:
- How attackers interact with documented APIs
- The security implications of exposed OpenAPI / Swagger documentation
- How deception techniques can be applied dynamically at the API layer
- How realistic “customer systems” can be used as controlled targets for experimentation

The current implementation represents an **early phase** of the project, where foundational components and system structure are being established.

---

## Customer System: Digital Wallet API
As part of the project, a **Digital Wallet System** is implemented to act as a **customer-side API**.

This system is **not the main product**, but rather a **representative real-world backend** that:
- Exposes realistic API endpoints
- Mimics common financial application behavior
- Provides an attack surface for future deception experiments

The Digital Wallet API is used to:
- Simulate legitimate client interactions
- Observe how attackers explore and abuse APIs
- Serve as an input to deception mechanisms in later stages

---

## High-Level System Components
The project is conceptually divided into the following components:

- **Customer API (Digital Wallet System)**  
  A realistic backend API representing a financial application.
...
---

## Digital Wallet API – Design Overview 
The Digital Wallet API is designed to resemble a real-world system and includes the following **conceptual endpoint groups**.

> **Note:** These endpoints represent the intended design. Only a subset is implemented at this stage.

### User Accounts
- View User Profile  
- Update User Profile  
- Add Bank Account Information  
- View Bank Account Information  
- Update Bank Account Information  

### Wallet Operations
- View Wallet Balance  
- Transfer Funds to Another User  
- Transfer Funds to Bank Account  
- Top Up Wallet Balance  
- Withdrawal  
- Bill Payment  

### Payments / Transactions
- View User Payments  
- View Payment Details  

### Admin Operations
- View All Registered Users  
- View All Wallets  
- View All Transactions  
- View System Financial Overview  

### Authentication
- User Sign Up / Sign In / Sign Out  
- Admin Sign In / Sign Out  

These endpoints are included to provide **realism and structure**, and to reflect how actual digital wallet APIs are designed.

---

## Technology Stack
- **Backend Framework:** FastAPI (Python)
- **API Style:** RESTful
- **API Documentation:** OpenAPI (Swagger)
- **Server:** Uvicorn (ASGI)
- **Data Storage:** In-memory (prototype phase)

---

## Future Work


---

## Academic Context
This project is developed as part of a graduation project focused on API security and adaptive deception, using realistic API design to simulate real-world attack surfaces.

