from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
import random
import uuid
import logging
from datetime import datetime

router = APIRouter()

logging.basicConfig(filename="decoy_user_accounts.log", level=logging.INFO)

# -----------------------------
# Fake Schemas
# -----------------------------

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    city: Optional[str] = None


class AddBankAccountRequest(BaseModel):
    bank_name: str
    iban: str
    masked_account_number: str
    currency: str
    is_default: bool


class UpdateBankAccountRequest(BaseModel):
    bank_name: Optional[str] = None
    iban: Optional[str] = None
    is_default: Optional[bool] = None


# -----------------------------
# Fake generators
# -----------------------------

def fake_user(user_id):
    return {
        "id": user_id,
        "full_name": "Ahmed Al-Salem",
        "email": f"{user_id}@example.com",
        "phone": "+966500000000",
        "city": random.choice(["Riyadh", "Jeddah", "Dammam"]),
        "is_verified": random.choice([True, False]),
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }


def fake_bank_account(user_id):
    return {
        "id": f"bank_{uuid.uuid4().hex[:8]}",
        "user_id": user_id,
        "bank_name": random.choice(["Al Rajhi Bank", "SNB", "Riyad Bank"]),
        "iban": "SA" + str(random.randint(1000000000000000000000, 9999999999999999999999)),
        "masked_account_number": "****" + str(random.randint(1000, 9999)),
        "currency": "SAR",
        "is_default": random.choice([True, False]),
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }


def fake_payment(user_id):
    return {
        "id": f"pay_{uuid.uuid4().hex[:8]}",
        "user_id": user_id,
        "status": random.choice(["COMPLETED", "PENDING", "FAILED"]),
        "amount": round(random.uniform(50, 1200), 2),
        "merchant": random.choice(["STC", "Amazon", "Jarir", "Noon"]),
        "description": "Online purchase",
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }


# -----------------------------
# Decoy Endpoints — Users
# -----------------------------

@router.get("/users/{user_id}")
def view_user_profile(user_id: str):

    logging.info(f"[DECOY] profile viewed user={user_id}")

    return fake_user(user_id)


@router.put("/users/{user_id}")
def update_user_profile(user_id: str, payload: UpdateProfileRequest):

    logging.info(f"[DECOY] profile update attempt user={user_id}")

    user = fake_user(user_id)

    if payload.full_name:
        user["full_name"] = payload.full_name
    if payload.phone:
        user["phone"] = payload.phone
    if payload.city:
        user["city"] = payload.city

    user["updated_at"] = datetime.now().isoformat()

    return user


# -----------------------------
# Decoy Endpoints — Bank Accounts
# -----------------------------

@router.post("/users/{user_id}/bank-accounts")
def add_bank_account(user_id: str, payload: AddBankAccountRequest):

    logging.info(f"[DECOY] bank account added user={user_id}")

    return fake_bank_account(user_id)


@router.get("/users/{user_id}/bank-accounts")
def view_bank_accounts(user_id: str):

    logging.info(f"[DECOY] bank accounts viewed user={user_id}")

    return [fake_bank_account(user_id) for _ in range(random.randint(1,3))]


@router.put("/users/{user_id}/bank-accounts/{bank_account_id}")
def update_bank_account(user_id: str, bank_account_id: str, payload: UpdateBankAccountRequest):

    logging.info(f"[DECOY] bank account update attempt user={user_id} account={bank_account_id}")

    account = fake_bank_account(user_id)
    account["id"] = bank_account_id

    if payload.bank_name:
        account["bank_name"] = payload.bank_name
    if payload.iban:
        account["iban"] = payload.iban
    if payload.is_default is not None:
        account["is_default"] = payload.is_default

    account["updated_at"] = datetime.now().isoformat()

    return account


# -----------------------------
# Decoy Endpoints — Payments
# -----------------------------

@router.get("/users/{user_id}/payments")
def view_user_payments(
    user_id: str,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50),
    offset: int = Query(default=0),
):

    logging.info(f"[DECOY] payments viewed user={user_id}")

    payments = [fake_payment(user_id) for _ in range(random.randint(3,10))]

    if status:
        payments = [p for p in payments if p["status"] == status]

    return payments[offset:offset+limit]


@router.get("/users/{user_id}/payments/{payment_id}")
def view_payment_details(user_id: str, payment_id: str):

    logging.info(f"[DECOY] payment details accessed user={user_id} payment={payment_id}")

    payment = fake_payment(user_id)
    payment["id"] = payment_id

    return payment