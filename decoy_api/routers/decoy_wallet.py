from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from decimal import Decimal
import random
import uuid
import logging

router = APIRouter()

# simple logger for decoy activity
logging.basicConfig(filename="decoy_wallet.log", level=logging.INFO)

# -----------------------------
# Schemas (mirror real ones)
# -----------------------------
class WalletAmountRequest(BaseModel):
    amount: float

# -----------------------------
# Fake wallet generator
# -----------------------------
def fake_wallet(user_id: str):
    return {
        "user_id": user_id,
        "balance": str(round(random.uniform(500, 12000), 2)),
        "currency": "SAR"
    }

# -----------------------------
# Endpoints (Decoy)
# -----------------------------

@router.get("/users/{user_id}/wallet")
def view_wallet_balance(user_id: str):

    wallet = fake_wallet(user_id)

    logging.info(f"[DECOY] wallet balance accessed: {user_id}")

    return wallet


@router.post("/users/{user_id}/wallet/topup")
def topup_wallet(user_id: str, payload: WalletAmountRequest):

    amount = Decimal(str(payload.amount))
    fake_balance = Decimal(str(round(random.uniform(1000, 9000), 2)))

    new_balance = fake_balance + amount

    logging.info(f"[DECOY] wallet topup attempt: {user_id} amount={amount}")

    return {
        "message": "Wallet topped up",
        "new_balance": str(new_balance),
        "currency": "SAR",
        "transaction_id": f"tx_{uuid.uuid4().hex[:10]}"
    }


@router.post("/users/{user_id}/wallet/withdraw")
def withdraw_wallet(user_id: str, payload: WalletAmountRequest):

    amount = Decimal(str(payload.amount))
    fake_balance = Decimal(str(round(random.uniform(500, 7000), 2)))

    if fake_balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = fake_balance - amount

    logging.info(f"[DECOY] withdraw attempt: {user_id} amount={amount}")

    return {
        "message": "Withdraw successful",
        "new_balance": str(new_balance),
        "currency": "SAR",
        "reference_id": f"wd_{uuid.uuid4().hex[:8]}"
    }


@router.post("/users/{user_id}/wallet/transfer/{target_user_id}")
def transfer_to_user(user_id: str, target_user_id: str, payload: WalletAmountRequest):

    amount = Decimal(str(payload.amount))
    fake_balance = Decimal(str(round(random.uniform(1000, 8000), 2)))

    if user_id == target_user_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")

    if fake_balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = fake_balance - amount

    logging.info(
        f"[DECOY] transfer attempt: from={user_id} to={target_user_id} amount={amount}"
    )

    return {
        "message": "Transfer successful",
        "new_balance": str(new_balance),
        "currency": "SAR",
        "transaction_ref": f"tr_{uuid.uuid4().hex[:8]}"
    }


@router.post("/users/{user_id}/wallet/pay-bill")
def pay_bill(user_id: str, payload: WalletAmountRequest):

    amount = Decimal(str(payload.amount))
    fake_balance = Decimal(str(round(random.uniform(1000, 6000), 2)))

    if fake_balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = fake_balance - amount

    logging.info(f"[DECOY] bill payment attempt: user={user_id} amount={amount}")

    return {
        "message": "Bill paid successfully",
        "new_balance": str(new_balance),
        "currency": "SAR",
        "payment_id": f"bill_{uuid.uuid4().hex[:8]}"
    }