# backend_api/routers/wallet.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, condecimal
from typing import Dict, Any
from decimal import Decimal

from backend_api.db.users_store import T_USERS, now_iso
from backend_api.db.wallet_store import T_WALLETS, T_TRANSACTIONS

router = APIRouter(tags=["wallet"])

# -----------------------------
# Schemas
# -----------------------------

class WalletBalanceResponse(BaseModel):
    user_id: str
    balance: str  # Changed to string to match stored format
    currency: str


class WalletAmountRequest(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)


# -----------------------------
# Helpers
# -----------------------------

def get_wallet_or_404(user_id: str) -> Dict[str, Any]:
    # Fix: T_WALLETS is keyed by wallet_id, not user_id, so we need to search
    wallet = next((w for w in T_WALLETS.values() if w["user_id"] == user_id), None)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return wallet


def ensure_user_exists(user_id: str):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")


def generate_transaction_id() -> str:
    """Generate next transaction ID using max + 1"""
    existing_ids = [int(tx["id"].split("_")[1]) for tx in T_TRANSACTIONS if tx["id"].startswith("tx_")]
    next_id = max(existing_ids, default=7000) + 1
    return f"tx_{next_id}"


def create_transaction(
    user_id: str,
    wallet_id: str,
    tx_type: str,
    amount: Decimal,
    currency_code: str,
    counterparty_kind: str,
    counterparty_ref: str,
    description: str,
    status: str = "COMPLETED"
) -> None:
    """Create a properly structured transaction entry"""
    now = now_iso()
    T_TRANSACTIONS.append({
        "id": generate_transaction_id(),
        "user_id": user_id,
        "wallet_id": wallet_id,
        "type": tx_type,
        "status": status,
        "amount": {
            "currency_code": currency_code,
            "value": str(amount)
        },
        "counterparty": {
            "kind": counterparty_kind,
            "ref": counterparty_ref
        },
        "description": description,
        "created_at": now,
        "updated_at": now,

    })


# -----------------------------
# Endpoints
# -----------------------------

@router.get("/users/{user_id}/wallet", response_model=WalletBalanceResponse)
def view_wallet_balance(user_id: str):
    ensure_user_exists(user_id)
    wallet = get_wallet_or_404(user_id)

    return {
        "user_id": user_id,
        "balance": wallet["balance"],
        "currency": wallet["currency_code"],
    }


@router.post("/users/{user_id}/wallet/topup")
def topup_wallet(user_id: str, payload: WalletAmountRequest):
    ensure_user_exists(user_id)
    wallet = get_wallet_or_404(user_id)

    # Fix: Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    current_balance = Decimal(str(wallet["balance"]))
    new_balance = current_balance + amount
    
    wallet["balance"] = str(new_balance)
    wallet["updated_at"] = now_iso()

    # Fix: Create properly structured transaction
    create_transaction(
        user_id=user_id,
        wallet_id=wallet["id"],
        tx_type="TOPUP",
        amount=amount,
        currency_code=wallet["currency_code"],
        counterparty_kind="CARD",
        counterparty_ref="card_****_0000",  # Placeholder
        description="Top up via card",
        status="COMPLETED"
    )

    return {
        "message": "Wallet topped up",
        "new_balance": wallet["balance"],
        "currency": wallet["currency_code"],
    }


@router.post("/users/{user_id}/wallet/withdraw")
def withdraw_wallet(user_id: str, payload: WalletAmountRequest):
    ensure_user_exists(user_id)
    wallet = get_wallet_or_404(user_id)

    # Fix: Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    current_balance = Decimal(str(wallet["balance"]))

    if current_balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = current_balance - amount
    wallet["balance"] = str(new_balance)
    wallet["updated_at"] = now_iso()

    # Fix: Create properly structured transaction
    create_transaction(
        user_id=user_id,
        wallet_id=wallet["id"],
        tx_type="WITHDRAW",
        amount=amount,
        currency_code=wallet["currency_code"],
        counterparty_kind="BANK",
        counterparty_ref="bank_account",  # Placeholder
        description="Withdraw to bank account",
        status="COMPLETED"
    )

    return {
        "message": "Withdraw successful",
        "new_balance": wallet["balance"],
        "currency": wallet["currency_code"],
    }


@router.post("/users/{user_id}/wallet/transfer/{target_user_id}")
def transfer_to_user(user_id: str, target_user_id: str, payload: WalletAmountRequest):
    ensure_user_exists(user_id)
    ensure_user_exists(target_user_id)

    # Fix: Prevent transfer to self
    if user_id == target_user_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")

    sender_wallet = get_wallet_or_404(user_id)
    receiver_wallet = get_wallet_or_404(target_user_id)

    # Fix: Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    sender_balance = Decimal(str(sender_wallet["balance"]))
    receiver_balance = Decimal(str(receiver_wallet["balance"]))

    if sender_balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # Update balances
    sender_wallet["balance"] = str(sender_balance - amount)
    sender_wallet["updated_at"] = now_iso()
    
    receiver_wallet["balance"] = str(receiver_balance + amount)
    receiver_wallet["updated_at"] = now_iso()

    # Fix: Create properly structured transaction
    create_transaction(
        user_id=user_id,
        wallet_id=sender_wallet["id"],
        tx_type="TRANSFER_USER",
        amount=amount,
        currency_code=sender_wallet["currency_code"],
        counterparty_kind="USER",
        counterparty_ref=target_user_id,
        description=f"Transfer to user {target_user_id}",
        status="COMPLETED"
    )

    return {
        "message": "Transfer successful",
        "new_balance": sender_wallet["balance"],
        "currency": sender_wallet["currency_code"],
    }


@router.post("/users/{user_id}/wallet/pay-bill")
def pay_bill(user_id: str, payload: WalletAmountRequest):
    ensure_user_exists(user_id)
    wallet = get_wallet_or_404(user_id)

    # Fix: Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    current_balance = Decimal(str(wallet["balance"]))

    if current_balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = current_balance - amount
    wallet["balance"] = str(new_balance)
    wallet["updated_at"] = now_iso()

    # Fix: Create properly structured transaction
    create_transaction(
        user_id=user_id,
        wallet_id=wallet["id"],
        tx_type="BILLPAY",
        amount=amount,
        currency_code=wallet["currency_code"],
        counterparty_kind="BILLER",
        counterparty_ref="biller_0000",  # Placeholder
        description="Bill payment",
        status="COMPLETED"
    )

    return {
        "message": "Bill paid successfully",
        "new_balance": wallet["balance"],
        "currency": wallet["currency_code"],
    }