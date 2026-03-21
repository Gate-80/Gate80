
from decimal import Decimal
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, condecimal
from sqlalchemy.orm import Session

from decoy_api.db.database import get_wallet_db
from decoy_api.db.models import (
    DecoyWallet, DecoyTransaction, DecoyUser,
    TransactionType, TransactionStatus
)
from decoy_api.routers.auth import require_user

router = APIRouter(tags=["wallet"])


# ── Schema ────────────────────────────────────────────────────────────────────
class WalletAmountRequest(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _get_wallet(db: Session, user_id: str) -> DecoyWallet:
    wallet = db.query(DecoyWallet).filter_by(user_id=user_id).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return wallet


def _next_tx_id(db: Session) -> str:
    txs = db.query(DecoyTransaction).all()
    if not txs:
        return "tx_8001"
    ids = [int(t.id.split("_")[1]) for t in txs if t.id.startswith("tx_")]
    return f"tx_{max(ids) + 1}"


def _create_tx(db, user_id, wallet_id, tx_type, amount, currency, cp_kind, cp_ref, desc):
    tx = DecoyTransaction(
        id=_next_tx_id(db),
        user_id=user_id,
        wallet_id=wallet_id,
        type=tx_type,
        status=TransactionStatus.COMPLETED,
        amount={"currency_code": currency, "value": str(amount)},
        counterparty={"kind": cp_kind, "ref": cp_ref},
        description=desc,
    )
    db.add(tx)
    return tx


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.get("/users/{user_id}/wallet")
def get_wallet_balance(
    user_id: str,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    wallet = _get_wallet(db, user_id)
    return {
        "user_id":  user_id,
        "balance":  wallet.balance,
        "currency": wallet.currency_code,
    }


@router.post("/users/{user_id}/wallet/topup")
def topup_wallet(
    user_id: str,
    payload: WalletAmountRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    wallet          = _get_wallet(db, user_id)
    amount          = Decimal(str(payload.amount))
    new_balance     = Decimal(str(wallet.balance)) + amount
    wallet.balance  = str(new_balance)

    _create_tx(db, user_id, wallet.id, TransactionType.TOPUP,
                amount, wallet.currency_code, "CARD", "card_****_0000", "Top up via card")
    db.commit()

    return {
        "message":     "Wallet topped up",
        "new_balance": wallet.balance,
        "currency":    wallet.currency_code,
    }


@router.post("/users/{user_id}/wallet/withdraw")
def withdraw_wallet(
    user_id: str,
    payload: WalletAmountRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    wallet  = _get_wallet(db, user_id)
    amount  = Decimal(str(payload.amount))
    balance = Decimal(str(wallet.balance))

    if balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    wallet.balance = str(balance - amount)
    _create_tx(db, user_id, wallet.id, TransactionType.WITHDRAW,
                amount, wallet.currency_code, "BANK", "bank_account", "Withdraw to bank account")
    db.commit()

    return {
        "message":     "Withdraw successful",
        "new_balance": wallet.balance,
        "currency":    wallet.currency_code,
    }


@router.post("/users/{user_id}/wallet/transfer/{target_user_id}")
def transfer_to_user(
    user_id: str,
    target_user_id: str,
    payload: WalletAmountRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    if user_id == target_user_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")

    sender_wallet = _get_wallet(db, user_id)
    amount        = Decimal(str(payload.amount))

    if Decimal(str(sender_wallet.balance)) < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    sender_wallet.balance = str(Decimal(str(sender_wallet.balance)) - amount)

    receiver_wallet = db.query(DecoyWallet).filter_by(user_id=target_user_id).first()
    if receiver_wallet:
        receiver_wallet.balance = str(Decimal(str(receiver_wallet.balance)) + amount)

    _create_tx(db, user_id, sender_wallet.id, TransactionType.TRANSFER_USER,
                amount, sender_wallet.currency_code, "USER", target_user_id,
                f"Transfer to user {target_user_id}")
    db.commit()

    return {
        "message":     "Transfer successful",
        "new_balance": sender_wallet.balance,
        "currency":    sender_wallet.currency_code,
    }


@router.post("/users/{user_id}/wallet/pay-bill")
def pay_bill(
    user_id: str,
    payload: WalletAmountRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    wallet = _get_wallet(db, user_id)
    amount = Decimal(str(payload.amount))

    if Decimal(str(wallet.balance)) < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    wallet.balance = str(Decimal(str(wallet.balance)) - amount)
    _create_tx(db, user_id, wallet.id, TransactionType.BILLPAY,
                amount, wallet.currency_code, "BILLER", "biller_0000", "Bill payment")
    db.commit()

    return {
        "message":     "Bill paid successfully",
        "new_balance": wallet.balance,
        "currency":    wallet.currency_code,
    }