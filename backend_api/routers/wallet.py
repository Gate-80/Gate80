from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, condecimal
from decimal import Decimal
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import User, Wallet, Transaction, TransactionType, TransactionStatus
from backend_api.db.audit_helper import (
    log_wallet_topup, 
    log_wallet_withdraw, 
    log_user_transfer, 
    log_bill_payment,
    log_failed_action
)


# Define user security scheme

router = APIRouter()

# -----------------------------
# Schemas
# -----------------------------
class WalletBalanceResponse(BaseModel):
    user_id: str
    balance: str
    currency: str


class WalletAmountRequest(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)


# -----------------------------
# Helper Functions
# -----------------------------
def get_wallet_or_404(db: Session, user_id: str) -> Wallet:
    """Get user's wallet or raise 404"""
    wallet = db.query(Wallet).filter_by(user_id=user_id).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return wallet


def ensure_user_exists(db: Session, user_id: str):
    """Check if user exists, raise 404 if not"""
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")


def generate_transaction_id(db: Session) -> str:
    """Generate next transaction ID"""
    transactions = db.query(Transaction).all()
    if not transactions:
        return "tx_7001"
    
    existing_ids = [int(tx.id.split("_")[1]) for tx in transactions if tx.id.startswith("tx_")]
    next_id = max(existing_ids, default=7000) + 1
    return f"tx_{next_id}"


def create_transaction(
    db: Session,
    user_id: str,
    wallet_id: str,
    tx_type: TransactionType,
    amount: Decimal,
    currency_code: str,
    counterparty_kind: str,
    counterparty_ref: str,
    description: str,
    status: TransactionStatus = TransactionStatus.COMPLETED
) -> Transaction:
    """Create a transaction record"""
    new_id = generate_transaction_id(db)
    
    transaction = Transaction(
        id=new_id,
        user_id=user_id,
        wallet_id=wallet_id,
        type=tx_type,
        status=status,
        amount={
            "currency_code": currency_code,
            "value": str(amount)
        },
        counterparty={
            "kind": counterparty_kind,
            "ref": counterparty_ref
        },
        description=description
    )
    
    db.add(transaction)
    return transaction


# -----------------------------
# Endpoints
# -----------------------------
@router.get("/users/{user_id}/wallet", response_model=WalletBalanceResponse)
def view_wallet_balance(user_id: str, db: Session = Depends(get_db)):
    ensure_user_exists(db, user_id)
    wallet = get_wallet_or_404(db, user_id)

    return {
        "user_id": user_id,
        "balance": wallet.balance,
        "currency": wallet.currency_code,
    }

@router.post("/users/{user_id}/wallet/topup")
def topup_wallet(user_id: str, payload: WalletAmountRequest, db: Session = Depends(get_db)):
    ensure_user_exists(db, user_id)
    wallet = get_wallet_or_404(db, user_id)

    # Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    current_balance = Decimal(str(wallet.balance))
    new_balance = current_balance + amount
    
    wallet.balance = str(new_balance)

    # Create transaction record
    create_transaction(
        db=db,
        user_id=user_id,
        wallet_id=wallet.id,
        tx_type=TransactionType.TOPUP,
        amount=amount,
        currency_code=wallet.currency_code,
        counterparty_kind="CARD",
        counterparty_ref="card_****_0000",
        description="Top up via card",
        status=TransactionStatus.COMPLETED
    )
    
    db.commit()
    db.refresh(wallet)
    
    # Log audit
    log_wallet_topup(
        db=db, 
        user_id=user_id, 
        wallet_id=wallet.id, 
        amount=str(amount), 
        currency=wallet.currency_code
    )

    return {
        "message": "Wallet topped up",
        "new_balance": wallet.balance,
        "currency": wallet.currency_code,
    }


@router.post("/users/{user_id}/wallet/withdraw")
def withdraw_wallet(user_id: str, payload: WalletAmountRequest, db: Session = Depends(get_db)):
    ensure_user_exists(db, user_id)
    wallet = get_wallet_or_404(db, user_id)

    # Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    current_balance = Decimal(str(wallet.balance))

    if current_balance < amount:
        # Log failed withdrawal
        log_failed_action(
            db=db,
            event="WALLET_WITHDRAW_FAILED",
            actor_type="USER",
            actor_id=user_id,
            error_message="Insufficient balance"
        )
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = current_balance - amount
    wallet.balance = str(new_balance)

    # Create transaction record
    create_transaction(
        db=db,
        user_id=user_id,
        wallet_id=wallet.id,
        tx_type=TransactionType.WITHDRAW,
        amount=amount,
        currency_code=wallet.currency_code,
        counterparty_kind="BANK",
        counterparty_ref="bank_account",
        description="Withdraw to bank account",
        status=TransactionStatus.COMPLETED
    )
    
    db.commit()
    db.refresh(wallet)
    
    # Log audit
    log_wallet_withdraw(
        db=db, 
        user_id=user_id, 
        wallet_id=wallet.id, 
        amount=str(amount), 
        currency=wallet.currency_code
    )

    return {
        "message": "Withdraw successful",
        "new_balance": wallet.balance,
        "currency": wallet.currency_code,
    }


@router.post("/users/{user_id}/wallet/transfer/{target_user_id}")
def transfer_to_user(
    user_id: str, 
    target_user_id: str, 
    payload: WalletAmountRequest, 
    db: Session = Depends(get_db),
):
    ensure_user_exists(db, user_id)
    ensure_user_exists(db, target_user_id)

    # Prevent transfer to self
    if user_id == target_user_id:
        log_failed_action(
            db=db,
            event="USER_TRANSFER_FAILED",
            actor_type="USER",
            actor_id=user_id,
            error_message="Cannot transfer to yourself"
        )
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")

    sender_wallet = get_wallet_or_404(db, user_id)
    receiver_wallet = get_wallet_or_404(db, target_user_id)

    # Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    sender_balance = Decimal(str(sender_wallet.balance))
    receiver_balance = Decimal(str(receiver_wallet.balance))

    if sender_balance < amount:
        log_failed_action(
            db=db,
            event="USER_TRANSFER_FAILED",
            actor_type="USER",
            actor_id=user_id,
            error_message="Insufficient balance"
        )
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # Update balances
    sender_wallet.balance = str(sender_balance - amount)
    receiver_wallet.balance = str(receiver_balance + amount)

    # Create transaction record
    create_transaction(
        db=db,
        user_id=user_id,
        wallet_id=sender_wallet.id,
        tx_type=TransactionType.TRANSFER_USER,
        amount=amount,
        currency_code=sender_wallet.currency_code,
        counterparty_kind="USER",
        counterparty_ref=target_user_id,
        description=f"Transfer to user {target_user_id}",
        status=TransactionStatus.COMPLETED
    )
    
    db.commit()
    db.refresh(sender_wallet)
    
    # Log audit
    log_user_transfer(
        db=db, 
        user_id=user_id, 
        wallet_id=sender_wallet.id, 
        amount=str(amount), 
        to_user=target_user_id
    )

    return {
        "message": "Transfer successful",
        "new_balance": sender_wallet.balance,
        "currency": sender_wallet.currency_code,
    }

@router.post("/users/{user_id}/wallet/pay-bill")
def pay_bill(user_id: str, payload: WalletAmountRequest, db: Session = Depends(get_db)):
    ensure_user_exists(db, user_id)
    wallet = get_wallet_or_404(db, user_id)

    # Use Decimal for accurate money calculations
    amount = Decimal(str(payload.amount))
    current_balance = Decimal(str(wallet.balance))

    if current_balance < amount:
        log_failed_action(
            db=db,
            event="BILL_PAYMENT_FAILED",
            actor_type="USER",
            actor_id=user_id,
            error_message="Insufficient balance"
        )
        raise HTTPException(status_code=400, detail="Insufficient balance")

    new_balance = current_balance - amount
    wallet.balance = str(new_balance)

    # Create transaction record
    create_transaction(
        db=db,
        user_id=user_id,
        wallet_id=wallet.id,
        tx_type=TransactionType.BILLPAY,
        amount=amount,
        currency_code=wallet.currency_code,
        counterparty_kind="BILLER",
        counterparty_ref="biller_0000",
        description="Bill payment",
        status=TransactionStatus.COMPLETED
    )
    
    db.commit()
    db.refresh(wallet)
    
    # Log audit
    log_bill_payment(
        db=db, 
        user_id=user_id, 
        wallet_id=wallet.id, 
        amount=str(amount)
    )

    return {
        "message": "Bill paid successfully",
        "new_balance": wallet.balance,
        "currency": wallet.currency_code,
    }