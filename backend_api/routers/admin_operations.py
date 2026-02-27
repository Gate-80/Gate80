
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field, condecimal
from typing import Optional, Literal, List, Dict
from decimal import Decimal
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import User, Wallet, Transaction, WalletStatus, TransactionType, TransactionStatus
from backend_api.db.audit_helper import log_admin_view_users, log_admin_view_wallets, log_admin_view_transactions
from backend_api.routers.admin_authentication import require_admin

router = APIRouter(prefix="/admin")

# -----------------------------
# Schemas  — Admin Operations
# -----------------------------
CurrencyCode = Literal["SAR", "USD", "EUR"]
MoneyValue = condecimal(max_digits=12, decimal_places=2)

class AdminUserResponse(BaseModel):
    id: str = Field(example="u_1004")
    full_name: str = Field(example="Test User")
    email: str = Field(example="user@example.com")
    phone: str = Field(example="+9665XXXXXXX")
    city: str = Field(example="Jeddah")
    is_verified: bool = Field(example=True)
    created_at: str
    updated_at: str

class Money(BaseModel):
    currency_code: CurrencyCode = Field(default="SAR", example="SAR")
    value: MoneyValue = Field(example="120.00")

class WalletResponse(BaseModel):
    id: str = Field(example="w_5001")
    user_id: str = Field(example="u_1001")
    currency_code: CurrencyCode = Field(example="SAR")
    balance: MoneyValue = Field(example="950.25")
    status: str = Field(example="ACTIVE")
    created_at: str
    updated_at: str

class Counterparty(BaseModel):
    kind: Literal["USER", "BANK", "CARD", "BILLER"] = Field(example="USER")
    ref: str = Field(example="u_1002")

class TransactionResponse(BaseModel):
    id: str = Field(pattern=r"^tx_\d{4,10}$", example="tx_7001")
    type: str = Field(example="TOPUP")
    status: str = Field(example="COMPLETED")
    amount: Money
    wallet_id: str = Field(example="w_5001")
    user_id: str = Field(example="u_1001")
    counterparty: Counterparty
    description: Optional[str] = Field(default=None, max_length=140, example="Top up via card")
    created_at: str
    updated_at: str

class OverviewByCurrency(BaseModel):
    currency_code: CurrencyCode
    total_wallets: int
    total_balance: MoneyValue
    total_transactions: int
    volume_completed: MoneyValue

class SystemFinancialOverviewResponse(BaseModel):
    total_users: int
    total_wallets: int
    total_transactions: int
    wallets_by_status: Dict[str, int]
    overview_by_currency: List[OverviewByCurrency]
    generated_at: str

# -----------------------------
# Endpoints
# -----------------------------
@router.get("/users", response_model=List[AdminUserResponse])
def admin_view_all_users(
    q: Optional[str] = Query(default=None, description="Search by name/email/city"),
    verified: Optional[bool] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """View all users with optional filtering"""
    query = db.query(User)
    if verified is not None:
        query = query.filter_by(is_verified=verified)
    if q:
        search = f"%{q.strip().lower()}%"
        query = query.filter(
            (User.full_name.ilike(search)) |
            (User.email.ilike(search)) |
            (User.city.ilike(search))
        )
    query = query.order_by(User.created_at.desc())
    users = query.offset(offset).limit(limit).all()
    log_admin_view_users(db=db, admin_id=admin.id, filters={"q": q, "verified": verified, "limit": limit, "offset": offset})
    return [{"id": u.id, "full_name": u.full_name, "email": u.email, "phone": u.phone, "city": u.city, "is_verified": u.is_verified, "created_at": u.created_at.isoformat(), "updated_at": u.updated_at.isoformat()} for u in users]


@router.get("/wallets", response_model=List[WalletResponse])
def admin_view_all_wallets(
    currency: Optional[CurrencyCode] = Query(default=None),
    status: Optional[str] = Query(default=None),
    user_id: Optional[str] = Query(default=None, description="Filter wallets by user_id"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """View all wallets with optional filtering"""
    query = db.query(Wallet)
    if currency:
        query = query.filter_by(currency_code=currency)
    if status:
        query = query.filter_by(status=status)
    if user_id:
        query = query.filter_by(user_id=user_id)
    query = query.order_by(Wallet.updated_at.desc())
    wallets = query.offset(offset).limit(limit).all()
    log_admin_view_wallets(db=db, admin_id=admin.id, filters={"currency": currency, "status": status, "user_id": user_id, "limit": limit, "offset": offset})
    return [{"id": w.id, "user_id": w.user_id, "currency_code": w.currency_code, "balance": w.balance, "status": w.status.value if hasattr(w.status, 'value') else w.status, "created_at": w.created_at.isoformat(), "updated_at": w.updated_at.isoformat()} for w in wallets]


@router.get("/transactions", response_model=List[TransactionResponse])
def admin_view_all_transactions(
    status: Optional[str] = Query(default=None),
    tx_type: Optional[str] = Query(default=None, alias="type"),
    user_id: Optional[str] = Query(default=None),
    wallet_id: Optional[str] = Query(default=None),
    currency: Optional[CurrencyCode] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """View all transactions with optional filtering"""
    query = db.query(Transaction)
    if status:
        query = query.filter_by(status=status)
    if tx_type:
        query = query.filter_by(type=tx_type)
    if user_id:
        query = query.filter_by(user_id=user_id)
    if wallet_id:
        query = query.filter_by(wallet_id=wallet_id)
    query = query.order_by(Transaction.created_at.desc())
    transactions = query.offset(offset).limit(limit).all()
    log_admin_view_transactions(db=db, admin_id=admin.id, filters={"status": status, "type": tx_type, "user_id": user_id, "wallet_id": wallet_id, "currency": currency, "limit": limit, "offset": offset})
    return [{"id": t.id, "type": t.type.value if hasattr(t.type, 'value') else t.type, "status": t.status.value if hasattr(t.status, 'value') else t.status, "amount": t.amount, "wallet_id": t.wallet_id, "user_id": t.user_id, "counterparty": t.counterparty, "description": t.description, "created_at": t.created_at.isoformat(), "updated_at": t.updated_at.isoformat()} for t in transactions]


@router.get("/overview/financial", response_model=SystemFinancialOverviewResponse)
def admin_view_system_financial_overview(
    admin = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """View system-wide financial overview"""
    from datetime import datetime, timezone
    total_users = db.query(User).count()
    wallets = db.query(Wallet).all()
    transactions = db.query(Transaction).all()
    wallets_by_status: Dict[str, int] = {}
    for w in wallets:
        status_key = w.status.value if hasattr(w.status, 'value') else w.status
        wallets_by_status[status_key] = wallets_by_status.get(status_key, 0) + 1
    currencies = sorted(set(w.currency_code for w in wallets))
    by_currency: List[OverviewByCurrency] = []
    for c in currencies:
        wallets_c = [w for w in wallets if w.currency_code == c]
        txs_c = [t for t in transactions if t.amount.get("currency_code") == c]
        total_balance = sum(Decimal(str(w.balance)) for w in wallets_c) if wallets_c else Decimal("0.0")
        completed = [t for t in txs_c if (t.status.value if hasattr(t.status, 'value') else t.status) == "COMPLETED"]
        volume_completed = sum(Decimal(str(t.amount.get("value", "0"))) for t in completed) if completed else Decimal("0.0")
        by_currency.append(OverviewByCurrency(currency_code=c, total_wallets=len(wallets_c), total_balance=str(total_balance), total_transactions=len(txs_c), volume_completed=str(volume_completed)))
    return SystemFinancialOverviewResponse(total_users=total_users, total_wallets=len(wallets), total_transactions=len(transactions), wallets_by_status=wallets_by_status, overview_by_currency=by_currency, generated_at=datetime.now(timezone.utc).isoformat())