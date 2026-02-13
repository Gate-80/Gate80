# backend_api/routers/admin_operations.py

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field, condecimal
from typing import Optional, Literal, List, Dict, Any
from decimal import Decimal

from backend_api.db.users_store import now_iso, T_USERS
from backend_api.db.wallet_store import T_WALLETS, T_TRANSACTIONS

# Import only require_admin (no audit)
from backend_api.routers.admin_authentication import require_admin

router = APIRouter(prefix="/admin", tags=["admin-operations"])

# -----------------------------
# Schemas — Admin Operations
# -----------------------------
CurrencyCode = Literal["SAR", "USD", "EUR"]
MoneyValue = condecimal(max_digits=12, decimal_places=2)

WalletStatus = Literal["ACTIVE", "FROZEN", "CLOSED"]
TransactionType = Literal["TOPUP", "WITHDRAW", "TRANSFER_USER", "TRANSFER_BANK", "BILLPAY"]
TransactionStatus = Literal["PENDING", "COMPLETED", "FAILED", "CANCELLED"]


class AdminUserResponse(BaseModel):
    id: str = Field(example="u_1001")
    full_name: str = Field(example="Taif Alsaadi")
    email: str = Field(example="taif.alsaadi@gmail.com")
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
    status: WalletStatus = Field(example="ACTIVE")
    created_at: str
    updated_at: str


class Counterparty(BaseModel):
    kind: Literal["USER", "BANK", "CARD", "BILLER"] = Field(example="USER")
    ref: str = Field(example="u_1002")


class TransactionResponse(BaseModel):
    id: str = Field(pattern=r"^tx_\d{4,10}$", example="tx_7001")
    type: TransactionType = Field(example="TOPUP")
    status: TransactionStatus = Field(example="COMPLETED")
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
# Endpoints — Admin Operations
# -----------------------------
@router.get("/users", response_model=List[AdminUserResponse])
def admin_view_all_users(
    q: Optional[str] = Query(default=None, description="Search by name/email/city"),
    verified: Optional[bool] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: Dict[str, Any] = Depends(require_admin),
):
    """View all users with optional filtering"""
    users = list(T_USERS.values())

    if verified is not None:
        users = [u for u in users if u.get("is_verified") == verified]

    if q:
        ql = q.strip().lower()

        def matches(u: Dict[str, Any]) -> bool:
            return (
                ql in u.get("full_name", "").lower()
                or ql in u.get("email", "").lower()
                or ql in u.get("city", "").lower()
            )

        users = [u for u in users if matches(u)]

    users.sort(key=lambda x: x["created_at"], reverse=True)
    return users[offset : offset + limit]


@router.get("/wallets", response_model=List[WalletResponse])
def admin_view_all_wallets(
    currency: Optional[CurrencyCode] = Query(default=None),
    status: Optional[WalletStatus] = Query(default=None),
    user_id: Optional[str] = Query(default=None, description="Filter wallets by user_id"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: Dict[str, Any] = Depends(require_admin),
):
    """View all wallets with optional filtering"""
    wallets = list(T_WALLETS.values())

    if currency:
        wallets = [w for w in wallets if w["currency_code"] == currency]
    if status:
        wallets = [w for w in wallets if w["status"] == status]
    if user_id:
        wallets = [w for w in wallets if w["user_id"] == user_id]

    wallets.sort(key=lambda x: x["updated_at"], reverse=True)
    return wallets[offset : offset + limit]


@router.get("/transactions", response_model=List[TransactionResponse])
def admin_view_all_transactions(
    status: Optional[TransactionStatus] = Query(default=None),
    tx_type: Optional[TransactionType] = Query(default=None, alias="type"),
    user_id: Optional[str] = Query(default=None),
    wallet_id: Optional[str] = Query(default=None),
    currency: Optional[CurrencyCode] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: Dict[str, Any] = Depends(require_admin),
):
    """View all transactions with optional filtering"""
    txs = list(T_TRANSACTIONS)

    if status:
        txs = [t for t in txs if t["status"] == status]
    if tx_type:
        txs = [t for t in txs if t["type"] == tx_type]
    if user_id:
        txs = [t for t in txs if t["user_id"] == user_id]
    if wallet_id:
        txs = [t for t in txs if t["wallet_id"] == wallet_id]
    if currency:
        txs = [t for t in txs if t["amount"]["currency_code"] == currency]

    txs.sort(key=lambda x: x["created_at"], reverse=True)
    return txs[offset : offset + limit]


@router.get("/overview/financial", response_model=SystemFinancialOverviewResponse)
def admin_view_system_financial_overview(admin: Dict[str, Any] = Depends(require_admin)):
    """View system-wide financial overview with aggregated statistics"""
    total_users = len(T_USERS)
    wallets = list(T_WALLETS.values())
    txs = list(T_TRANSACTIONS)

    wallets_by_status: Dict[str, int] = {}
    for w in wallets:
        wallets_by_status[w["status"]] = wallets_by_status.get(w["status"], 0) + 1

    currencies = sorted({w["currency_code"] for w in wallets} | {t["amount"]["currency_code"] for t in txs})
    by_currency: List[OverviewByCurrency] = []

    for c in currencies:
        wallets_c = [w for w in wallets if w["currency_code"] == c]
        txs_c = [t for t in txs if t["amount"]["currency_code"] == c]

        # Use Decimal for accurate money calculations
        total_balance = sum(Decimal(str(w["balance"])) for w in wallets_c) if wallets_c else Decimal("0.0")

        completed = [t for t in txs_c if t["status"] == "COMPLETED"]
        volume_completed = sum(Decimal(str(t["amount"]["value"])) for t in completed) if completed else Decimal("0.0")

        by_currency.append(
            OverviewByCurrency(
                currency_code=c,
                total_wallets=len(wallets_c),
                total_balance=str(total_balance),
                total_transactions=len(txs_c),
                volume_completed=str(volume_completed),
            )
        )

    return SystemFinancialOverviewResponse(
        total_users=total_users,
        total_wallets=len(wallets),
        total_transactions=len(txs),
        wallets_by_status=wallets_by_status,
        overview_by_currency=by_currency,
        generated_at=now_iso(),
    )