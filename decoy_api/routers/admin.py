
from decimal import Decimal
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from decoy_api.db.database import get_wallet_db
from decoy_api.db.models import (
    DecoyUser, DecoyWallet, DecoyTransaction, DecoyAdminSession
)
from decoy_api.routers.admin_auth import require_admin

router = APIRouter(prefix="/admin", tags=["admin-operations"])


@router.get("/users")
def admin_view_all_users(
    q:        Optional[str]  = Query(default=None),
    verified: Optional[bool] = Query(default=None),
    limit:    int            = Query(default=50, ge=1, le=200),
    offset:   int            = Query(default=0,  ge=0),
    admin: DecoyAdminSession = Depends(require_admin),
    db: Session = Depends(get_wallet_db),
):
    query = db.query(DecoyUser)
    if verified is not None:
        query = query.filter_by(is_verified=verified)
    if q:
        search = f"%{q.strip().lower()}%"
        query = query.filter(
            (DecoyUser.full_name.ilike(search)) |
            (DecoyUser.email.ilike(search)) |
            (DecoyUser.city.ilike(search))
        )
    users = query.order_by(DecoyUser.created_at.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id":          u.id,
            "full_name":   u.full_name,
            "email":       u.email,
            "phone":       u.phone,
            "city":        u.city,
            "is_verified": u.is_verified,
            "created_at":  u.created_at.isoformat(),
            "updated_at":  u.updated_at.isoformat(),
        }
        for u in users
    ]


@router.get("/wallets")
def admin_view_all_wallets(
    status:  Optional[str] = Query(default=None),
    user_id: Optional[str] = Query(default=None),
    limit:   int           = Query(default=50, ge=1, le=200),
    offset:  int           = Query(default=0,  ge=0),
    admin: DecoyAdminSession = Depends(require_admin),
    db: Session = Depends(get_wallet_db),
):
    query = db.query(DecoyWallet)
    if status:
        query = query.filter_by(status=status)
    if user_id:
        query = query.filter_by(user_id=user_id)
    wallets = query.offset(offset).limit(limit).all()
    return [
        {
            "id":            w.id,
            "user_id":       w.user_id,
            "currency_code": w.currency_code,
            "balance":       w.balance,
            "status":        w.status.value if hasattr(w.status, "value") else w.status,
            "created_at":    w.created_at.isoformat(),
            "updated_at":    w.updated_at.isoformat(),
        }
        for w in wallets
    ]


@router.get("/transactions")
def admin_view_all_transactions(
    status:    Optional[str] = Query(default=None),
    tx_type:   Optional[str] = Query(default=None, alias="type"),
    user_id:   Optional[str] = Query(default=None),
    wallet_id: Optional[str] = Query(default=None),
    limit:     int           = Query(default=50, ge=1, le=200),
    offset:    int           = Query(default=0,  ge=0),
    admin: DecoyAdminSession = Depends(require_admin),
    db: Session = Depends(get_wallet_db),
):
    query = db.query(DecoyTransaction)
    if status:
        query = query.filter_by(status=status)
    if tx_type:
        query = query.filter_by(type=tx_type)
    if user_id:
        query = query.filter_by(user_id=user_id)
    if wallet_id:
        query = query.filter_by(wallet_id=wallet_id)
    txs = query.order_by(DecoyTransaction.created_at.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id":           t.id,
            "type":         t.type.value if hasattr(t.type, "value") else t.type,
            "status":       t.status.value if hasattr(t.status, "value") else t.status,
            "amount":       t.amount,
            "wallet_id":    t.wallet_id,
            "user_id":      t.user_id,
            "counterparty": t.counterparty,
            "description":  t.description,
            "created_at":   t.created_at.isoformat(),
            "updated_at":   t.updated_at.isoformat(),
        }
        for t in txs
    ]


@router.get("/overview/financial")
def admin_financial_overview(
    admin: DecoyAdminSession = Depends(require_admin),
    db: Session = Depends(get_wallet_db),
):
    users   = db.query(DecoyUser).all()
    wallets = db.query(DecoyWallet).all()
    txs     = db.query(DecoyTransaction).all()

    wallets_by_status = {}
    for w in wallets:
        key = w.status.value if hasattr(w.status, "value") else w.status
        wallets_by_status[key] = wallets_by_status.get(key, 0) + 1

    total_balance = sum(Decimal(str(w.balance)) for w in wallets)
    completed     = [
        t for t in txs
        if (t.status.value if hasattr(t.status, "value") else t.status) == "COMPLETED"
    ]
    volume = sum(Decimal(str(t.amount.get("value", "0"))) for t in completed)

    return {
        "total_users":        len(users),
        "total_wallets":      len(wallets),
        "total_transactions": len(txs),
        "wallets_by_status":  wallets_by_status,
        "overview_by_currency": [
            {
                "currency_code":      "SAR",
                "total_wallets":      len(wallets),
                "total_balance":      str(total_balance),
                "total_transactions": len(txs),
                "volume_completed":   str(volume),
            }
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }