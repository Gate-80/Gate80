
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from decoy_api.db.database import get_wallet_db
from decoy_api.db.models import DecoyUser, DecoyBankAccount, DecoyPayment
from decoy_api.routers.auth import require_user

router = APIRouter(tags=["user-accounts"])


# ── Schemas ───────────────────────────────────────────────────────────────────
class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None
    phone:     Optional[str] = None
    city:      Optional[str] = None


class AddBankAccountRequest(BaseModel):
    bank_name:             str
    iban:                  str
    masked_account_number: str
    currency:              str  = "SAR"
    is_default:            bool = False


class UpdateBankAccountRequest(BaseModel):
    bank_name:  Optional[str]  = None
    iban:       Optional[str]  = None
    is_default: Optional[bool] = None


# ── Helpers ───────────────────────────────────────────────────────────────────
def _get_user(db: Session, user_id: str) -> DecoyUser:
    user = db.query(DecoyUser).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def _next_bank_id(db: Session) -> str:
    accounts = db.query(DecoyBankAccount).all()
    if not accounts:
        return "ba_3001"
    ids = [int(a.id.split("_")[1]) for a in accounts if a.id.startswith("ba_")]
    return f"ba_{max(ids) + 1}"


# ── Profile ───────────────────────────────────────────────────────────────────
@router.get("/users/{user_id}")
def view_user_profile(
    user_id: str,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    target = _get_user(db, user_id)
    return {
        "id":          target.id,
        "full_name":   target.full_name,
        "email":       target.email,
        "phone":       target.phone,
        "city":        target.city,
        "is_verified": target.is_verified,
        "created_at":  target.created_at.isoformat(),
        "updated_at":  target.updated_at.isoformat(),
    }


@router.put("/users/{user_id}")
def update_user_profile(
    user_id: str,
    payload: UpdateProfileRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    target = _get_user(db, user_id)
    if payload.full_name: target.full_name = payload.full_name
    if payload.phone:     target.phone     = payload.phone
    if payload.city:      target.city      = payload.city
    db.commit()
    db.refresh(target)
    return {
        "id":          target.id,
        "full_name":   target.full_name,
        "email":       target.email,
        "phone":       target.phone,
        "city":        target.city,
        "is_verified": target.is_verified,
        "created_at":  target.created_at.isoformat(),
        "updated_at":  target.updated_at.isoformat(),
    }


# ── Bank Accounts ─────────────────────────────────────────────────────────────
@router.get("/users/{user_id}/bank-accounts")
def view_bank_accounts(
    user_id: str,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    _get_user(db, user_id)
    accounts = db.query(DecoyBankAccount).filter_by(user_id=user_id).all()
    return [
        {
            "id":                    a.id,
            "user_id":               a.user_id,
            "bank_name":             a.bank_name,
            "iban":                  a.iban,
            "masked_account_number": a.masked_account_number,
            "currency":              a.currency,
            "is_default":            a.is_default,
            "created_at":            a.created_at.isoformat(),
            "updated_at":            a.updated_at.isoformat(),
        }
        for a in accounts
    ]


@router.post("/users/{user_id}/bank-accounts", status_code=201)
def add_bank_account(
    user_id: str,
    payload: AddBankAccountRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    _get_user(db, user_id)
    if payload.is_default:
        for acc in db.query(DecoyBankAccount).filter_by(user_id=user_id).all():
            acc.is_default = False

    new_id  = _next_bank_id(db)
    account = DecoyBankAccount(
        id=new_id, user_id=user_id,
        bank_name=payload.bank_name, iban=payload.iban,
        masked_account_number=payload.masked_account_number,
        currency=payload.currency, is_default=payload.is_default,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return {
        "id":                    account.id,
        "user_id":               account.user_id,
        "bank_name":             account.bank_name,
        "iban":                  account.iban,
        "masked_account_number": account.masked_account_number,
        "currency":              account.currency,
        "is_default":            account.is_default,
        "created_at":            account.created_at.isoformat(),
        "updated_at":            account.updated_at.isoformat(),
    }


@router.put("/users/{user_id}/bank-accounts/{bank_account_id}")
def update_bank_account(
    user_id: str,
    bank_account_id: str,
    payload: UpdateBankAccountRequest,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    account = db.query(DecoyBankAccount).filter_by(id=bank_account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Bank account not found")
    if payload.bank_name:
        account.bank_name = payload.bank_name
    if payload.iban:
        account.iban = payload.iban
    if payload.is_default is True:
        for other in db.query(DecoyBankAccount).filter_by(user_id=account.user_id).all():
            if other.id != account.id:
                other.is_default = False
    if payload.is_default is not None:
        account.is_default = payload.is_default
    db.commit()
    db.refresh(account)
    return {
        "id":                    account.id,
        "user_id":               account.user_id,
        "bank_name":             account.bank_name,
        "iban":                  account.iban,
        "masked_account_number": account.masked_account_number,
        "currency":              account.currency,
        "is_default":            account.is_default,
        "created_at":            account.created_at.isoformat(),
        "updated_at":            account.updated_at.isoformat(),
    }


# ── Payments ──────────────────────────────────────────────────────────────────
@router.get("/users/{user_id}/payments")
def view_user_payments(
    user_id: str,
    status: Optional[str] = Query(default=None),
    limit:  int           = Query(default=50, ge=1, le=200),
    offset: int           = Query(default=0,  ge=0),
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    _get_user(db, user_id)
    query = db.query(DecoyPayment).filter_by(user_id=user_id)
    if status:
        query = query.filter_by(status=status)
    payments = query.order_by(DecoyPayment.created_at.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id":          p.id,
            "user_id":     p.user_id,
            "status":      p.status,
            "amount":      p.amount,
            "merchant":    p.merchant,
            "description": p.description,
            "created_at":  p.created_at.isoformat(),
            "updated_at":  p.updated_at.isoformat(),
        }
        for p in payments
    ]


@router.get("/users/{user_id}/payments/{payment_id}")
def view_payment_details(
    user_id: str,
    payment_id: str,
    user: DecoyUser = Depends(require_user),
    db: Session = Depends(get_wallet_db),
):
    payment = db.query(DecoyPayment).filter_by(id=payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    return {
        "id":          payment.id,
        "user_id":     payment.user_id,
        "status":      payment.status,
        "amount":      payment.amount,
        "merchant":    payment.merchant,
        "description": payment.description,
        "created_at":  payment.created_at.isoformat(),
        "updated_at":  payment.updated_at.isoformat(),
    }