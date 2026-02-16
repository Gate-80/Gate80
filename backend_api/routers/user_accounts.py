
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field, condecimal
from typing import Optional, Literal, List
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import User, BankAccount, Payment
from backend_api.db.audit_helper import log_bank_account_added, log_bank_account_updated, log_profile_updated

router = APIRouter()

# -----------------------------
# Schemas — Users / Bank
# -----------------------------
class UserProfileResponse(BaseModel):
    id: str = Field(example="u_1001")
    full_name: str = Field(min_length=3, max_length=60, example="Taif Alsaadi")
    email: str = Field(example="taif.alsaadi@gmail.com")
    phone: str = Field(max_length=20, example="+9665XXXXXXX")
    city: str = Field(example="Jeddah")
    is_verified: bool = Field(example=True)
    created_at: str = Field(example="2026-02-08T21:56:51+00:00")
    updated_at: str = Field(example="2026-02-08T21:56:51+00:00")

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=80, example="Taif Alsaadi")
    phone: Optional[str] = Field(None, min_length=8, max_length=20, example="+9665XXXXXXX")
    city: Optional[str] = Field(None, min_length=2, max_length=60, example="Jeddah")

BankCurrency = Literal["SAR", "USD"]  

class AddBankAccountRequest(BaseModel):
    bank_name: str = Field(min_length=2, max_length=60, example="Al Rajhi Bank")
    iban: str = Field(min_length=10, max_length=34, example="SA4420000001234567891234")
    masked_account_number: str = Field(min_length=8, max_length=30, example="**** **** **** 3192")
    currency: BankCurrency = Field(default="SAR", example="SAR")
    is_default: bool = Field(default=False, example=False)

class BankAccountResponse(BaseModel):
    id: str = Field(example="ba_2001")
    user_id: str = Field(example="u_1001")
    bank_name: str = Field(example="Al Rajhi Bank")
    iban: str = Field(min_length=10, max_length=34, example="SA4420000001234567891234")
    masked_account_number: str = Field(example="**** **** **** 3192")
    currency: BankCurrency = Field(default="SAR", example="SAR")
    is_default: bool = Field(example=True)
    created_at: str = Field(example="2026-02-08T21:56:51+00:00")
    updated_at: str = Field(example="2026-02-08T21:56:51+00:00")

class UpdateBankAccountRequest(BaseModel):
    bank_name: Optional[str] = Field(None, min_length=2, max_length=60, example="Saudi National Bank")
    iban: Optional[str] = Field(None, min_length=10, max_length=34, example="SA1520000009876543219876")
    is_default: Optional[bool] = Field(default=None, example=True)

# -----------------------------
# Schemas — Payments
# -----------------------------
CurrencyCode = Literal["SAR", "USD", "EUR"]
PaymentStatus = Literal["CREATED", "AUTHORIZED", "COMPLETED", "FAILED", "CANCELLED"]

MoneyValue = condecimal(max_digits=10, decimal_places=2)

class Money(BaseModel):
    currency_code: CurrencyCode = Field(default="SAR", example="SAR")
    value: MoneyValue = Field(example="120.00")

class Merchant(BaseModel):
    name: str = Field(min_length=2, max_length=60, example="RASD Store")
    merchant_id: str = Field(min_length=3, max_length=30, example="m_9001")

class PaymentSummaryResponse(BaseModel):
    id: str = Field(pattern=r"^pay_\d{4,10}$", example="pay_3001")
    user_id: str = Field(pattern=r"^u_\d{4,10}$", example="u_1001")
    status: PaymentStatus = Field(example="COMPLETED")
    amount: Money
    merchant: Merchant
    description: Optional[str] = Field(default=None, max_length=120, example="Order #A1001")
    created_at: str = Field(example="2026-02-08T21:56:51+00:00")
    updated_at: str = Field(example="2026-02-08T21:56:51+00:00")

# -----------------------------
# Helper Functions
# -----------------------------
def generate_bank_account_id(db: Session) -> str:
    """Generate next bank account ID"""
    accounts = db.query(BankAccount).all()
    if not accounts:
        return "ba_2001"
    
    existing_ids = [int(acc.id.split("_")[1]) for acc in accounts if acc.id.startswith("ba_")]
    next_id = max(existing_ids, default=2000) + 1
    return f"ba_{next_id}"

# -----------------------------
# Endpoints — Users / Bank
# -----------------------------
@router.get("/users/{user_id}", response_model=UserProfileResponse)
def view_user_profile(user_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "city": user.city,
        "is_verified": user.is_verified,
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
    }

@router.patch("/users/{user_id}", response_model=UserProfileResponse)
def update_user_profile(user_id: str, payload: UpdateProfileRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Track which fields changed
    fields_changed = []
    
    if payload.full_name is not None:
        user.full_name = payload.full_name
        fields_changed.append("full_name")
    if payload.phone is not None:
        user.phone = payload.phone
        fields_changed.append("phone")
    if payload.city is not None:
        user.city = payload.city
        fields_changed.append("city")

    db.commit()
    db.refresh(user)
    
    # Log profile update
    if fields_changed:
        log_profile_updated(db=db, user_id=user_id, fields_changed=fields_changed)
    
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "city": user.city,
        "is_verified": user.is_verified,
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
    }

@router.post("/users/{user_id}/bank-accounts", response_model=BankAccountResponse, status_code=201)
def add_bank_account(user_id: str, payload: AddBankAccountRequest, db: Session = Depends(get_db)):
    # Check if user exists
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # If setting as default, unset other defaults for this user
    if payload.is_default:
        user_accounts = db.query(BankAccount).filter_by(user_id=user_id).all()
        for acc in user_accounts:
            acc.is_default = False

    # Create new bank account
    new_id = generate_bank_account_id(db)
    new_account = BankAccount(
        id=new_id,
        user_id=user_id,
        bank_name=payload.bank_name,
        iban=payload.iban,
        masked_account_number=payload.masked_account_number,
        currency=payload.currency,
        is_default=payload.is_default
    )
    
    db.add(new_account)
    db.commit()
    db.refresh(new_account)
    
    # Log bank account addition
    log_bank_account_added(db=db, user_id=user_id, bank_account_id=new_id, bank_name=payload.bank_name)
    
    return {
        "id": new_account.id,
        "user_id": new_account.user_id,
        "bank_name": new_account.bank_name,
        "iban": new_account.iban,
        "masked_account_number": new_account.masked_account_number,
        "currency": new_account.currency,
        "is_default": new_account.is_default,
        "created_at": new_account.created_at.isoformat(),
        "updated_at": new_account.updated_at.isoformat(),
    }

@router.get("/users/{user_id}/bank-accounts", response_model=List[BankAccountResponse])
def view_bank_accounts(user_id: str, db: Session = Depends(get_db)):
    # Check if user exists
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    accounts = db.query(BankAccount).filter_by(user_id=user_id).all()
    
    return [
        {
            "id": acc.id,
            "user_id": acc.user_id,
            "bank_name": acc.bank_name,
            "iban": acc.iban,
            "masked_account_number": acc.masked_account_number,
            "currency": acc.currency,
            "is_default": acc.is_default,
            "created_at": acc.created_at.isoformat(),
            "updated_at": acc.updated_at.isoformat(),
        }
        for acc in accounts
    ]

@router.patch("/bank-accounts/{bank_account_id}", response_model=BankAccountResponse)
def update_bank_account(bank_account_id: str, payload: UpdateBankAccountRequest, db: Session = Depends(get_db)):
    acc = db.query(BankAccount).filter_by(id=bank_account_id).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Bank account not found")

    if payload.bank_name is not None:
        acc.bank_name = payload.bank_name
    if payload.iban is not None:
        acc.iban = payload.iban
    if payload.is_default is not None:
        # If setting as default, unset others for same user
        if payload.is_default is True:
            user_accounts = db.query(BankAccount).filter_by(user_id=acc.user_id).all()
            for other in user_accounts:
                if other.id != acc.id:
                    other.is_default = False
        
        acc.is_default = payload.is_default

    db.commit()
    db.refresh(acc)
    
    # Log bank account update
    log_bank_account_updated(db=db, user_id=acc.user_id, bank_account_id=bank_account_id)
    
    return {
        "id": acc.id,
        "user_id": acc.user_id,
        "bank_name": acc.bank_name,
        "iban": acc.iban,
        "masked_account_number": acc.masked_account_number,
        "currency": acc.currency,
        "is_default": acc.is_default,
        "created_at": acc.created_at.isoformat(),
        "updated_at": acc.updated_at.isoformat(),
    }

# -----------------------------
# Endpoints — Payments
# -----------------------------
@router.get("/users/{user_id}/payments", response_model=List[PaymentSummaryResponse])
def view_user_payments(
    user_id: str,
    status: Optional[PaymentStatus] = Query(default=None, description="Filter by payment status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    # Check if user exists
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Query payments
    query = db.query(Payment).filter_by(user_id=user_id)
    
    if status:
        query = query.filter_by(status=status)
    
    # Order by created_at descending
    query = query.order_by(Payment.created_at.desc())
    
    # Apply pagination
    payments = query.offset(offset).limit(limit).all()
    
    return [
        {
            "id": p.id,
            "user_id": p.user_id,
            "status": p.status,
            "amount": p.amount,
            "merchant": p.merchant,
            "description": p.description,
            "created_at": p.created_at.isoformat(),
            "updated_at": p.updated_at.isoformat(),
        }
        for p in payments
    ]

@router.get("/payments/{payment_id}", response_model=PaymentSummaryResponse)
def view_payment_details(payment_id: str, db: Session = Depends(get_db)):
    payment = db.query(Payment).filter_by(id=payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    return {
        "id": payment.id,
        "user_id": payment.user_id,
        "status": payment.status,
        "amount": payment.amount,
        "merchant": payment.merchant,
        "description": payment.description,
        "created_at": payment.created_at.isoformat(),
        "updated_at": payment.updated_at.isoformat(),
    }