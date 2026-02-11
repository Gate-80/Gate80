from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, condecimal
from typing import Optional, Literal, List
from datetime import datetime, timezone

router = APIRouter(tags=["user-accounts"])

# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# -----------------------------
# In-memory data (prototype)
# -----------------------------
T_USERS = {
    "u_1001": {
        "id": "u_1001",
        "full_name": "Taif Alsaadi",
        "email": "taif.alsaadi@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Jeddah",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    "u_1002": {
        "id": "u_1002",
        "full_name": "Hanan Alharbi",
        "email": "hanan.alharbi@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Riyadh",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    "u_1003": {
        "id": "u_1003",
        "full_name": "Queen RAMA",
        "email": "queenrama@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Los Angeles",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
}

T_BANK_ACCOUNTS = [
    {
        "id": "ba_2001",
        "user_id": "u_1001",
        "bank_name": "Al Rajhi Bank",
        "iban": "SA4420000001234567891234",
        "masked_account_number": "**** **** **** 3192",
        "currency": "SAR",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    {
        "id": "ba_2002",
        "user_id": "u_1002",
        "bank_name": "Saudi National Bank",
        "iban": "SA1520000009876543219876",
        "masked_account_number": "**** **** **** 7741",
        "currency": "SAR",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    {
        "id": "ba_2003",
        "user_id": "u_1003",
        "bank_name": "American Bank",
        "iban": "SA1520000009876543219821",
        "masked_account_number": "**** **** **** 9821",
        "currency": "USD",  # لو تبين SAR فقط غيريها
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
]

T_PAYMENTS = [
    {
        "id": "pay_3001",
        "user_id": "u_1001",
        "status": "COMPLETED",
        "amount": {"currency_code": "SAR", "value": "120.00"},
        "merchant": {"name": "RASD Store", "merchant_id": "m_9001"},
        "description": "Order #A1001",
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    {
        "id": "pay_3002",
        "user_id": "u_1001",
        "status": "AUTHORIZED",
        "amount": {"currency_code": "SAR", "value": "55.50"},
        "merchant": {"name": "Coffee Spot", "merchant_id": "m_9002"},
        "description": "Coffee beans",
        "created_at": "2026-02-09T10:12:05+00:00",
        "updated_at": "2026-02-09T10:12:05+00:00",
    },
    {
        "id": "pay_3003",
        "user_id": "u_1002",
        "status": "FAILED",
        "amount": {"currency_code": "SAR", "value": "999.00"},
        "merchant": {"name": "ElectroMart", "merchant_id": "m_9010"},
        "description": "Attempted purchase",
        "created_at": "2026-02-10T08:01:00+00:00",
        "updated_at": "2026-02-10T08:01:00+00:00",
    },
]

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
    value: MoneyValue = Field(example="120.00")  # مهم: type صحيح

class Merchant(BaseModel):
    name: str = Field(min_length=2, max_length=60, example="RASD Store")
    merchant_id: str = Field(min_length=3, max_length=30, example="m_9001")

class PaymentSummaryResponse(BaseModel):
    id: str = Field(
        pattern=r"^pay_\d{4,10}$",
        example="pay_3001",
        description="Unique payment identifier",
    )
    user_id: str = Field(
        pattern=r"^u_\d{4,10}$",
        example="u_1001",
        description="User identifier",
    )
    status: PaymentStatus = Field(example="COMPLETED")
    amount: Money
    merchant: Merchant
    description: Optional[str] = Field(default=None, max_length=120, example="Order #A1001")
    created_at: str = Field(example="2026-02-08T21:56:51+00:00")
    updated_at: str = Field(example="2026-02-08T21:56:51+00:00")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "pay_3001",
                "user_id": "u_1001",
                "status": "COMPLETED",
                "amount": {"currency_code": "SAR", "value": "120.00"},
                "merchant": {"name": "RASD Store", "merchant_id": "m_9001"},
                "description": "Order #A1001",
                "created_at": "2026-02-08T21:56:51+00:00",
                "updated_at": "2026-02-08T21:56:51+00:00",
            }
        }

# -----------------------------
# Endpoints — Users / Bank
# -----------------------------
@router.get("/users/{user_id}", response_model=UserProfileResponse)
def view_user_profile(user_id: str):
    user = T_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.patch("/users/{user_id}", response_model=UserProfileResponse)
def update_user_profile(user_id: str, payload: UpdateProfileRequest):
    user = T_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.full_name is not None:
        user["full_name"] = payload.full_name
    if payload.phone is not None:
        user["phone"] = payload.phone
    if payload.city is not None:
        user["city"] = payload.city

    user["updated_at"] = now_iso()
    return user

@router.post("/users/{user_id}/bank-accounts", response_model=BankAccountResponse, status_code=201)
def add_bank_account(user_id: str, payload: AddBankAccountRequest):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.is_default:
        for acc in T_BANK_ACCOUNTS:
            if acc["user_id"] == user_id:
                acc["is_default"] = False
                acc["updated_at"] = now_iso()

    new_id = f"ba_{2000 + len(T_BANK_ACCOUNTS) + 1}"
    now = now_iso()

    new_acc = {
        "id": new_id,
        "user_id": user_id,
        "bank_name": payload.bank_name,
        "iban": payload.iban,
        "masked_account_number": payload.masked_account_number,
        "currency": payload.currency,
        "is_default": payload.is_default,
        "created_at": now,
        "updated_at": now,
    }

    T_BANK_ACCOUNTS.append(new_acc)
    return new_acc

@router.get("/users/{user_id}/bank-accounts", response_model=List[BankAccountResponse])
def view_bank_accounts(user_id: str):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")
    return [acc for acc in T_BANK_ACCOUNTS if acc["user_id"] == user_id]

@router.patch("/bank-accounts/{bank_account_id}", response_model=BankAccountResponse)
def update_bank_account(bank_account_id: str, payload: UpdateBankAccountRequest):
    acc = next((a for a in T_BANK_ACCOUNTS if a["id"] == bank_account_id), None)
    if not acc:
        raise HTTPException(status_code=404, detail="Bank account not found")

    if payload.bank_name is not None:
        acc["bank_name"] = payload.bank_name
    if payload.iban is not None:
        acc["iban"] = payload.iban
    if payload.is_default is not None:
          # if setting this account as default, unset others for same user
        if payload.is_default is True:
            for other in T_BANK_ACCOUNTS:
                if other["user_id"] == acc["user_id"] and other["id"] != acc["id"]:
                    other["is_default"] = False
                    other["updated_at"] = now_iso()

        acc["is_default"] = payload.is_default

    acc["updated_at"] = now_iso()
    return acc

# -----------------------------
# Endpoints — Payments
# -----------------------------
@router.get("/users/{user_id}/payments", response_model=List[PaymentSummaryResponse])
def view_user_payments(
    user_id: str,
    status: Optional[PaymentStatus] = Query(default=None, description="Filter by payment status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")

    user_payments = [p for p in T_PAYMENTS if p["user_id"] == user_id]

    if status:
        user_payments = [p for p in user_payments if p["status"] == status]

    user_payments.sort(key=lambda x: x["created_at"], reverse=True)
    return user_payments[offset : offset + limit]

@router.get("/payments/{payment_id}", response_model=PaymentSummaryResponse)
def view_payment_details(payment_id: str):
    payment = next((p for p in T_PAYMENTS if p["id"] == payment_id), None)
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payment