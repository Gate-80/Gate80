from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Literal, List
from datetime import datetime, timezone

router = APIRouter(tags=["user-accounts"])

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
        "currency": "USD",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
]

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# -----------------------------
# Schemas
# -----------------------------
class UserProfileResponse(BaseModel):
    id: str
    full_name: str = Field(min_length=3, max_length=60)
    email: str
    phone: str = Field(max_length=20)
    city: str
    is_verified: bool
    created_at: str
    updated_at: str

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=80)
    phone: Optional[str] = Field(None, min_length=8, max_length=20)
    city: Optional[str] = Field(None, min_length=2, max_length=60)

class AddBankAccountRequest(BaseModel):
    bank_name: str = Field(min_length=2, max_length=60)
    iban: str = Field(min_length=10, max_length=34)
    masked_account_number: str = Field(min_length=8, max_length=30)
    currency: Literal["SAR"] = "SAR"
    is_default: bool = False

class BankAccountResponse(BaseModel):
    id: str
    user_id: str
    bank_name: str
    iban: str = Field(min_length=10, max_length=34)
    masked_account_number: str
    currency: Literal["SAR"] = "SAR"
    is_default: bool
    created_at: str
    updated_at: str

class UpdateBankAccountRequest(BaseModel):
    bank_name: Optional[str] = Field(None, min_length=2, max_length=60)
    iban: Optional[str] = Field(None, min_length=10, max_length=34)
    is_default: Optional[bool] = None

# -----------------------------
# Endpoints
# -----------------------------

# 1) View user profile
@router.get("/users/{user_id}", response_model=UserProfileResponse)
def view_user_profile(user_id: str):
    user = T_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# 2) Update user profile (RESTful path + PATCH)
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

# 3) Create bank account for a user
@router.post("/users/{user_id}/bank-accounts", response_model=BankAccountResponse, status_code=201)
def add_bank_account(user_id: str, payload: AddBankAccountRequest):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")

    # If setting this new account as default, unset others for this user
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

# 4) View bank accounts for a user
@router.get("/users/{user_id}/bank-accounts", response_model=List[BankAccountResponse])
def view_bank_accounts(user_id: str):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")
    return [acc for acc in T_BANK_ACCOUNTS if acc["user_id"] == user_id]

# 5) Update bank account info (PATCH)
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
        acc["is_default"] = payload.is_default

    acc["updated_at"] = now_iso()
    return acc