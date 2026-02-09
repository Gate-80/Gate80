from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Literal

from datetime import datetime

router = APIRouter(prefix="", tags=["user-accounts"])

# ------------------------------------------------------------------
# Fake in-memory storage (for now)
# ------------------------------------------------------------------
FAKE_USER = {
    "id": "u_12345",
    "email": "user@example.com",
    "fullName": "Wed Abdullah",
    "phone": "+966500000000",
    "status": "ACTIVE",
    "createdAt": "2026-02-01T10:00:00Z",
    "updatedAt": "2026-02-08T10:00:00Z"
}

# ------------------------------------------------------------------
# Fake data for view endpoints
# ------------------------------------------------------------------
T_USERS = {
    "u_1001": {
        "id": "u_1001",
        "full_name": "Taif Alsaadi",
        "email": "taif.alsaadi@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Jeddah",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00"
    },
    "u_1002": {
        "id": "u_1002",
        "full_name": "Hanan Alharbi",
        "email": "hanan.alharbi@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Riyadh",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00"
    }
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
        "created_at": "2026-02-08T21:56:51+00:00"
    },
    {
        "id": "ba_2002",
        "user_id": "u_1002",
        "bank_name": "Saudi National Bank",
        "iban": "SA1520000009876543219876",
        "masked_account_number": "**** **** **** 7741",
        "currency": "SAR",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00"
    }
]



# ------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------
class UpdateProfileRequest(BaseModel):
    fullName: Optional[str] = Field(None, min_length=2, max_length=80)
    phone: Optional[str] = Field(None, min_length=8, max_length=20)

def get_current_user():
    return FAKE_USER

# ------------------------------------------------------------------
# T Schemas
# ------------------------------------------------------------------
class UserProfileResponse(BaseModel):
    id: str
    full_name: str = Field(min_length=3, max_length=60)
    email: str
    phone: str = Field(max_length=20)
    city: str
    is_verified: bool
    created_at: str

class BankAccountResponse(BaseModel):
    id: str
    user_id: str
    bank_name: str
    iban: str = Field(min_length=10, max_length=34)
    masked_account_number: str
    currency: Literal["SAR"] = "SAR"
    is_default: bool = True
    created_at: str



# ------------------------------------------------------------------
# 1) View user profile
# ------------------------------------------------------------------
@router.get("/users/{user_id}", response_model=UserProfileResponse)
def view_user_profile(user_id: str):
    user = T_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ------------------------------------------------------------------
# 2) Update user profile
# ------------------------------------------------------------------
@router.patch("/users/update-users")
def update_profile(
    payload: UpdateProfileRequest,
    user=Depends(get_current_user)
):
    if payload.fullName is not None:
        user["fullName"] = payload.fullName
    if payload.phone is not None:
        user["phone"] = payload.phone

    user["updatedAt"] = datetime.utcnow().isoformat() + "Z"
    return user


# ------------------------------------------------------------------
# 4) View bank account information
# ------------------------------------------------------------------
@router.get("/users/{user_id}/bank-accounts", response_model=list[BankAccountResponse])
def view_bank_accounts(user_id: str):
    if user_id not in T_USERS:
        raise HTTPException(status_code=404, detail="User not found")
    return [acc for acc in T_BANK_ACCOUNTS if acc["user_id"] == user_id]


# ------------------------------------------------------------------
# 5) Update Bank Account Information
# ------------------------------------------------------------------
@router.post("/bank-accounts/update")
def update_bank_account():
    return {"message": "update bank account"}