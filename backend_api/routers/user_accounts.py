from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Optional
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
# Schemas
# ------------------------------------------------------------------
class UpdateProfileRequest(BaseModel):
    fullName: Optional[str] = Field(None, min_length=2, max_length=80)
    phone: Optional[str] = Field(None, min_length=8, max_length=20)

def get_current_user():
    return FAKE_USER

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
# 5) Update Bank Account Information
# ------------------------------------------------------------------
@router.post("/bank-accounts/update")
def update_bank_account():
    return {"message": "update bank account"}