# backend_api/routers/user_authentication.py

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any
from secrets import token_urlsafe

from backend_api.db.users_store import now_iso, T_USERS

router = APIRouter(prefix="/auth", tags=["user-authentication"])

# In-memory session storage (similar to admin sessions)
T_USER_SESSIONS: Dict[str, Dict[str, Any]] = {}

# -----------------------------
# Helper Functions
# -----------------------------
def generate_user_id() -> str:
    """Generate next user ID using max + 1"""
    existing_ids = [int(u["id"].split("_")[1]) for u in T_USERS.values() if u["id"].startswith("u_")]
    next_id = max(existing_ids, default=1000) + 1
    return f"u_{next_id}"


def require_user(x_user_token: Optional[str] = Header(default=None, alias="X-User-Token")) -> Dict[str, Any]:
    """
    User session authentication:
    - User logs in -> receives token
    - Client sends `X-User-Token` for protected routes
    - Token maps to a session in T_USER_SESSIONS
    """
    if not x_user_token:
        raise HTTPException(status_code=401, detail="User token required")

    session = T_USER_SESSIONS.get(x_user_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired user token")

    user = T_USERS.get(session["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# -----------------------------
# Schemas
# -----------------------------
class UserSignUpRequest(BaseModel):
    full_name: str = Field(min_length=3, max_length=60, example="Taif Alsaadi")
    email: EmailStr = Field(example="taif.alsaadi@gmail.com")
    password: str = Field(min_length=8, max_length=80, example="SecurePass123!")
    phone: str = Field(min_length=8, max_length=20, example="+9665XXXXXXX")
    city: str = Field(min_length=2, max_length=60, example="Jeddah")


class UserSignInRequest(BaseModel):
    email: EmailStr = Field(example="taif.alsaadi@gmail.com")
    password: str = Field(min_length=8, max_length=80, example="SecurePass123!")


class UserSessionResponse(BaseModel):
    token: str = Field(example="some_token_value")
    user_id: str = Field(example="u_1001")
    full_name: str = Field(example="Taif Alsaadi")
    email: str = Field(example="taif.alsaadi@gmail.com")
    created_at: str = Field(example="2026-02-13T00:00:00+00:00")


class UserSignUpResponse(BaseModel):
    user_id: str = Field(example="u_1004")
    full_name: str = Field(example="Taif Alsaadi")
    email: str = Field(example="taif.alsaadi@gmail.com")
    message: str = Field(example="User registered successfully")


class UserLogoutResponse(BaseModel):
    message: str = Field(example="Logged out successfully")


# -----------------------------
# Endpoints
# -----------------------------
@router.post("/sign-up", response_model=UserSignUpResponse, status_code=201)
def user_sign_up(payload: UserSignUpRequest):
    """
    Register a new user account
    """
    # Check if email already exists
    existing_user = next((u for u in T_USERS.values() if u["email"] == payload.email), None)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Generate new user ID
    new_user_id = generate_user_id()
    now = now_iso()

    # Create new user
    new_user = {
        "id": new_user_id,
        "full_name": payload.full_name,
        "email": payload.email,
        "password": payload.password,  # Note: In production, hash this!
        "phone": payload.phone,
        "city": payload.city,
        "is_verified": False,  # New users start unverified
        "created_at": now,
        "updated_at": now,
    }

    T_USERS[new_user_id] = new_user

    return {
        "user_id": new_user_id,
        "full_name": payload.full_name,
        "email": payload.email,
        "message": "User registered successfully"
    }


@router.post("/sign-in", response_model=UserSessionResponse)
def user_sign_in(payload: UserSignInRequest):
    """
    User login - creates a session token
    """
    # Find user by email
    user = next((u for u in T_USERS.values() if u["email"] == payload.email), None)
    
    if not user or user.get("password") != payload.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Generate session token
    token = token_urlsafe(24)
    session = {
        "token": token,
        "user_id": user["id"],
        "created_at": now_iso(),
    }
    T_USER_SESSIONS[token] = session

    return {
        "token": token,
        "user_id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "created_at": session["created_at"],
    }


@router.post("/sign-out", response_model=UserLogoutResponse)
def user_sign_out(
    user: Dict[str, Any] = Depends(require_user),
    x_user_token: Optional[str] = Header(default=None, alias="X-User-Token")
):
    """
    User logout - invalidates the session token
    """
    # Remove session token
    if x_user_token in T_USER_SESSIONS:
        del T_USER_SESSIONS[x_user_token]
    
    return {"message": "Logged out successfully"}


@router.get("/me")
def get_current_user(user: Dict[str, Any] = Depends(require_user)):
    """
    Get current authenticated user's profile
    """
    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "phone": user["phone"],
        "city": user["city"],
        "is_verified": user["is_verified"],
        "created_at": user["created_at"],
        "updated_at": user["updated_at"],
    }