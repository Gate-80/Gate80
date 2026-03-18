from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from secrets import token_urlsafe
import uuid
import random
import string
import logging

router = APIRouter()

logging.basicConfig(filename="decoy_auth.log", level=logging.INFO)

# -----------------------------
# Fake schemas
# -----------------------------
class UserSignUpRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    phone: str
    city: str


class UserSignInRequest(BaseModel):
    email: EmailStr
    password: str


# -----------------------------
# Fake helpers
# -----------------------------
SAUDI_BANKS = [
    "Al Rajhi Bank",
    "SNB",
    "Riyad Bank",
    "Banque Saudi Fransi",
    "Arab National Bank"
]

# simple in-memory decoy sessions
DECOY_SESSIONS = {}

def generate_user_id() -> str:
    return f"u_{random.randint(1000, 9999)}"

def fake_user_from_email(email: str):
    user_id = generate_user_id()
    now = datetime.now().isoformat()
    return {
        "id": user_id,
        "full_name": "Demo User",
        "email": email,
        "phone": "+9665" + "".join(random.choices(string.digits, k=8)),
        "city": random.choice(["Riyadh", "Jeddah", "Dammam"]),
        "is_verified": random.choice([True, False]),
        "created_at": now,
        "updated_at": now,
    }


# -----------------------------
# Decoy endpoints
# -----------------------------
@router.post("/sign-up", status_code=201)
def user_sign_up(payload: UserSignUpRequest):
    """
    Register a new user account.
    Decoy version: returns believable success response only.
    """
    new_user_id = generate_user_id()

    logging.info(f"[DECOY] sign-up attempt email={payload.email} user_id={new_user_id}")

    return {
        "user_id": new_user_id,
        "full_name": payload.full_name,
        "email": payload.email,
        "message": "User registered successfully",
    }


@router.post("/sign-in")
def user_sign_in(payload: UserSignInRequest):
    """
    User login - decoy session token creation
    """
    # decoy failure path for realism
    if "invalid" in payload.email.lower() or payload.password.strip() == "":
        logging.info(f"[DECOY] sign-in failed email={payload.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = fake_user_from_email(payload.email)
    token = token_urlsafe(24)
    created_at = datetime.now().isoformat()

    DECOY_SESSIONS[token] = {
        "user_id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "phone": user["phone"],
        "city": user["city"],
        "is_verified": user["is_verified"],
        "created_at": user["created_at"],
        "updated_at": user["updated_at"],
        "session_created_at": created_at,
    }

    logging.info(f"[DECOY] sign-in success email={payload.email} token={token[:8]}...")

    return {
        "token": token,
        "user_id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "created_at": created_at,
    }


@router.post("/sign-out")
def user_sign_out(x_user_token: Optional[str] = Header(default=None, alias="X-User-Token")):
    """
    User logout - decoy token invalidation
    """
    if x_user_token and x_user_token in DECOY_SESSIONS:
        session = DECOY_SESSIONS.pop(x_user_token)
        logging.info(f"[DECOY] sign-out user_id={session['user_id']}")
    else:
        logging.info("[DECOY] sign-out attempted with missing/unknown token")

    return {"message": "Logged out successfully"}


@router.get("/me")
def get_current_user(x_user_token: Optional[str] = Header(default=None, alias="X-User-Token")):
    """
    Get current authenticated user's profile
    """
    if not x_user_token or x_user_token not in DECOY_SESSIONS:
        logging.info("[DECOY] /me access denied due to invalid token")
        raise HTTPException(status_code=401, detail="Unauthorized")

    session = DECOY_SESSIONS[x_user_token]

    logging.info(f"[DECOY] /me accessed user_id={session['user_id']}")

    return {
        "id": session["user_id"],
        "full_name": session["full_name"],
        "email": session["email"],
        "phone": session["phone"],
        "city": session["city"],
        "is_verified": session["is_verified"],
        "created_at": session["created_at"],
        "updated_at": datetime.now().isoformat(),
    }