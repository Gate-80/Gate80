
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from secrets import token_urlsafe
from sqlalchemy.orm import Session
import random
import string

from backend_api.db.database import get_db
from backend_api.db.models import User, UserSession, Wallet, BankAccount, WalletStatus
from backend_api.db.audit_helper import log_user_login, log_user_logout, log_failed_action

router = APIRouter(prefix="/auth", tags=["user-authentication"])

SAUDI_BANKS = [
    "Al Rajhi Bank",
    "Saudi National Bank",
    "Riyad Bank",
    "Banque Saudi Fransi",
    "Arab National Bank",
]


# -----------------------------
# Helper Functions
# -----------------------------
def generate_user_id(db: Session) -> str:
    """Generate next user ID using max + 1"""
    users = db.query(User).all()
    if not users:
        return "u_1001"
    existing_ids = [int(u.id.split("_")[1]) for u in users if u.id.startswith("u_")]
    next_id = max(existing_ids, default=1000) + 1
    return f"u_{next_id}"


def generate_wallet_id(db: Session) -> str:
    """Generate next wallet ID using max + 1"""
    wallets = db.query(Wallet).all()
    if not wallets:
        return "w_5001"
    existing_ids = [int(w.id.split("_")[1]) for w in wallets if w.id.startswith("w_")]
    next_id = max(existing_ids, default=5000) + 1
    return f"w_{next_id}"


def generate_bank_account_id(db: Session) -> str:
    """Generate next bank account ID using max + 1"""
    accounts = db.query(BankAccount).all()
    if not accounts:
        return "ba_2001"
    existing_ids = [int(a.id.split("_")[1]) for a in accounts if a.id.startswith("ba_")]
    next_id = max(existing_ids, default=2000) + 1
    return f"ba_{next_id}"


def require_user(
    x_user_token: Optional[str] = Header(default=None, alias="X-User-Token"),
    db: Session = Depends(get_db)
) -> User:
    """
    User session authentication dependency.
    Returns the authenticated User object.
    """
    if not x_user_token:
        raise HTTPException(status_code=401, detail="User token required")

    session = db.query(UserSession).filter_by(token=x_user_token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired user token")

    user = db.query(User).filter_by(id=session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# -----------------------------
# Schemas
# -----------------------------
class UserSignUpRequest(BaseModel):
    full_name: str = Field(min_length=3, max_length=60, example="Test User")
    email: EmailStr = Field(example="user@example.com")
    password: str = Field(min_length=8, max_length=80, example="password123")
    phone: str = Field(min_length=8, max_length=20, example="+9665XXXXXXX")
    city: str = Field(min_length=2, max_length=60, example="Jeddah")


class UserSignInRequest(BaseModel):
    email: EmailStr = Field(example="user@example.com")
    password: str = Field(min_length=8, max_length=80, example="password123")


class UserSessionResponse(BaseModel):
    token: str = Field(example="some_token_value")
    user_id: str = Field(example="u_1004")
    full_name: str = Field(example="Test User")
    email: str = Field(example="user@example.com")
    created_at: str = Field(example="2026-02-13T00:00:00+00:00")


class UserSignUpResponse(BaseModel):
    user_id: str = Field(example="u_1004")
    full_name: str = Field(example="Test User")
    email: str = Field(example="user@example.com")
    message: str = Field(example="User registered successfully")


class UserLogoutResponse(BaseModel):
    message: str = Field(example="Logged out successfully")


# -----------------------------
# Endpoints
# -----------------------------
@router.post("/sign-up", response_model=UserSignUpResponse, status_code=201)
def user_sign_up(payload: UserSignUpRequest, db: Session = Depends(get_db)):
    """
    Register a new user account.
    Automatically creates a wallet and bank account for the new user.
    """
    # Check if email already exists
    existing_user = db.query(User).filter_by(email=payload.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Generate new user ID
    new_user_id = generate_user_id(db)

    # Create new user
    new_user = User(
        id=new_user_id,
        full_name=payload.full_name,
        email=payload.email,
        password=payload.password,  # Note: Should be hashed in production
        phone=payload.phone,
        city=payload.city,
        is_verified=False
    )
    db.add(new_user)
    db.flush()  # flush to get the ID without committing yet

    # ── Auto-create wallet ──
    # Every new user gets an active SAR wallet with 0 balance.
    # This prevents 404s on wallet endpoints after registration.
    new_wallet = Wallet(
        id=generate_wallet_id(db),
        user_id=new_user_id,
        currency_code="SAR",
        balance="0.00",
        status=WalletStatus.ACTIVE,
    )
    db.add(new_wallet)

    # ── Auto-create bank account ──
    # Every new user gets a default bank account slot.
    # This prevents 404s on bank-account endpoints after registration.
    masked = "**** **** **** " + "".join(random.choices(string.digits, k=4))
    new_bank = BankAccount(
        id=generate_bank_account_id(db),
        user_id=new_user_id,
        bank_name=random.choice(SAUDI_BANKS),
        iban=f"SA{random.randint(10,99)}20000{''.join(random.choices(string.digits, k=15))}",
        masked_account_number=masked,
        currency="SAR",
        is_default=True,
    )
    db.add(new_bank)

    db.commit()
    db.refresh(new_user)

    return {
        "user_id": new_user.id,
        "full_name": new_user.full_name,
        "email": new_user.email,
        "message": "User registered successfully",
    }


@router.post("/sign-in", response_model=UserSessionResponse)
def user_sign_in(payload: UserSignInRequest, db: Session = Depends(get_db)):
    """
    User login - creates a session token
    """
    user = db.query(User).filter_by(email=payload.email).first()

    if not user or user.password != payload.password:
        log_failed_action(
            db=db,
            event="USER_LOGIN_FAILED",
            actor_type="USER",
            actor_id=None,
            error_message="Invalid email or password"
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = token_urlsafe(24)
    session = UserSession(token=token, user_id=user.id)
    db.add(session)
    db.commit()

    log_user_login(db=db, user_id=user.id, success=True)

    return {
        "token": token,
        "user_id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "created_at": session.created_at.isoformat(),
    }


@router.post("/sign-out", response_model=UserLogoutResponse)
def user_sign_out(
    user: User = Depends(require_user),
    x_user_token: Optional[str] = Header(default=None, alias="X-User-Token"),
    db: Session = Depends(get_db)
):
    """
    User logout - invalidates the session token
    """
    if x_user_token:
        session = db.query(UserSession).filter_by(token=x_user_token).first()
        if session:
            db.delete(session)
            db.commit()

    log_user_logout(db=db, user_id=user.id)

    return {"message": "Logged out successfully"}


@router.get("/me")
def get_current_user(user: User = Depends(require_user)):
    """
    Get current authenticated user's profile
    """
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