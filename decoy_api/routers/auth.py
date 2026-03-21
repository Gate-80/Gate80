
from secrets import token_urlsafe
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from decoy_api.db.database import get_wallet_db
from decoy_api.db.models import DecoyUser, DecoyUserSession, DecoyWallet, WalletStatus

router = APIRouter(prefix="/auth", tags=["user-authentication"])


# ── Schemas ───────────────────────────────────────────────────────────────────
class SignUpRequest(BaseModel):
    full_name: str
    email:     EmailStr
    password:  str
    phone:     str
    city:      str


class SignInRequest(BaseModel):
    email:    EmailStr
    password: str


# ── Shared dependency — imported by other routers ─────────────────────────────
def require_user(
    x_user_token: Optional[str] = Header(default=None, alias="X-User-Token"),
    db: Session = Depends(get_wallet_db),
) -> DecoyUser:
    """
    Validates X-User-Token and returns the authenticated DecoyUser.
    Raises 401 if token is missing or invalid — identical to real backend.
    """
    if not x_user_token:
        raise HTTPException(status_code=401, detail="User token required")
    session = db.query(DecoyUserSession).filter_by(token=x_user_token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired user token")
    user = db.query(DecoyUser).filter_by(id=session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ── Helpers ───────────────────────────────────────────────────────────────────
def _next_user_id(db: Session) -> str:
    users = db.query(DecoyUser).all()
    if not users:
        return "u_2001"
    ids = [int(u.id.split("_")[1]) for u in users if u.id.startswith("u_")]
    return f"u_{max(ids) + 1}"


def _next_wallet_id(db: Session) -> str:
    wallets = db.query(DecoyWallet).all()
    if not wallets:
        return "w_6001"
    ids = [int(w.id.split("_")[1]) for w in wallets if w.id.startswith("w_")]
    return f"w_{max(ids) + 1}"


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/sign-up", status_code=201)
def sign_up(payload: SignUpRequest, db: Session = Depends(get_wallet_db)):
    if db.query(DecoyUser).filter_by(email=payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_id = _next_user_id(db)
    user = DecoyUser(
        id=new_id,
        full_name=payload.full_name,
        email=payload.email,
        password=payload.password,
        phone=payload.phone,
        city=payload.city,
        is_verified=False,
    )
    db.add(user)

    wallet = DecoyWallet(
        id=_next_wallet_id(db),
        user_id=new_id,
        currency_code="SAR",
        balance="0.00",
        status=WalletStatus.ACTIVE,
    )
    db.add(wallet)
    db.commit()

    return {
        "user_id":   new_id,
        "full_name": payload.full_name,
        "email":     payload.email,
        "message":   "User registered successfully",
    }


@router.post("/sign-in")
def sign_in(payload: SignInRequest, db: Session = Depends(get_wallet_db)):
    user = db.query(DecoyUser).filter_by(email=payload.email).first()
    if not user or user.password != payload.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token   = token_urlsafe(24)
    session = DecoyUserSession(token=token, user_id=user.id)
    db.add(session)
    db.commit()

    return {
        "token":      token,
        "user_id":    user.id,
        "full_name":  user.full_name,
        "email":      user.email,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sign-out")
def sign_out(
    user: DecoyUser = Depends(require_user),
    x_user_token: Optional[str] = Header(default=None, alias="X-User-Token"),
    db: Session = Depends(get_wallet_db),
):
    if x_user_token:
        session = db.query(DecoyUserSession).filter_by(token=x_user_token).first()
        if session:
            db.delete(session)
            db.commit()
    return {"message": "Logged out successfully"}


@router.get("/me")
def get_me(user: DecoyUser = Depends(require_user)):
    return {
        "id":          user.id,
        "full_name":   user.full_name,
        "email":       user.email,
        "phone":       user.phone,
        "city":        user.city,
        "is_verified": user.is_verified,
        "created_at":  user.created_at.isoformat(),
        "updated_at":  user.updated_at.isoformat(),
    }