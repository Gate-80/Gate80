
from secrets import token_urlsafe
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from decoy_api.db.database import get_wallet_db
from decoy_api.db.models import DecoyAdminSession

router = APIRouter(prefix="/admin/auth", tags=["admin-authentication"])

DECOY_ADMIN = {
    "id":       "admin_1",
    "username": "admin",
    "password": "admin123",
    "role":     "SUPER_ADMIN",
}


# ── Schema ────────────────────────────────────────────────────────────────────
class AdminSignInRequest(BaseModel):
    username: str
    password: str


# ── Shared dependency — imported by admin router ──────────────────────────────
def require_admin(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    db: Session = Depends(get_wallet_db),
) -> DecoyAdminSession:
    """
    Validates X-Admin-Token and returns the active admin session.
    Raises 401 if token is missing or invalid — identical to real backend.
    """
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Admin token required")
    session = db.query(DecoyAdminSession).filter_by(token=x_admin_token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired admin token")
    return session


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/sign-in")
def admin_sign_in(
    payload: AdminSignInRequest,
    db: Session = Depends(get_wallet_db),
):
    if payload.username != DECOY_ADMIN["username"] or payload.password != DECOY_ADMIN["password"]:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    token   = token_urlsafe(24)
    session = DecoyAdminSession(
        token=token,
        admin_id=DECOY_ADMIN["id"],
        role=DECOY_ADMIN["role"],
    )
    db.add(session)
    db.commit()

    return {
        "token":      token,
        "admin_id":   DECOY_ADMIN["id"],
        "role":       DECOY_ADMIN["role"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sign-out")
def admin_sign_out(
    admin: DecoyAdminSession = Depends(require_admin),
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    db: Session = Depends(get_wallet_db),
):
    if x_admin_token:
        session = db.query(DecoyAdminSession).filter_by(token=x_admin_token).first()
        if session:
            db.delete(session)
            db.commit()
    return {"message": "Logged out"}