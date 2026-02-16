
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from typing import Optional
from secrets import token_urlsafe
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import Admin, AdminSession
from backend_api.db.audit_helper import log_admin_login, log_admin_logout, log_failed_action

router = APIRouter(prefix="/admin/auth", tags=["admin-authentication"])


# -----------------------------
# Helper Functions
# -----------------------------
def require_admin(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    db: Session = Depends(get_db)
) -> Admin:
    """
    Admin session authentication dependency.
    Returns the authenticated Admin object.
    """
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Admin token required")

    # Check if session exists in database
    session = db.query(AdminSession).filter_by(token=x_admin_token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired admin token")

    # Get admin from database
    admin = db.query(Admin).filter_by(id=session.admin_id).first()
    if not admin:
        raise HTTPException(status_code=401, detail="Admin not found")

    return admin


# -----------------------------
# Schemas
# -----------------------------
class AdminLoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, example="admin")
    password: str = Field(min_length=3, max_length=80, example="admin123")


class AdminSessionResponse(BaseModel):
    token: str = Field(example="some_token_value")
    admin_id: str = Field(example="a_0001")
    role: str = Field(example="SUPER_ADMIN")
    created_at: str = Field(example="2026-02-13T00:00:00+00:00")


class AdminLogoutResponse(BaseModel):
    message: str = Field(example="Logged out")


# -----------------------------
# Endpoints
# -----------------------------
@router.post("/sign-in", response_model=AdminSessionResponse)
def admin_sign_in(payload: AdminLoginRequest, db: Session = Depends(get_db)):
    """Admin login endpoint - creates a session token"""
    # Find admin by username
    admin = db.query(Admin).filter_by(username=payload.username).first()
    
    if not admin or admin.password != payload.password:
        # Log failed login
        log_failed_action(
            db=db,
            event="ADMIN_LOGIN_FAILED",
            actor_type="ADMIN",
            actor_id=None,
            error_message=f"Invalid credentials for username: {payload.username}"
        )
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    # Generate session token
    token = token_urlsafe(24)
    session = AdminSession(
        token=token,
        admin_id=admin.id,
        role=admin.role
    )
    
    db.add(session)
    db.commit()

    # Log successful login
    log_admin_login(db=db, admin_id=admin.id, success=True)

    return {
        "token": token,
        "admin_id": admin.id,
        "role": admin.role,
        "created_at": session.created_at.isoformat(),
    }


@router.post("/sign-out", response_model=AdminLogoutResponse)
def admin_sign_out(
    admin: Admin = Depends(require_admin),
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
    db: Session = Depends(get_db)
):
    """Admin logout endpoint - invalidates the session token"""
    # Remove session from database
    if x_admin_token:
        session = db.query(AdminSession).filter_by(token=x_admin_token).first()
        if session:
            db.delete(session)
            db.commit()
    
    # Log logout
    log_admin_logout(db=db, admin_id=admin.id)
    
    return {"message": "Logged out"}