# backend_api/routers/admin_authentication.py

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from secrets import token_urlsafe

from backend_api.db.users_store import now_iso
from backend_api.db.admin_store import T_ADMINS, T_ADMIN_SESSIONS, T_ADMIN_AUDIT_LOGS

router = APIRouter(prefix="/admin/auth", tags=["admin-authentication"])

# -----------------------------
# Helpers — Admin Auth + Audit
# -----------------------------
def audit(event: str, admin_id: Optional[str], meta: Optional[Dict[str, Any]] = None) -> None:
    """Helper function to create audit log entries"""
    existing_ids = [int(log["id"].split("_")[1]) for log in T_ADMIN_AUDIT_LOGS if log["id"].startswith("aud_")]
    next_id = max(existing_ids, default=0) + 1
    
    T_ADMIN_AUDIT_LOGS.append(
        {
            "id": f"aud_{next_id:04d}",
            "event": event,
            "admin_id": admin_id,
            "meta": meta or {},
            "created_at": now_iso(),
        }
    )


def require_admin(x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token")) -> Dict[str, Any]:
    """
    Prototype session auth:
    - Admin logs in -> receives token
    - Client sends `X-Admin-Token` for admin routes
    - Token maps to a session in T_ADMIN_SESSIONS
    """
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Admin token required")

    session = T_ADMIN_SESSIONS.get(x_admin_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired admin token")

    admin = T_ADMINS.get(session["admin_id"])
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
def admin_sign_in(payload: AdminLoginRequest):
    """Admin login endpoint - creates a session token"""
    admin = next((a for a in T_ADMINS.values() if a["username"] == payload.username), None)
    if not admin or admin.get("password") != payload.password:
        audit("ADMIN_LOGIN_FAILED", admin_id=None, meta={"username": payload.username})
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    token = token_urlsafe(24)
    session = {
        "token": token,
        "admin_id": admin["id"],
        "role": admin.get("role", "ADMIN"),
        "created_at": now_iso(),
    }
    T_ADMIN_SESSIONS[token] = session
    audit("ADMIN_LOGIN_SUCCESS", admin_id=admin["id"], meta={"role": session["role"]})
    return session


@router.post("/sign-out", response_model=AdminLogoutResponse)
def admin_sign_out(
    admin: Dict[str, Any] = Depends(require_admin),
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token")
):
    """Admin logout endpoint - invalidates the session token"""
    # require_admin already validated token
    if x_admin_token in T_ADMIN_SESSIONS:
        del T_ADMIN_SESSIONS[x_admin_token]
    audit("ADMIN_LOGOUT", admin_id=admin["id"])
    return {"message": "Logged out"}