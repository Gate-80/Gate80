
"""
Audit logging helper functions.
Use these to log important events throughout the application.
auditing state-changing actions (creates, updates, deletes, money movements) not read-only actions
"""

from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from backend_api.db.models import AuditLog


def generate_audit_id(db: Session) -> str:
    """Generate next audit log ID"""
    # Get existing IDs and find max
    existing_logs = db.query(AuditLog).all()
    if not existing_logs:
        return "aud_0001"
    
    existing_ids = [int(log.id.split("_")[1]) for log in existing_logs if log.id.startswith("aud_")]
    next_id = max(existing_ids, default=0) + 1
    return f"aud_{next_id:04d}"


def log_audit(
    db: Session,
    event: str,
    actor_type: str,  # "USER" or "ADMIN"
    actor_id: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action_result: str = "SUCCESS",
    ip_address: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Log an audit event to the database.
    
    Args:
        db: Database session
        event: Event name (e.g., "USER_TRANSFER", "ADMIN_VIEW_USERS")
        actor_type: "USER" or "ADMIN"
        actor_id: ID of user or admin performing action
        resource_type: Type of resource affected (e.g., "WALLET", "TRANSACTION")
        resource_id: ID of affected resource
        action_result: "SUCCESS", "FAILED", or "UNAUTHORIZED"
        ip_address: Client IP address (optional)
        meta: Additional context as dictionary
    
    Returns:
        Created AuditLog object
    
    Example:
        log_audit(
            db=db,
            event="USER_TRANSFER",
            actor_type="USER",
            actor_id="u_1001",
            resource_type="WALLET",
            resource_id="w_5001",
            action_result="SUCCESS",
            meta={"amount": "50.00", "to_user": "u_1002"}
        )
    """
    audit_log = AuditLog(
        id=generate_audit_id(db),
        event=event,
        actor_type=actor_type,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action_result=action_result,
        ip_address=ip_address,
        meta=meta or {}
    )
    
    db.add(audit_log)
    db.commit()
    return audit_log


# Convenience functions for common events

def log_user_login(db: Session, user_id: str, success: bool = True, ip: Optional[str] = None):
    """Log user login attempt"""
    return log_audit(
        db=db,
        event="USER_LOGIN",
        actor_type="USER",
        actor_id=user_id,
        action_result="SUCCESS" if success else "FAILED",
        ip_address=ip
    )


def log_user_logout(db: Session, user_id: str):
    """Log user logout"""
    return log_audit(
        db=db,
        event="USER_LOGOUT",
        actor_type="USER",
        actor_id=user_id,
        action_result="SUCCESS"
    )


def log_wallet_topup(db: Session, user_id: str, wallet_id: str, amount: str, currency: str):
    """Log wallet top-up"""
    return log_audit(
        db=db,
        event="WALLET_TOPUP",
        actor_type="USER",
        actor_id=user_id,
        resource_type="WALLET",
        resource_id=wallet_id,
        action_result="SUCCESS",
        meta={"amount": amount, "currency": currency}
    )


def log_wallet_withdraw(db: Session, user_id: str, wallet_id: str, amount: str, currency: str):
    """Log wallet withdrawal"""
    return log_audit(
        db=db,
        event="WALLET_WITHDRAW",
        actor_type="USER",
        actor_id=user_id,
        resource_type="WALLET",
        resource_id=wallet_id,
        action_result="SUCCESS",
        meta={"amount": amount, "currency": currency}
    )


def log_user_transfer(db: Session, user_id: str, wallet_id: str, amount: str, to_user: str):
    """Log user-to-user transfer"""
    return log_audit(
        db=db,
        event="USER_TRANSFER",
        actor_type="USER",
        actor_id=user_id,
        resource_type="WALLET",
        resource_id=wallet_id,
        action_result="SUCCESS",
        meta={"amount": amount, "to_user": to_user}
    )


def log_bill_payment(db: Session, user_id: str, wallet_id: str, amount: str):
    """Log bill payment"""
    return log_audit(
        db=db,
        event="BILL_PAYMENT",
        actor_type="USER",
        actor_id=user_id,
        resource_type="WALLET",
        resource_id=wallet_id,
        action_result="SUCCESS",
        meta={"amount": amount}
    )


def log_bank_account_added(db: Session, user_id: str, bank_account_id: str, bank_name: str):
    """Log when user adds a bank account"""
    return log_audit(
        db=db,
        event="BANK_ACCOUNT_ADDED",
        actor_type="USER",
        actor_id=user_id,
        resource_type="BANK_ACCOUNT",
        resource_id=bank_account_id,
        action_result="SUCCESS",
        meta={"bank_name": bank_name}
    )


def log_bank_account_updated(db: Session, user_id: str, bank_account_id: str):
    """Log when user updates a bank account"""
    return log_audit(
        db=db,
        event="BANK_ACCOUNT_UPDATED",
        actor_type="USER",
        actor_id=user_id,
        resource_type="BANK_ACCOUNT",
        resource_id=bank_account_id,
        action_result="SUCCESS"
    )


def log_profile_updated(db: Session, user_id: str, fields_changed: list):
    """Log when user updates their profile"""
    return log_audit(
        db=db,
        event="PROFILE_UPDATED",
        actor_type="USER",
        actor_id=user_id,
        resource_type="USER",
        resource_id=user_id,
        action_result="SUCCESS",
        meta={"fields_changed": fields_changed}
    )


def log_admin_login(db: Session, admin_id: str, success: bool = True, ip: Optional[str] = None):
    """Log admin login attempt"""
    return log_audit(
        db=db,
        event="ADMIN_LOGIN",
        actor_type="ADMIN",
        actor_id=admin_id,
        action_result="SUCCESS" if success else "FAILED",
        ip_address=ip
    )


def log_admin_logout(db: Session, admin_id: str):
    """Log admin logout"""
    return log_audit(
        db=db,
        event="ADMIN_LOGOUT",
        actor_type="ADMIN",
        actor_id=admin_id,
        action_result="SUCCESS"
    )


def log_admin_view_users(db: Session, admin_id: str, filters: Optional[Dict] = None):
    """Log when admin views users list"""
    return log_audit(
        db=db,
        event="ADMIN_VIEW_USERS",
        actor_type="ADMIN",
        actor_id=admin_id,
        action_result="SUCCESS",
        meta=filters or {}
    )


def log_admin_view_wallets(db: Session, admin_id: str, filters: Optional[Dict] = None):
    """Log when admin views wallets"""
    return log_audit(
        db=db,
        event="ADMIN_VIEW_WALLETS",
        actor_type="ADMIN",
        actor_id=admin_id,
        action_result="SUCCESS",
        meta=filters or {}
    )


def log_admin_view_transactions(db: Session, admin_id: str, filters: Optional[Dict] = None):
    """Log when admin views transactions"""
    return log_audit(
        db=db,
        event="ADMIN_VIEW_TRANSACTIONS",
        actor_type="ADMIN",
        actor_id=admin_id,
        action_result="SUCCESS",
        meta=filters or {}
    )


def log_failed_action(
    db: Session,
    event: str,
    actor_type: str,
    actor_id: Optional[str],
    error_message: str,
    ip_address: Optional[str] = None
):
    """Log a failed action (e.g., insufficient balance, unauthorized access)"""
    return log_audit(
        db=db,
        event=event,
        actor_type=actor_type,
        actor_id=actor_id or "UNKNOWN",
        action_result="FAILED",
        ip_address=ip_address,
        meta={"error": error_message}
    )