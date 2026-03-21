"""
GATE80 — Decoy API
db/models.py

Wallet DB models — mirrors the real backend schema.
All data is fake but structurally identical to the real system.
"""

import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum as SQLEnum, JSON, Numeric
from decoy_api.db.database import WalletBase


def now_utc():
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Enums — identical to real backend
# ─────────────────────────────────────────────────────────────────────────────
class WalletStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    CLOSED = "CLOSED"


class TransactionType(str, enum.Enum):
    TOPUP         = "TOPUP"
    WITHDRAW      = "WITHDRAW"
    TRANSFER_USER = "TRANSFER_USER"
    TRANSFER_BANK = "TRANSFER_BANK"
    BILLPAY       = "BILLPAY"


class TransactionStatus(str, enum.Enum):
    PENDING   = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    CANCELLED = "CANCELLED"


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────
class DecoyUser(WalletBase):
    __tablename__ = "users"

    id         = Column(String, primary_key=True, index=True)
    full_name  = Column(String, nullable=False)
    email      = Column(String, unique=True, nullable=False, index=True)
    password   = Column(String, nullable=False)
    phone      = Column(String, nullable=False)
    city       = Column(String, nullable=False)
    is_verified = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class DecoyWallet(WalletBase):
    __tablename__ = "wallets"

    id            = Column(String, primary_key=True, index=True)
    user_id       = Column(String, nullable=False, unique=True, index=True)
    currency_code = Column(String, default="SAR")
    balance       = Column(String, default="0.00")
    status        = Column(SQLEnum(WalletStatus), default=WalletStatus.ACTIVE)
    created_at    = Column(DateTime(timezone=True), default=now_utc)
    updated_at    = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class DecoyTransaction(WalletBase):
    __tablename__ = "transactions"

    id           = Column(String, primary_key=True, index=True)
    user_id      = Column(String, nullable=False, index=True)
    wallet_id    = Column(String, nullable=False)
    type         = Column(SQLEnum(TransactionType), nullable=False)
    status       = Column(SQLEnum(TransactionStatus), default=TransactionStatus.COMPLETED)
    amount       = Column(JSON, nullable=False)   # {"currency_code": "SAR", "value": "100.00"}
    counterparty = Column(JSON, nullable=False)   # {"kind": "USER", "ref": "u_1002"}
    description  = Column(String)
    created_at   = Column(DateTime(timezone=True), default=now_utc)
    updated_at   = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class DecoyUserSession(WalletBase):
    __tablename__ = "user_sessions"

    token      = Column(String, primary_key=True, index=True)
    user_id    = Column(String, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class DecoyAdminSession(WalletBase):
    __tablename__ = "admin_sessions"

    token      = Column(String, primary_key=True, index=True)
    admin_id   = Column(String, nullable=False)
    role       = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class DecoyBankAccount(WalletBase):
    __tablename__ = "bank_accounts"

    id                    = Column(String, primary_key=True, index=True)
    user_id               = Column(String, nullable=False, index=True)
    bank_name             = Column(String, nullable=False)
    iban                  = Column(String, nullable=False)
    masked_account_number = Column(String, nullable=False)
    currency              = Column(String, default="SAR")
    is_default            = Column(Boolean, default=False)
    created_at            = Column(DateTime(timezone=True), default=now_utc)
    updated_at            = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class DecoyPayment(WalletBase):
    __tablename__ = "payments"

    id          = Column(String, primary_key=True, index=True)
    user_id     = Column(String, nullable=False, index=True)
    status      = Column(String, default="COMPLETED")
    amount      = Column(JSON, nullable=False)
    merchant    = Column(JSON, nullable=False)
    description = Column(String)
    created_at  = Column(DateTime(timezone=True), default=now_utc)
    updated_at  = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)