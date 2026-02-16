# SQLAlchemy models (tables)

from sqlalchemy import Column, String, Boolean, DateTime, Enum as SQLEnum, ForeignKey, Numeric, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from backend_api.db.database import Base


def now_utc():
    """Helper function to get current UTC time"""
    return datetime.now(timezone.utc)


# -----------------------------
# Enums
# -----------------------------
class WalletStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    CLOSED = "CLOSED"


class TransactionType(str, enum.Enum):
    TOPUP = "TOPUP"
    WITHDRAW = "WITHDRAW"
    TRANSFER_USER = "TRANSFER_USER"
    TRANSFER_BANK = "TRANSFER_BANK"
    BILLPAY = "BILLPAY"


class TransactionStatus(str, enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class PaymentStatus(str, enum.Enum):
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# -----------------------------
# Models
# -----------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)  # Note: Should be hashed in production
    phone = Column(String, nullable=False)
    city = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    # Relationships
    bank_accounts = relationship("BankAccount", back_populates="user", cascade="all, delete-orphan")
    wallets = relationship("Wallet", back_populates="user", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="user", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="user", cascade="all, delete-orphan")


class BankAccount(Base):
    __tablename__ = "bank_accounts"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    bank_name = Column(String, nullable=False)
    iban = Column(String, nullable=False)
    masked_account_number = Column(String, nullable=False)
    currency = Column(String, default="SAR")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    # Relationships
    user = relationship("User", back_populates="bank_accounts")


class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, unique=True)
    currency_code = Column(String, default="SAR")
    balance = Column(String, default="0.00")  # Store as string to maintain precision
    status = Column(SQLEnum(WalletStatus), default=WalletStatus.ACTIVE)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    # Relationships
    user = relationship("User", back_populates="wallets")
    transactions = relationship("Transaction", back_populates="wallet", cascade="all, delete-orphan")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    wallet_id = Column(String, ForeignKey("wallets.id"), nullable=False)
    type = Column(SQLEnum(TransactionType), nullable=False)
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING)
    amount = Column(JSON, nullable=False)  # Stored as {"currency_code": "SAR", "value": "100.00"}
    counterparty = Column(JSON, nullable=False)  # Stored as {"kind": "USER", "ref": "u_1002"}
    description = Column(String)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    # Relationships
    user = relationship("User", back_populates="transactions")
    wallet = relationship("Wallet", back_populates="transactions")


class Payment(Base):
    __tablename__ = "payments"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    status = Column(SQLEnum(PaymentStatus), default=PaymentStatus.CREATED)
    amount = Column(JSON, nullable=False)  # Stored as {"currency_code": "SAR", "value": "100.00"}
    merchant = Column(JSON, nullable=False)  # Stored as {"name": "Store", "merchant_id": "m_9001"}
    description = Column(String)
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    # Relationships
    user = relationship("User", back_populates="payments")


class Admin(Base):
    __tablename__ = "admins"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)  # Note: Should be hashed in production
    role = Column(String, default="ADMIN")
    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    token = Column(String, primary_key=True, index=True)
    admin_id = Column(String, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class UserSession(Base):
    __tablename__ = "user_sessions"

    token = Column(String, primary_key=True, index=True)
    user_id = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, index=True)
    event = Column(String, nullable=False, index=True)  # e.g., "USER_TRANSFER", "ADMIN_VIEW_USERS", "USER_LOGIN"
    actor_type = Column(String, nullable=False)  # "USER" or "ADMIN"
    actor_id = Column(String, index=True)  # user_id or admin_id
    resource_type = Column(String)  # "WALLET", "TRANSACTION", "USER", "BANK_ACCOUNT", etc.
    resource_id = Column(String)  # ID of the affected resource
    action_result = Column(String)  # "SUCCESS", "FAILED", "UNAUTHORIZED"
    ip_address = Column(String)  # Client IP address (optional for now)
    meta = Column(JSON)  # Additional context (amounts, counterparty, error messages, etc.)
    created_at = Column(DateTime(timezone=True), default=now_utc, index=True)