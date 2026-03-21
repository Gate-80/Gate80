"""
GATE80 — Decoy API
db/database.py

Two separate databases:
  - decoy_wallet.db  → fake wallet state (users, wallets, transactions)
  - decoy_logs.db    → attacker interaction logs
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ─────────────────────────────────────────────────────────────────────────────
# Wallet DB — fake state
# ─────────────────────────────────────────────────────────────────────────────
WALLET_DB_URL = "sqlite:///./decoy_wallet.db"

wallet_engine = create_engine(
    WALLET_DB_URL,
    connect_args={"check_same_thread": False}
)
WalletSession = sessionmaker(autocommit=False, autoflush=False, bind=wallet_engine)
WalletBase = declarative_base()


def get_wallet_db():
    db = WalletSession()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Logs DB — attacker interaction logs
# ─────────────────────────────────────────────────────────────────────────────
LOGS_DB_URL = "sqlite:///./decoy_logs.db"

logs_engine = create_engine(
    LOGS_DB_URL,
    connect_args={"check_same_thread": False}
)
LogsSession = sessionmaker(autocommit=False, autoflush=False, bind=logs_engine)
LogsBase = declarative_base()


def get_logs_db():
    db = LogsSession()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# Init both DBs
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    from decoy_api.db.models import (
        DecoyUser, DecoyWallet, DecoyTransaction,
        DecoyUserSession, DecoyAdminSession, DecoyBankAccount, DecoyPayment
    )
    from decoy_api.db.log_models import DecoyRequest

    WalletBase.metadata.create_all(bind=wallet_engine)
    LogsBase.metadata.create_all(bind=logs_engine)