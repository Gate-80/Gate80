"""
Wallet DB connection.

After Phase 1B, this DB only holds wallet data (users, wallets, transactions,
payments, bank_accounts, audit_logs, admins, *_sessions). The four platform
tables (projects, endpoint_inventory, decoy_config, proxy_config) live in
data/gate80_platform.db and are accessed through SQLAlchemy session binds.

What that means for callers: no change. `db.query(User)` hits the wallet DB,
`db.query(Project)` hits the platform DB — SQLAlchemy routes automatically
based on the model class.
"""
import os
import stat
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Platform engine + models — needed for the cross-DB session binds below.
from gate80_platform.db.database import engine as _platform_engine
from gate80_platform.db.models import (
    Project,
    EndpointInventory,
    DecoyConfig,
    ProxyConfig,
)


SQLALCHEMY_DATABASE_URL = "sqlite:///./digital_wallet.db"
DB_PATH = "./digital_wallet.db"

# check_same_thread=False is required for SQLite + FastAPI thread pool.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# Single Session class that knows about BOTH DBs.
# - Default engine: wallet (binds left unset for wallet models).
# - Platform models route to platform engine via the binds= mapping.
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    binds={
        Project: _platform_engine,
        EndpointInventory: _platform_engine,
        DecoyConfig: _platform_engine,
        ProxyConfig: _platform_engine,
    },
)

# Wallet-only Base — only wallet models register on this metadata.
# init_db() will create wallet tables only; platform tables are managed by
# alembic_platform.
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency. Same name as before — call sites unchanged."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create wallet tables on app startup.

    Platform tables are managed by `alembic -c alembic_platform.ini upgrade head`.
    The legacy migrate_sqlite_schema() helper has been removed — alembic now
    owns schema migrations for both DBs.
    """
    Base.metadata.create_all(bind=engine)

    # Make sure permissions don't trip up other team members on shared dev boxes.
    if os.path.exists(DB_PATH):
        os.chmod(
            DB_PATH,
            stat.S_IRUSR | stat.S_IWUSR
            | stat.S_IRGRP | stat.S_IWGRP
            | stat.S_IROTH | stat.S_IWOTH,
        )
