"""
Platform DB connection.

Separate from the customer wallet DB. Holds GATE80 control-plane data:
projects, endpoint inventory, decoy configs, and proxy configs.

DB file: data/gate80_platform.db (created by alembic upgrade).
"""
from __future__ import annotations

from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session


# Resolve repo root so this works regardless of where the process is launched.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "gate80_platform.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"


# check_same_thread=False is required for SQLite + FastAPI (request thread pool).
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_platform_db() -> Generator[Session, None, None]:
    """FastAPI dependency. Yields a platform DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
