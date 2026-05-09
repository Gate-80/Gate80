"""Read configured decoys from the platform DB.

Uses NullPool so each call opens and closes its own connection. SQLite
connections are cheap, and NullPool prevents the pool exhaustion we hit
under load (QueuePool default size 5 + overflow 10 = 15 max).
"""
import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool


PLATFORM_DB_PATH = os.getenv("GATE80_PLATFORM_DB_PATH", "data/gate80_platform.db")

_engine = create_engine(
    f"sqlite:///{PLATFORM_DB_PATH}",
    connect_args={"check_same_thread": False},
    poolclass=NullPool,
)
SessionLocal = sessionmaker(bind=_engine)


def get_decoy_config_for_endpoint(path: str, method: str):
    """Return the deployed decoy config for (path, method), or None if not configured."""
    db = SessionLocal()
    try:
        row = db.execute(
            text("""
                SELECT dc.decoy_type, dc.status_code, dc.response_template, dc.delay_ms, dc.is_enabled
                FROM endpoint_inventory ei
                JOIN decoy_config dc ON dc.endpoint_id = ei.id
                WHERE ei.path = :path
                  AND UPPER(ei.method) = :method
                  AND ei.is_selected_for_decoy = 1
                  AND dc.is_enabled = 1
                LIMIT 1
            """),
            {
                "path": path if path.startswith("/") else f"/{path}",
                "method": method.upper(),
            },
        ).fetchone()

        if not row:
            return None

        return {
            "decoy_type": row[0],
            "status_code": int(row[1]) if row[1] is not None else 200,
            "response_template": row[2],
            "delay_ms": int(row[3]) if row[3] is not None else 0,
            "is_enabled": bool(row[4]),
        }
    finally:
        db.close()
