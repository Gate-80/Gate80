from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os

BACKEND_DB_PATH = os.getenv("BACKEND_DB_PATH", "digital_wallet.db")

_engine = create_engine(
    f"sqlite:///{BACKEND_DB_PATH}",
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=_engine)


def get_decoy_config_for_endpoint(path: str, method: str):
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
            }
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