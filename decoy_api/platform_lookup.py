"""Cross-DB lookup helpers for the decoy.

The decoy lives in decoy_wallet.db but needs to read endpoint inventory
(response schemas, etc.) from the platform DB at data/gate80_platform.db.
This module isolates that cross-DB connection so the rest of the decoy
doesn't have to know about platform tables.

Uses NullPool — same reasoning as proxy/decoy_lookup.py.
"""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

logger = logging.getLogger("decoy.platform_lookup")

PLATFORM_DB_PATH = os.getenv("GATE80_PLATFORM_DB_PATH", "data/gate80_platform.db")
_engine = create_engine(
    f"sqlite:///{PLATFORM_DB_PATH}",
    connect_args={"check_same_thread": False},
    poolclass=NullPool,
)
SessionLocal = sessionmaker(bind=_engine)


@lru_cache(maxsize=512)
def get_response_schema(path: str, method: str) -> dict | None:
    """Look up response_schema_json for an endpoint. Cached per (path, method)."""
    db = SessionLocal()
    try:
        row = db.execute(
            text(
                """
                SELECT response_schema_json
                FROM endpoint_inventory
                WHERE path = :path AND UPPER(method) = :method
                LIMIT 1
                """
            ),
            {
                "path": path if path.startswith("/") else f"/{path}",
                "method": method.upper(),
            },
        ).fetchone()

        if not row or not row[0]:
            return None

        value = row[0]
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return value if isinstance(value, dict) else None
    except Exception as exc:
        logger.warning("get_response_schema failed for %s %s: %s", method, path, exc)
        return None
    finally:
        db.close()


def scrub_schema(schema: Any) -> Any:
    """Strip descriptions, examples, titles before sending to the LLM."""
    if isinstance(schema, dict):
        return {
            k: scrub_schema(v)
            for k, v in schema.items()
            if k not in ("description", "example", "examples", "title", "$comment")
        }
    if isinstance(schema, list):
        return [scrub_schema(item) for item in schema]
    return schema
