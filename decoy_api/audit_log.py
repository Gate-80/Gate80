"""
JSONL audit log for LLM calls.

Privacy mitigation #5: customers can review every payload that left their
infrastructure for the LLM. One line per call. Append-only. Never
overwrites or deletes — log rotation is the operator's responsibility.

Format (one JSON object per line):
  {
    "ts": "2026-05-08T20:43:48.123456Z",
    "request_id": "uuid",
    "session_id": "ip:127.0.0.1",
    "attack_type": "credential_based_attacks",
    "method": "POST",
    "path": "/api/v1/auth/sign-in",
    "model": "claude-haiku-4-5",
    "source": "llm" | "fallback" | "skipped" | "error",
    "prompt_chars": 1234,
    "prompt_preview": "...first 500 chars of prompt...",
    "raw_response": {...},      # parsed plan dict, if any
    "applied_actions": [...],
    "rejected_actions": [...],
    "error_message": "..."     # only present if source=fallback/error
  }

Bytes that left the GATE80 boundary live in `prompt_preview`. The full
prompt isn't stored to keep file sizes manageable; the first 500 chars
are enough for compliance review since the rest is the schema (already
known to the customer) and structural metadata.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("decoy.audit_log")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_PATH = LOG_DIR / "llm_prompts.jsonl"

PROMPT_PREVIEW_CHARS = 500

# A simple module-level lock keeps writes from interleaving when uvicorn
# runs the post_process under different request workers.
_write_lock = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def append_llm_audit(
    *,
    request_id: str,
    session_id: str,
    attack_type: str,
    method: str,
    path: str,
    model: str | None,
    source: str,
    prompt: str | None,
    raw_response: dict[str, Any] | None,
    applied_actions: list[str],
    rejected_actions: list[str],
    error_message: str | None = None,
) -> None:
    """Append one JSON line to logs/llm_prompts.jsonl. Never raises on disk errors."""
    record = {
        "ts": _utc_now_iso(),
        "request_id": request_id,
        "session_id": session_id,
        "attack_type": attack_type,
        "method": method,
        "path": path,
        "model": model,
        "source": source,
        "prompt_chars": len(prompt) if prompt else 0,
        "prompt_preview": (prompt or "")[:PROMPT_PREVIEW_CHARS],
        "raw_response": raw_response,
        "applied_actions": applied_actions,
        "rejected_actions": rejected_actions,
    }
    if error_message:
        record["error_message"] = error_message

    line = json.dumps(record, ensure_ascii=True) + "\n"
    try:
        with _write_lock:
            with LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line)
    except OSError as exc:
        logger.warning("audit log write failed: %s", exc)
