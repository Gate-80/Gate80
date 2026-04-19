"""
GATE80 — Decoy API
logger.py

Logs every attacker interaction to decoy_logs.db.
"""

import json
import logging
from typing import Optional
from sqlalchemy.orm import Session
from decoy_api.db.log_models import DecoyRequest, DeceptionPlanLog

logger = logging.getLogger("decoy.logger")

_REDACT_HEADERS = {"x-user-token", "x-admin-token", "authorization", "cookie"}
_MAX_BODY_BYTES  = 10_240


def _redact_headers(headers: dict) -> dict:
    return {
        k: "***REDACTED***" if k.lower() in _REDACT_HEADERS else v
        for k, v in headers.items()
    }


def log_decoy_request(
    db: Session,
    *,
    request_id: str,
    client_ip: str,
    session_id: Optional[str],
    method: str,
    path: str,
    query_params: dict,
    headers: dict,
    body: Optional[str],
    response_status: int,
    response_body: Optional[str],
    response_time_ms: int,
) -> None:
    try:
        record = DecoyRequest(
            request_id=request_id,
            client_ip=client_ip,
            session_id=session_id,
            method=method,
            path=path,
            query_params=json.dumps(query_params) if query_params else None,
            headers=json.dumps(_redact_headers(headers)),
            body=body[:_MAX_BODY_BYTES] if body and len(body) > _MAX_BODY_BYTES else body,
            response_status=response_status,
            response_body=response_body,
            response_time_ms=response_time_ms,
        )
        db.add(record)
        db.commit()
        logger.info(
            "DECOY 🪤 %s %s → %d  sid=%s",
            method, path, response_status, session_id or "unknown"
        )
    except Exception as exc:
        logger.error("Failed to log decoy request %s: %s", request_id, exc)
        db.rollback()


def log_deception_plan(
    db: Session,
    *,
    request_id: str,
    session_id: str,
    attack_type: str,
    method: str,
    path: str,
    plan_id: str,
    plan_source: str,
    model_name: Optional[str],
    prompt_version: Optional[str],
    confidence: Optional[float],
    rationale: Optional[str],
    generation_error: Optional[str],
    response_status_before: int,
    response_status_after: int,
    raw_plan: Optional[dict],
    validated_plan: dict,
    applied_actions: list[str],
    rejected_actions: list[str],
    final_body_preview: Optional[str],
) -> None:
    try:
        record = DeceptionPlanLog(
            request_id=request_id,
            session_id=session_id,
            attack_type=attack_type,
            method=method,
            path=path,
            plan_id=plan_id,
            plan_source=plan_source,
            model_name=model_name,
            prompt_version=prompt_version,
            confidence=confidence,
            rationale=rationale,
            generation_error=generation_error,
            response_status_before=response_status_before,
            response_status_after=response_status_after,
            raw_plan=json.dumps(raw_plan) if raw_plan else None,
            validated_plan=json.dumps(validated_plan),
            applied_actions=json.dumps(applied_actions),
            rejected_actions=json.dumps(rejected_actions),
            final_body_preview=final_body_preview,
        )
        db.add(record)
        db.commit()
    except Exception as exc:
        logger.error("Failed to log deception plan %s: %s", request_id, exc)
        db.rollback()
