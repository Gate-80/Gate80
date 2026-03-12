
import json
import logging
from typing import Optional
from fastapi import Request
from sqlalchemy.orm import Session

from proxy.db.models import ProxyRequest

logger = logging.getLogger("proxy.logger")

_REDACT_HEADERS = {"x-user-token", "x-admin-token", "authorization", "cookie"}
_MAX_BODY_BYTES = 10_240  # 10 KB


def _redact_headers(headers: dict) -> dict:
    return {
        k: "***REDACTED***" if k.lower() in _REDACT_HEADERS else v
        for k, v in headers.items()
    }


def _truncate_body(body: Optional[str]) -> Optional[str]:
    if body and len(body) > _MAX_BODY_BYTES:
        return body[:_MAX_BODY_BYTES] + "…[truncated]"
    return body


def log_request(
    db: Session,
    *,
    request_id: str,
    client_ip: str,
    method: str,
    path: str,
    query_params: dict,
    headers: dict,
    body: Optional[str],
    response_status: int,
    response_time_ms: int,
    forwarded_to_backend: bool = True,
    backend_error: Optional[str] = None,
    session_id: Optional[str] = None,
    anomaly_score: Optional[float] = None,
    routed_to: str = "backend",
    flagged_as_suspicious: bool = False,
    suspicion_reason: Optional[str] = None,
) -> None:
    # Log a proxy request to the database.
    try:
        record = ProxyRequest(
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            query_params=json.dumps(query_params) if query_params else None,
            headers=json.dumps(_redact_headers(headers)),
            body=_truncate_body(body),
            response_status=response_status,
            response_time_ms=response_time_ms,
            forwarded_to_backend=forwarded_to_backend,
            backend_error=backend_error,
            session_id=session_id,
            anomaly_score=anomaly_score,
            routed_to=routed_to,
            flagged_as_suspicious=flagged_as_suspicious,
            suspicion_reason=suspicion_reason,
        )
        db.add(record)
        db.commit()

    except Exception as exc:
        logger.error("Failed to log proxy request %s: %s", request_id, exc)
        db.rollback()


def db_log(
    db: Session,
    req_id: str,
    client_ip: str,
    request: Request,
    body_str: Optional[str],
    response_status: int,
    response_time_ms: int,
    *,
    forwarded_to_backend: bool = True,
    backend_error: Optional[str] = None,
    session_id: Optional[str] = None,
    anomaly_score: Optional[float] = None,
    routed_to: str = "backend",
    flagged_as_suspicious: bool = False,
    suspicion_reason: Optional[str] = None,
) -> None:
    """
    Convenience wrapper around log_request() used by the proxy handler.
    Accepts the Request object directly so main.py doesn't repeat
    request.method / request.url.path / request.query_params / request.headers
    on every call.
    """
    log_request(
        db=db,
        request_id=req_id,
        client_ip=client_ip,
        method=request.method,
        path=request.url.path,
        query_params=dict(request.query_params),
        headers=dict(request.headers),
        body=body_str,
        response_status=response_status,
        response_time_ms=response_time_ms,
        forwarded_to_backend=forwarded_to_backend,
        backend_error=backend_error,
        session_id=session_id,
        anomaly_score=anomaly_score,
        routed_to=routed_to,
        flagged_as_suspicious=flagged_as_suspicious,
        suspicion_reason=suspicion_reason,
    )