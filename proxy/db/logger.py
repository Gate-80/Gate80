
from sqlalchemy.orm import Session
from proxy.db.models import ProxyRequest
import logging

logger = logging.getLogger("proxy")


def log_request(
    db: Session,
    request_id: str,
    client_ip: str,
    method: str,
    path: str,
    query_params: dict,
    headers: dict,
    body: str,
    response_status: int,
    response_time_ms: int,
    forwarded_to_backend: bool = True,
    backend_error: str = None,
):
    """
    Log a proxy request to the database.
    
    Args:
        db: Database session
        request_id: Unique request ID (UUID)
        client_ip: Client IP address
        method: HTTP method (GET, POST, etc.)
        path: Request path
        query_params: Query parameters dict
        headers: Request headers dict
        body: Request body (string)
        response_status: HTTP response status code
        response_time_ms: Response time in milliseconds
        forwarded_to_backend: Whether request was forwarded to backend
        backend_error: Error message if backend was unreachable
    """
    try:
        # Filter sensitive headers (don't log passwords, tokens in plain text)
        safe_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in ["authorization", "x-user-token", "x-admin-token"]
        }
        
        # Add masked version if auth headers present
        if "authorization" in headers:
            safe_headers["authorization"] = "Bearer ***REDACTED***"
        if "x-user-token" in headers:
            safe_headers["x-user-token"] = "***REDACTED***"
        if "x-admin-token" in headers:
            safe_headers["x-admin-token"] = "***REDACTED***"
        
        # Create database entry
        proxy_request = ProxyRequest(
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            query_params=ProxyRequest.dict_to_json(query_params),
            headers=ProxyRequest.dict_to_json(safe_headers),
            body=body[:10000] if body else None,  # Limit body size to 10KB
            response_status=response_status,
            response_time_ms=response_time_ms,
            forwarded_to_backend=forwarded_to_backend,
            backend_error=backend_error,
        )
        
        db.add(proxy_request)
        db.commit()
        
    except Exception as e:
        logger.error(f"Failed to log request to database: {e}")
        db.rollback()


def flag_request_as_suspicious(db: Session, request_id: str, reason: str):
    """
    Flag a request as suspicious.
    
    Args:
        db: Database session
        request_id: Request ID to flag
        reason: Reason for flagging
    """
    try:
        request = db.query(ProxyRequest).filter_by(request_id=request_id).first()
        if request:
            request.flagged_as_suspicious = True
            request.suspicion_reason = reason
            db.commit()
            logger.warning(f"Request {request_id} flagged as suspicious: {reason}")
    except Exception as e:
        logger.error(f"Failed to flag request {request_id}: {e}")
        db.rollback()