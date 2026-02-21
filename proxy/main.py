
import time
import uuid
import logging
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from proxy.db.database import SessionLocal, init_db
from proxy.db.logger import log_request

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [proxy] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("proxy")

# -----------------------------
# Configuration
# -----------------------------
BACKEND_URL = "http://127.0.0.1:8000"

# Headers that should not be forwarded (HTTP hop-by-hop headers)
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

# -----------------------------
# App Initialization
# -----------------------------
app = FastAPI(
    title="RASD Reverse Proxy",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# Reuse a single httpx client across all requests (more efficient)
http_client = httpx.AsyncClient(timeout=30.0)


# Initialize database on startup
@app.on_event("startup")
def startup_event():
    """Initialize proxy database on startup"""
    init_db()
    logger.info("✅ Proxy database initialized")


# -----------------------------
# Helper Functions
# -----------------------------
def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    # Check for X-Forwarded-For header (if behind another proxy)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Fallback to direct client
    return request.client.host if request.client else "unknown"


# -----------------------------
# Middleware – Request Logging
# -----------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with timing and request ID."""
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    start = time.time()

    response = await call_next(request)

    ms = int((time.time() - start) * 1000)
    logger.info(
        f"id={req_id} {request.method} {request.url.path} "
        f"-> {response.status_code} {ms}ms"
    )

    response.headers["X-Request-Id"] = req_id
    return response


# -----------------------------
# Reverse Proxy – Forward All Requests
# -----------------------------
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
)
async def reverse_proxy(request: Request, path: str):
    """Forward all incoming requests to the backend API."""
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    start_time = time.time()
    
    target_url = f"{BACKEND_URL}/{path}"
    body = await request.body()
    body_str = body.decode("utf-8", errors="ignore") if body else None
    
    # Extract client info
    client_ip = get_client_ip(request)
    
    # Filter out hop-by-hop headers and forward the rest
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() != "host" and k.lower() not in HOP_BY_HOP_HEADERS
    }
    
    # Add proxy identification header
    forward_headers["X-From-Proxy"] = "1"
    
    # Database session for logging
    db = SessionLocal()
    
    try:
        backend_response = await http_client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
            headers=forward_headers,
        )
        
        # Calculate response time
        response_time_ms = int((time.time() - start_time) * 1000)
        
        # Log to database
        log_request(
            db=db,
            request_id=req_id,
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            headers=dict(request.headers),
            body=body_str,
            response_status=backend_response.status_code,
            response_time_ms=response_time_ms,
            forwarded_to_backend=True,
        )
        
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers),
        )

    except httpx.ConnectError:
        response_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Backend unavailable at {BACKEND_URL}")
        
        # Log failed connection
        log_request(
            db=db,
            request_id=req_id,
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            headers=dict(request.headers),
            body=body_str,
            response_status=503,
            response_time_ms=response_time_ms,
            forwarded_to_backend=False,
            backend_error="Backend service unavailable",
        )
        
        return Response(
            content=b'{"detail": "Backend service unavailable"}',
            status_code=503,
            headers={"Content-Type": "application/json"}
        )

    except httpx.TimeoutException:
        response_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Request to {target_url} timed out")
        
        # Log timeout
        log_request(
            db=db,
            request_id=req_id,
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            headers=dict(request.headers),
            body=body_str,
            response_status=504,
            response_time_ms=response_time_ms,
            forwarded_to_backend=False,
            backend_error="Request timeout",
        )
        
        return Response(
            content=b'{"detail": "Request timed out"}',
            status_code=504,
            headers={"Content-Type": "application/json"}
        )
    
    finally:
        db.close()