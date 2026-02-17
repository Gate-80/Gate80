
import time
import uuid
import logging
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

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

# Disable Swagger UI on proxy - it's just a transparent forwarder
app = FastAPI(
    title="RASD Reverse Proxy",
    docs_url=None,    # Disable /docs
    redoc_url=None,   # Disable /redoc
    openapi_url=None  # Disable /openapi.json
)

# Reuse a single httpx client across all requests (more efficient)
http_client = httpx.AsyncClient(timeout=30.0)


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
    target_url = f"{BACKEND_URL}/{path}"
    body = await request.body()

    # Filter out hop-by-hop headers and forward the rest
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() != "host" and k.lower() not in HOP_BY_HOP_HEADERS
    }

    # Add proxy identification header
    forward_headers["X-From-Proxy"] = "1"

    try:
        backend_response = await http_client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
            headers=forward_headers,
        )

        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers),
        )

    except httpx.ConnectError:
        logger.error(f"Backend unavailable at {BACKEND_URL}")
        return Response(
            content=b'{"detail": "Backend service unavailable"}',
            status_code=503,
            headers={"Content-Type": "application/json"}
        )

    except httpx.TimeoutException:
        logger.error(f"Request to {target_url} timed out")
        return Response(
            content=b'{"detail": "Request timed out"}',
            status_code=504,
            headers={"Content-Type": "application/json"}
        )