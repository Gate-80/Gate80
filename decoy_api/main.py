"""
GATE80 — Adaptive API Deception System
decoy_api/main.py

Decoy API — mimics the real digital wallet backend.
Runs on :8001. All traffic is logged to decoy_logs.db.
Wallet state is persisted in decoy_wallet.db.
"""

import uuid
import time
import json
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from decoy_api.db.database import init_db, LogsSession
from decoy_api.logger import log_decoy_request
from decoy_api.seed import seed

from decoy_api.routers import auth, admin_auth, user_accounts, wallet, admin


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_session_id(request: Request) -> str:
    user_token  = request.headers.get("X-User-Token")
    admin_token = request.headers.get("X-Admin-Token")
    if user_token:
        return f"user:{user_token}"
    if admin_token:
        return f"admin:{admin_token}"
    return f"ip:{get_client_ip(request)}"

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [decoy] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("decoy")

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="GATE80 Decoy API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("GATE80 🪤 Decoy databases initialised")
    seed()
    logger.info("GATE80 🪤 Decoy API ready on :8001")


# ─────────────────────────────────────────────────────────────────────────────
# Middleware — log every request to decoy_logs.db
# ─────────────────────────────────────────────────────────────────────────────
@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    start      = time.time()
    body_bytes = await request.body()
    body_str   = body_bytes.decode("utf-8", errors="ignore") if body_bytes else None

    # Re-inject body so routers can still read it
    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request._receive = receive

    response = await call_next(request)
    response_time_ms = int((time.time() - start) * 1000)

    # Log to decoy_logs.db
    db = LogsSession()
    try:
        log_decoy_request(
            db=db,
            request_id=request.headers.get("X-Request-Id") or str(uuid.uuid4()),
            client_ip=get_client_ip(request),
            session_id=get_session_id(request),
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            headers=dict(request.headers),
            body=body_str,
            response_status=response.status_code,
            response_body=None,  # body already consumed by router
            response_time_ms=response_time_ms,
        )
    finally:
        db.close()

    logger.info(
        "DECOY 🪤 %s %s → %d  %dms  sid=%s",
        request.method, request.url.path,
        response.status_code, response_time_ms,
        get_session_id(request),
    )
    return response


# ─────────────────────────────────────────────────────────────────────────────
# System endpoints
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "digital-wallet-api"}


@app.get("/hello")
def hello():
    return {"message": "Hello from the API"}


# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────
app.include_router(auth.router,          prefix="/api/v1")
app.include_router(admin_auth.router,    prefix="/api/v1")
app.include_router(user_accounts.router, prefix="/api/v1")
app.include_router(wallet.router,        prefix="/api/v1")
app.include_router(admin.router,         prefix="/api/v1")


# ─────────────────────────────────────────────────────────────────────────────
# Catch-all — log any undefined endpoint
# ─────────────────────────────────────────────────────────────────────────────
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
)
async def catch_all(path: str, request: Request):
    logger.warning("DECOY ⚠️  undefined endpoint hit: %s %s", request.method, request.url.path)
    return JSONResponse(content={"detail": "Not found"}, status_code=404)