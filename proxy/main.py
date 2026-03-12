"""
GATE80 — Adaptive API Deception System
"""

import os
import time
import uuid
import logging
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from proxy.db.database import SessionLocal, init_db
from proxy.db.logger import db_log
from detection.model import AnomalyDetector

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [proxy] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("proxy")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
DECOY_URL   = os.getenv("DECOY_URL",   "http://127.0.0.1:8001")
MODEL_PATH  = os.getenv("MODEL_PATH",  "model/isolation_forest.pkl")
SCALER_PATH = os.getenv("SCALER_PATH", "model/scaler.pkl")

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-length",
}

# ─────────────────────────────────────────────────────────────────────────────
# App & shared resources
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="GATE80 Reverse Proxy",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

http_client = httpx.AsyncClient(timeout=30.0)
detector: AnomalyDetector | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    global detector

    init_db()
    logger.info("✅ Proxy database initialised")

    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        detector = AnomalyDetector(MODEL_PATH, SCALER_PATH)
    else:
        logger.warning(
            "⚠️  Model files not found (%s, %s) — detection disabled.",
            MODEL_PATH, SCALER_PATH,
        )


@app.on_event("shutdown")
async def shutdown_event():
    await http_client.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────
def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_session_id(request: Request) -> str:
    """
    Derive a stable session identity from the request.
    Priority: X-User-Token → X-Admin-Token → client IP
    """
    user_token  = request.headers.get("X-User-Token")
    admin_token = request.headers.get("X-Admin-Token")
    if user_token:
        return f"user:{user_token}"
    if admin_token:
        return f"admin:{admin_token}"
    return f"ip:{get_client_ip(request)}"


def build_forward_headers(request: Request) -> dict:
    """Strip hop-by-hop headers and add proxy marker."""
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() != "host" and k.lower() not in HOP_BY_HOP_HEADERS
    }
    headers["X-From-Proxy"] = "1"
    return headers


async def forward(request: Request, body: bytes, target_url: str) -> httpx.Response:
    """Forward a request to target_url and return the raw httpx response."""
    return await http_client.request(
        method=request.method,
        url=target_url,
        params=request.query_params,
        content=body,
        headers=build_forward_headers(request),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Middleware — console logging
# ─────────────────────────────────────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    start  = time.time()

    response = await call_next(request)

    ms = int((time.time() - start) * 1000)
    logger.info(
        "id=%s %s %s → %d  %dms",
        req_id, request.method, request.url.path, response.status_code, ms,
    )
    response.headers["X-Request-Id"] = req_id
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Reverse proxy — main handler
# ─────────────────────────────────────────────────────────────────────────────
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def reverse_proxy(request: Request, path: str):
    req_id     = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    start_time = time.time()
    client_ip  = get_client_ip(request)
    sid        = get_session_id(request)

    body     = await request.body()
    body_str = body.decode("utf-8", errors="ignore") if body else None
    db       = SessionLocal()

    # Check if this session was already flagged in a previous request
    pre_flagged = False
    if detector is not None:
        state = detector.get_or_create_session(sid)
        pre_flagged = state.is_anomalous

    try:
        if pre_flagged:
            # ── Already flagged → send to decoy ──────────────────────────────
            try:
                upstream = await forward(request, body, f"{DECOY_URL}/{path}")
                response_time_ms = int((time.time() - start_time) * 1000)

                _, score = detector.process_request(
                    sid, request.url.path,
                    upstream.status_code, response_time_ms,
                )

                logger.info(
                    "GATE80 🔀 [DECOY]   sid=%-40s score=%.4f  %s %s → %d",
                    sid, score, request.method, request.url.path, upstream.status_code,
                )

                db_log(
                    db, req_id, client_ip, request, body_str,
                    upstream.status_code, response_time_ms,
                    forwarded_to_backend=False,
                    session_id=sid,
                    anomaly_score=score,
                    routed_to="decoy",
                    flagged_as_suspicious=True,
                    suspicion_reason=f"IF score={score:.4f}",
                )

                return Response(
                    content=upstream.content,
                    status_code=upstream.status_code,
                    headers=dict(upstream.headers),
                )

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                response_time_ms = int((time.time() - start_time) * 1000)
                error_msg = "Decoy unavailable" if isinstance(exc, httpx.ConnectError) else "Decoy timeout"
                logger.warning("GATE80 ⚠️  decoy unreachable: %s", exc)

                db_log(
                    db, req_id, client_ip, request, body_str,
                    503, response_time_ms,
                    forwarded_to_backend=False,
                    backend_error=error_msg,
                    session_id=sid,
                    routed_to="error",
                )

                return Response(
                    content=b'{"detail": "Service unavailable"}',
                    status_code=503,
                    headers={"Content-Type": "application/json"},
                )

        else:
            # ── Normal session → send to real backend ─────────────────────────
            try:
                upstream = await forward(request, body, f"{BACKEND_URL}/{path}")
                response_time_ms = int((time.time() - start_time) * 1000)

                if detector is not None:
                    is_anomalous, score = detector.process_request(
                        sid, request.url.path,
                        upstream.status_code, response_time_ms,
                    )
                else:
                    is_anomalous, score = False, 0.0

                if is_anomalous:
                    logger.warning(
                        "GATE80 🚨 [FLAGGED] sid=%-40s score=%.4f "
                        "→ next requests → decoy",
                        sid, score,
                    )
                else:
                    logger.info(
                        "GATE80 ✅ [BACKEND] sid=%-40s score=%.4f  %s %s → %d",
                        sid, score, request.method,
                        request.url.path, upstream.status_code,
                    )

                db_log(
                    db, req_id, client_ip, request, body_str,
                    upstream.status_code, response_time_ms,
                    forwarded_to_backend=True,
                    session_id=sid,
                    anomaly_score=score,
                    routed_to="backend",
                    flagged_as_suspicious=is_anomalous,
                    suspicion_reason=f"IF score={score:.4f}" if is_anomalous else None,
                )

                return Response(
                    content=upstream.content,
                    status_code=upstream.status_code,
                    headers=dict(upstream.headers),
                )

            except httpx.ConnectError:
                response_time_ms = int((time.time() - start_time) * 1000)
                logger.error("GATE80 ❌ backend unavailable at %s", BACKEND_URL)

                db_log(
                    db, req_id, client_ip, request, body_str,
                    503, response_time_ms,
                    forwarded_to_backend=False,
                    backend_error="Backend service unavailable",
                    session_id=sid,
                    routed_to="error",
                )

                return Response(
                    content=b'{"detail": "Backend service unavailable"}',
                    status_code=503,
                    headers={"Content-Type": "application/json"},
                )

            except httpx.TimeoutException:
                response_time_ms = int((time.time() - start_time) * 1000)
                logger.error("GATE80 ⏱  backend timeout: %s/%s", BACKEND_URL, path)

                db_log(
                    db, req_id, client_ip, request, body_str,
                    504, response_time_ms,
                    forwarded_to_backend=False,
                    backend_error="Request timeout",
                    session_id=sid,
                    routed_to="error",
                )

                return Response(
                    content=b'{"detail": "Request timed out"}',
                    status_code=504,
                    headers={"Content-Type": "application/json"},
                )

    finally:
        db.close()