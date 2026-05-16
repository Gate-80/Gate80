"""
GATE80 — Reverse Proxy
proxy/main.py

Intercepts all traffic, scores sessions with Isolation Forest,
classifies attack behavior using a two-layer sliding window model,
and routes suspicious sessions to the stateful decoy API.

Two-layer classification:
  Layer 1 (window, 60% weight)  — recent behavior, full after 6 requests
  Layer 2 (cumulative, 40% weight) — lifetime evidence with decay

At flag time: classification runs immediately using cumulative layer
(window may not be full yet). As window fills, window layer adds weight.
This handles both fast attacks (window-dominant) and slow multi-phase
attacks like scanning (cumulative-dominant).

Dataset generation mode:
  Set GATE80_DETECTION_DISABLED=1 to disable anomaly detection entirely.
  All traffic is forwarded to the real backend. No sessions are flagged.
  Use this when running the unified traffic generator to prevent the
  detection engine from contaminating normal session feature values.

  Run:  GATE80_DETECTION_DISABLED=1 uvicorn proxy.main:app --reload --port 8080
"""

import os
import time
import uuid
import logging
import httpx
import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import Response
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from proxy.db.database import SessionLocal, init_db
from proxy.db.logger import db_log
from detection.model import AnomalyDetector
from proxy.behaviour_class import (
    SessionWindow, RequestSignal, classify_behavior, BEHAVIOR_WINDOW_SIZE
)

# ─────────────────────────────────────────────────────────────────────
# Transfer rate-limit guard (Filter/Router pattern, Bridges et al. 2025)
# Deterministic pre-check that runs BEFORE behavioural classification.
# Catches rapid wallet-drain attacks using a valid session token —
# a pattern that authenticated session-level behavioural models miss.
# ─────────────────────────────────────────────────────────────────────
from collections import deque
import re as _re

# Configuration — tune these to balance false-positives vs containment
RAPID_TRANSFER_THRESHOLD = 5     # N transfers in window flags the session
RAPID_TRANSFER_WINDOW_SEC = 60   # rolling window length
TRANSFER_PATH_PATTERN = _re.compile(r"^/api/v1/users/[^/]+/wallet/transfer/[^/]+/?$")

# In-memory per-session transfer timestamps. Cleared on service restart.
_transfer_history: dict[str, deque] = {}

def _is_transfer_endpoint(path: str, method: str) -> bool:
    """Check if a request targets the wallet transfer endpoint."""
    return method == "POST" and bool(TRANSFER_PATH_PATTERN.match(path))

def _check_rapid_transfer(session_id: str, now: float) -> bool:
    """
    Returns True if this session has exceeded RAPID_TRANSFER_THRESHOLD
    transfers within the RAPID_TRANSFER_WINDOW_SEC window.
    """
    history = _transfer_history.setdefault(session_id, deque())
    # Drop entries outside the window
    cutoff = now - RAPID_TRANSFER_WINDOW_SEC
    while history and history[0] < cutoff:
        history.popleft()
    # Record current request
    history.append(now)
    # Flag if threshold exceeded
    return len(history) > RAPID_TRANSFER_THRESHOLD

import json

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
BACKEND_URL  = os.getenv("BACKEND_URL",  "http://127.0.0.1:8000")
DECOY_URL    = os.getenv("DECOY_URL",    "http://127.0.0.1:8001")
MODEL_PATH   = os.getenv("MODEL_PATH",   "model/random_forest.pkl")
SCALER_PATH  = os.getenv("SCALER_PATH",  "model/scaler.pkl")

BACKEND_DB_PATH = os.getenv("BACKEND_DB_PATH", "digital_wallet.db")
DECOY_DB_PATH   = os.getenv("DECOY_DB_PATH",   "decoy_wallet.db")

# ─────────────────────────────────────────────────────────────────────────────
# Dataset generation mode — disables anomaly detection entirely.
# All traffic is forwarded directly to the real backend.
# Set env var: GATE80_DETECTION_DISABLED=1
# ─────────────────────────────────────────────────────────────────────────────
DETECTION_DISABLED = os.getenv("GATE80_DETECTION_DISABLED", "0") == "1"
FORCE_DECOY_API = os.getenv("FORCE_DECOY_API", "0") == "1"
HOP_BY_HOP_HEADERS = { #headers that cannot be bybass between proxy and the backend
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-length",
}

# ─────────────────────────────────────────────────────────────────────────────
# App & shared resources
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI( # creating the fast api for the reverse proxy 
    title="GATE80 Reverse Proxy",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)



@app.get("/health")
async def proxy_health():
    """Fast-path health check. Bypasses classification, forwarding, and logging.
    Intended for load balancers and uptime probes — does NOT exercise the
    normal request pipeline."""
    return {"status": "ok", "service": "gate80-proxy"}

http_client = httpx.AsyncClient(timeout=30.0)
detector: AnomalyDetector | None = None

_backend_session_factory = None
_decoy_session_factory   = None

# Sliding windows tracked for ALL sessions — built before flagging
session_windows: dict[str, "SessionWindow"] = {}


def get_or_create_window(sid: str) -> SessionWindow: #getting the session widnow based on the session window id
    if sid not in session_windows:
        session_windows[sid] = SessionWindow()
    return session_windows[sid]


# ─────────────────────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():# its the event that starting up the proxy 
    global detector, _backend_session_factory, _decoy_session_factory

    init_db() # initiating the database
    logger.info("✅ Proxy database initialised")

    if DETECTION_DISABLED:# if the detection were disabled a warning will come in the terminal
        logger.warning(
            "⚠️  GATE80_DETECTION_DISABLED=1 — detection is OFF. "
            "All traffic forwarded to real backend. "
            "Use this mode for dataset generation only."
        )
    else:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):#also initiating the anamoloy detector
            detector = AnomalyDetector(MODEL_PATH, SCALER_PATH)
        else:
            logger.warning( #else it couldnt fetch the detector file
                "⚠️  Model files not found (%s, %s) — detection disabled.",
                MODEL_PATH, SCALER_PATH,
            )

    if os.path.exists(BACKEND_DB_PATH):# intitaing the db connection for token mirroring
        engine = create_engine(
            f"sqlite:///{BACKEND_DB_PATH}",
            connect_args={"check_same_thread": False}
        )
        _backend_session_factory = sessionmaker(bind=engine)
        logger.info("✅ Backend DB connected for token mirroring")
    else: #else the db connection eas failed
        logger.warning("⚠️  Backend DB not found — token mirroring disabled")

    if os.path.exists(DECOY_DB_PATH): # intitaing the decoy db connection for token mirroring
        engine = create_engine(
            f"sqlite:///{DECOY_DB_PATH}",
            connect_args={"check_same_thread": False}
        )
        _decoy_session_factory = sessionmaker(bind=engine)
        logger.info("✅ Decoy DB connected for token mirroring")
    else: #else the db connection eas failed
        logger.warning("⚠️  Decoy DB not found — token mirroring disabled")

    if not DETECTION_DISABLED:#this lines to print out the dectection is enabled in the proxy terminal
        logger.info(
            "✅ Adaptive deception ready — window_size=%d, decay=%.2f, "
            "behavior_classes=%s",
            BEHAVIOR_WINDOW_SIZE, 0.85,
            ["brute_force", "scanning", "fraud", "unknown_suspicious"], # these are the types of attack that was tested for detection
        )


@app.on_event("shutdown") # here to shutdown the prxy event
async def shutdown_event():
    await http_client.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Token mirroring
# ─────────────────────────────────────────────────────────────────────────────
def mirror_token_to_decoy(token: str) -> None:
    if not _backend_session_factory or not _decoy_session_factory: # if backend db and decoy db is not ready stop the function
        return

    try:
        backend_db = _backend_session_factory()#opens up a connection
        row = backend_db.execute(
            text("SELECT user_id FROM user_sessions WHERE token = :token"), #search for the token in usersession taple
            {"token": token}
        ).fetchone()
        backend_db.close()

        if not row: #if the mirror is not found leave the function
            logger.debug("Token not found in backend DB — skipping mirror")
            return

        user_id = row[0] # store the user id here

        backend_db = _backend_session_factory()
        user = backend_db.execute( #storing the user here 
            text("SELECT id, full_name, email, phone, city, is_verified FROM users WHERE id = :uid"),
            {"uid": user_id}
        ).fetchone()
        backend_db.close()

        decoy_db = _decoy_session_factory()

        existing_user = decoy_db.execute(
            text("SELECT id FROM users WHERE id = :uid"),
            {"uid": user_id}
        ).fetchone()

        if not existing_user and user: #if user not existed add new one into the users taple
            decoy_db.execute(
                text(
                    "INSERT INTO users (id, full_name, email, password, phone, city, is_verified) "
                    "VALUES (:id, :full_name, :email, :password, :phone, :city, :is_verified)"
                ),
                {
                    "id":          user[0],
                    "full_name":   user[1],
                    "email":       user[2],
                    "password":    "mirrored",
                    "phone":       user[3],
                    "city":        user[4],
                    "is_verified": user[5],
                }
            )

            existing_wallet = decoy_db.execute(#here is to search from the wallet taple for the user
                text("SELECT id FROM wallets WHERE user_id = :uid"),
                {"uid": user_id}
            ).fetchone()

            if not existing_wallet: #if the wallet is not exist insert a new one
                decoy_db.execute(
                    text(
                        "INSERT INTO wallets (id, user_id, currency_code, balance, status) "
                        "VALUES (:id, :user_id, 'SAR', '2500.00', 'ACTIVE')"
                    ),
                    {"id": f"w_mirror_{user_id}", "user_id": user_id}
                )

        existing_token = decoy_db.execute( #fetching the existed token
            
            text("SELECT token FROM user_sessions WHERE token = :token"),
            {"token": token}
        ).fetchone()

        if not existing_token:#if the token is not existed insert a new one
            decoy_db.execute(
                text("INSERT INTO user_sessions (token, user_id) VALUES (:token, :user_id)"),
                {"token": token, "user_id": user_id}
            )

        decoy_db.commit()
        decoy_db.close()

        logger.info(
            "GATE80 🪞 token mirrored to decoy: user_id=%s token=%s...",
            user_id, token[:8]
        )

    except Exception as e: #handling an exception if the mirroring is failed
        logger.error("GATE80 ❌ token mirroring failed: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_client_ip(request: Request) -> str: #function that gets the client ip number it also nefit us to know where the request come for
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown" #if the "-Forwarded-For" is not avalible it uses the direct fastapi ip else it returns unknown


def get_session_id(request: Request) -> str:#function that helps what session the request comes from
    user_token  = request.headers.get("X-User-Token")
    admin_token = request.headers.get("X-Admin-Token")
    #it checks if the token was comin from a user session or an admin session
    if user_token: 
        return f"user:{user_token}"
    if admin_token:
        return f"admin:{admin_token}"
    return f"ip:{get_client_ip(request)}"# if there isnt a token it uses the ip of th request as the identinty of the session


def build_forward_headers(request: Request, extra: dict | None = None) -> dict: #this function will help you build the header that will be sent to backend or decoyapi
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() != "host" and k.lower() not in HOP_BY_HOP_HEADERS
    }
    headers["X-From-Proxy"] = "1"
    if extra:
        headers.update(extra) #here if there is extra header also it sent ou to backend and decoy api
    return headers


async def forward(#this function help gets to the specifec request to the taget
    request: Request,
    body: bytes,
    target_url: str,
    extra_headers: dict | None = None,
) -> httpx.Response:
    return await http_client.request(
        method=request.method,
        url=target_url, # for example "http://127.0.0.1:8000/api/v1/auth/sign-in" 
        params=request.query_params,
        content=body,
        headers=build_forward_headers(request, extra_headers),
    )


def _reclassify(window: SessionWindow, sid: str) -> None:
    """
    Reclassify using the two-layer model.
    Cumulative layer is always active.
    Window layer activates once window is full.
    No minimum request count needed — cumulative provides early signal.
    """
    new_type = classify_behavior(window)
    if new_type != window.attack_type:
        logger.info(
            "GATE80 🔄 [BEHAVIOR SHIFT] sid=%-40s %s → %s",
            sid, window.attack_type, new_type,
        )
        window.attack_type = new_type #it befit us if the attacker changed the behaviour of the attack

def request_token_present(sid: str) -> bool: #check if the token was connected to a session 
    return sid.startswith("user:") or sid.startswith("admin:")

def get_configured_decoy(path: str, method: str):
    """Look up a configured decoy for (path, method) in the platform DB.

    Delegates to proxy.decoy_lookup which knows about gate80_platform.db.
    """
    try:
        from proxy.decoy_lookup import get_decoy_config_for_endpoint
        return get_decoy_config_for_endpoint(path, method)
    except Exception as exc:
        logger.warning("GATE80 configured decoy lookup failed: %s", exc)
        return None

@app.middleware("http") #It provides a clear trace for every request, including the HTTP method,
#request path, status code, response time, and request ID. This is very useful for integration testing, debugging, request tracking, and SOC monitoring.
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
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4()) #Generate or reuse a unique request ID for tracing.

    start_time = time.time()# Record the request start time to calculate total response time later.
    client_ip = get_client_ip(request)# Extract the client IP address.

    sid = get_session_id(request)#extact the session id 

    window = get_or_create_window(sid)# Retrieve or create the behavior window for this session.
    # The window stores recent requests and is used for attack behavior classification.

    body = await request.body() #here to read the Request body
    body_str = body.decode("utf-8", errors="ignore") if body else None # Convert the request body to text for logging.
    db = SessionLocal()#Open a proxy database session to store request logs and routing decisions.

    # Control-plane routes should not affect detection state
    if path.startswith("api/v1/onboarding"):
        try:
            upstream = await forward(request, body, f"{BACKEND_URL}/{path}")
            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                headers=dict(upstream.headers),
            )
        finally:
            db.close()

    last_signal_time = window.requests[-1].timestamp if window.requests else start_time
    think_time_ms = (start_time - last_signal_time) * 1000 # Calculate think time, which is the time gap between the current request


    # Dataset generation mode — skip detection and decoy routing

    if DETECTION_DISABLED:
        try:
            upstream = await forward(request, body, f"{BACKEND_URL}/{path}")
            response_time_ms = int((time.time() - start_time) * 1000)

            db_log(
                db,
                req_id,
                client_ip,
                request,
                body_str,
                upstream.status_code,
                response_time_ms,
                forwarded_to_backend=True,
                session_id=sid,
                anomaly_score=0.0,
                routed_to="backend",
                flagged_as_suspicious=False,
            )

            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                headers=dict(upstream.headers),
            )

        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error("GATE80 ❌ backend error in generation mode: %s", exc)

            db_log(
                db,
                req_id,
                client_ip,
                request,
                body_str,
                503,
                response_time_ms,
                forwarded_to_backend=False,
                backend_error="Backend unavailable",
                session_id=sid,
                routed_to="error",
            )

            return Response(
                content=b'{"detail": "Backend unavailable"}',
                status_code=503,
                headers={"Content-Type": "application/json"},
            )

        finally:
            db.close()

    # Normal operation — detection active
    # If the session was previously flagged, future requests are routed to deception.
    pre_flagged = False
    if detector is not None:
        state = detector.get_or_create_session(sid)

        # Deterministic rate-limit pre-check (Filter/Router pattern).
        # Authenticated session-level behavioural models miss rapid
        # wallet drains using a valid token. This guard catches them.
        if _is_transfer_endpoint(request.url.path, request.method):
            if _check_rapid_transfer(sid, time.time()):
                if not state.is_anomalous:
                    state.is_anomalous = True
                    logger.warning(
                        "[rate-limit] session %s flagged: >%d transfers in %ds",
                        sid, RAPID_TRANSFER_THRESHOLD, RAPID_TRANSFER_WINDOW_SEC,
                    )

        pre_flagged = state.is_anomalous

    try:
        # ─────────────────────────────────────────────────────────────────────
        # ─────────────────────────────────────────────────────────────────────
        # Branch A: session already flagged → forward to adaptive decoy
        # ─────────────────────────────────────────────────────────────────────
        if pre_flagged:
            try:
                # Reclassify on every decoy request — two-layer model handles
                # both early (cumulative) and late (window) signals.
                _reclassify(window, sid)

                # Check if this endpoint has a configured decoy in the platform DB.
                # This can be used as a fallback or endpoint-specific deception policy.
                configured = get_configured_decoy(request.url.path, request.method)
                if configured:# If a configured decoy exists, apply the configured delay and return
                    if configured["delay_ms"] > 0:
                        await asyncio.sleep(configured["delay_ms"] / 1000)
                    response_time_ms = int((time.time() - start_time) * 1000)
                    db_log(# Log the configured decoy response in the proxy database.
                        db, req_id, client_ip, request, body_str,
                        configured["status_code"], response_time_ms,
                        forwarded_to_backend=False,
                        session_id=sid,
                        anomaly_score=0.0,
                        routed_to="configured_decoy",
                        flagged_as_suspicious=True,
                        suspicion_reason=f"Configured decoy: {configured['decoy_type']}",
                        attack_type=window.attack_type,
                    )
                    return Response(
                        content=json.dumps(configured["response_template"]).encode("utf-8"),
                        status_code=configured["status_code"],
                        headers={"Content-Type": "application/json"},
                    )

                # No configured decoy → forward to live adaptive decoy at :8001.
                # The decoy_api runs the full deception engine (strategy + planner)
                # and returns a transformed response. We pass it through unchanged.
                upstream = await forward(
                    request, body,
                    f"{DECOY_URL}/{path}",
                    extra_headers={"X-Attack-Type": window.attack_type},
                )
                response_time_ms = int((time.time() - start_time) * 1000)

                # Update behavior window with the decoy's actual response status.
                window.add(RequestSignal(
                    timestamp=start_time,
                    path=request.url.path,
                    status_code=upstream.status_code,
                    think_time_ms=0,
                ))

                if detector is not None:
                    _, score = detector.process_request(
                        sid,
                        request.url.path,
                        upstream.status_code,
                        response_time_ms,
                    )
                else:
                    score = 0.0

                logger.info(
                    "GATE80 [ADAPTIVE DECOY] sid=%-40s score=%.4f attack_type=%s %s %s -> %d",
                    sid, score, window.attack_type,
                    request.method, request.url.path, upstream.status_code,
                )

                db_log(
                    db, req_id, client_ip, request, body_str,
                    upstream.status_code, response_time_ms,
                    forwarded_to_backend=False,
                    session_id=sid,
                    anomaly_score=score,
                    routed_to="adaptive_decoy",
                    flagged_as_suspicious=True,
                    suspicion_reason=f"Adaptive decoy: {window.attack_type}",
                    attack_type=window.attack_type,
                )

                # Pass the decoy's response through to the client unchanged.
                # Drop hop-by-hop headers that Starlette will set itself.
                upstream_headers = dict(upstream.headers)
                for h in ("content-encoding", "transfer-encoding",
                          "content-length", "connection"):
                    upstream_headers.pop(h, None)
                return Response(
                    content=upstream.content,
                    status_code=upstream.status_code,
                    headers=upstream_headers,
                    media_type=upstream.headers.get("content-type", "application/json"),
                )

            except Exception as exc:
                response_time_ms = int((time.time() - start_time) * 1000)
                logger.warning("GATE80 decoy unreachable: %s", exc)
                logger.error("GATE80 adaptive decoy failed: %s", exc)

                db_log(
                    db,
                    req_id,
                    client_ip,
                    request,
                    body_str,
                    503,
                    response_time_ms,
                    forwarded_to_backend=False,
                    backend_error=f"Decoy routing failure: {exc}",
                    session_id=sid,
                    routed_to="error",
                    attack_type=window.attack_type,
                )

                return Response(
                    content=b'{"detail": "Adaptive decoy unavailable"}',
                    status_code=503,
                    headers={"Content-Type": "application/json"},
                )

        # Branch B: normal session → forward to real backend
        try:
            upstream = await forward(request, body, f"{BACKEND_URL}/{path}")
            response_time_ms = int((time.time() - start_time) * 1000)

            window.add(
                RequestSignal(
                    timestamp=start_time,
                    path=request.url.path,
                    status_code=upstream.status_code,
                    think_time_ms=think_time_ms,
                )
            )

            if detector is not None:
                is_anomalous, score = detector.process_request(
                    sid,
                    request.url.path,
                    upstream.status_code,
                    response_time_ms,
                )
            else:
                is_anomalous, score = False, 0.0

            attack_type = window.attack_type

            if is_anomalous:
                attack_type = classify_behavior(window)
                window.attack_type = attack_type

                token = request.headers.get("X-User-Token")
                if token:
                    mirror_token_to_decoy(token) # Mirror the user token to the Decoy API database when available.


                logger.warning(
                    "GATE80 🚨 [FLAGGED] sid=%-40s score=%.4f attack_type=%s "
                    "→ next requests → adaptive decoy",
                    sid,
                    score,
                    attack_type,
                )

            else:
                logger.info( # Log normal backend routing or suspicious detection results.

                    "GATE80 ✅ [BACKEND] sid=%-40s score=%.4f %s %s → %d",
                    sid,
                    score,
                    request.method,
                    request.url.path,
                    upstream.status_code,
                )

            db_log(
                db,
                req_id,
                client_ip,
                request,
                body_str,
                upstream.status_code,
                response_time_ms,
                forwarded_to_backend=True,
                session_id=sid,
                anomaly_score=score,
                routed_to="backend",
                flagged_as_suspicious=is_anomalous,
                suspicion_reason=f"RF score={score:.4f}" if is_anomalous else None,
                attack_type=attack_type,
            )

            return Response( # Return the real backend response to the client.
                content=upstream.content,
                status_code=upstream.status_code,
                headers=dict(upstream.headers),
            )

        except httpx.ConnectError: # Handle backend connection failures.

            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error("GATE80 ❌ backend unavailable at %s", BACKEND_URL)

            db_log(
                db,
                req_id,
                client_ip,
                request,
                body_str,
                503,
                response_time_ms,
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
      # Handle backend timeout errors.

        except httpx.TimeoutException:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error("GATE80 backend timeout: %s/%s", BACKEND_URL, path)

            db_log(
                db,
                req_id,
                client_ip,
                request,
                body_str,
                504,
                response_time_ms,
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
 #finally closing the db
    finally:
        db.close()