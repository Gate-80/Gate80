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
from adaptivedecoy.schemas import SessionSummary, Signals, TargetContext
from adaptivedecoy.decoy_policy import choose_decoy_plan, build_llm_payload
from adaptivedecoy.decoy_handler import apply_decoy_plan
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

_backend_session_factory = None
_decoy_session_factory   = None

# Sliding windows tracked for ALL sessions — built before flagging
session_windows: dict[str, "SessionWindow"] = {}


def get_or_create_window(sid: str) -> SessionWindow:
    if sid not in session_windows:
        session_windows[sid] = SessionWindow()
    return session_windows[sid]


# ─────────────────────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    global detector, _backend_session_factory, _decoy_session_factory

    init_db()
    logger.info("✅ Proxy database initialised")

    if DETECTION_DISABLED:
        logger.warning(
            "⚠️  GATE80_DETECTION_DISABLED=1 — detection is OFF. "
            "All traffic forwarded to real backend. "
            "Use this mode for dataset generation only."
        )
    else:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            detector = AnomalyDetector(MODEL_PATH, SCALER_PATH)
        else:
            logger.warning(
                "⚠️  Model files not found (%s, %s) — detection disabled.",
                MODEL_PATH, SCALER_PATH,
            )

    if os.path.exists(BACKEND_DB_PATH):
        engine = create_engine(
            f"sqlite:///{BACKEND_DB_PATH}",
            connect_args={"check_same_thread": False}
        )
        _backend_session_factory = sessionmaker(bind=engine)
        logger.info("✅ Backend DB connected for token mirroring")
    else:
        logger.warning("⚠️  Backend DB not found — token mirroring disabled")

    if os.path.exists(DECOY_DB_PATH):
        engine = create_engine(
            f"sqlite:///{DECOY_DB_PATH}",
            connect_args={"check_same_thread": False}
        )
        _decoy_session_factory = sessionmaker(bind=engine)
        logger.info("✅ Decoy DB connected for token mirroring")
    else:
        logger.warning("⚠️  Decoy DB not found — token mirroring disabled")

    if not DETECTION_DISABLED:
        logger.info(
            "✅ Adaptive deception ready — window_size=%d, decay=%.2f, "
            "behavior_classes=%s",
            BEHAVIOR_WINDOW_SIZE, 0.85,
            ["brute_force", "scanning", "fraud", "unknown_suspicious"],
        )


@app.on_event("shutdown")
async def shutdown_event():
    await http_client.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# Token mirroring
# ─────────────────────────────────────────────────────────────────────────────
def mirror_token_to_decoy(token: str) -> None:
    if not _backend_session_factory or not _decoy_session_factory:
        return

    try:
        backend_db = _backend_session_factory()
        row = backend_db.execute(
            text("SELECT user_id FROM user_sessions WHERE token = :token"),
            {"token": token}
        ).fetchone()
        backend_db.close()

        if not row:
            logger.debug("Token not found in backend DB — skipping mirror")
            return

        user_id = row[0]

        backend_db = _backend_session_factory()
        user = backend_db.execute(
            text("SELECT id, full_name, email, phone, city, is_verified FROM users WHERE id = :uid"),
            {"uid": user_id}
        ).fetchone()
        backend_db.close()

        decoy_db = _decoy_session_factory()

        existing_user = decoy_db.execute(
            text("SELECT id FROM users WHERE id = :uid"),
            {"uid": user_id}
        ).fetchone()

        if not existing_user and user:
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

            existing_wallet = decoy_db.execute(
                text("SELECT id FROM wallets WHERE user_id = :uid"),
                {"uid": user_id}
            ).fetchone()

            if not existing_wallet:
                decoy_db.execute(
                    text(
                        "INSERT INTO wallets (id, user_id, currency_code, balance, status) "
                        "VALUES (:id, :user_id, 'SAR', '2500.00', 'ACTIVE')"
                    ),
                    {"id": f"w_mirror_{user_id}", "user_id": user_id}
                )

        existing_token = decoy_db.execute(
            text("SELECT token FROM user_sessions WHERE token = :token"),
            {"token": token}
        ).fetchone()

        if not existing_token:
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

    except Exception as e:
        logger.error("GATE80 ❌ token mirroring failed: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_session_id(request: Request) -> str:
    user_token  = request.headers.get("X-User-Token")
    admin_token = request.headers.get("X-Admin-Token")
    if user_token:
        return f"user:{user_token}"
    if admin_token:
        return f"admin:{admin_token}"
    return f"ip:{get_client_ip(request)}"


def build_forward_headers(request: Request, extra: dict | None = None) -> dict:
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() != "host" and k.lower() not in HOP_BY_HOP_HEADERS
    }
    headers["X-From-Proxy"] = "1"
    if extra:
        headers.update(extra)
    return headers


async def forward(
    request: Request,
    body: bytes,
    target_url: str,
    extra_headers: dict | None = None,
) -> httpx.Response:
    return await http_client.request(
        method=request.method,
        url=target_url,
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
        window.attack_type = new_type

def build_session_summary(sid: str, window: SessionWindow) -> SessionSummary:
    requests = getattr(window, "requests", [])

    total_requests = len(requests)

    if total_requests >= 2:
        duration_sec = max(
            requests[-1].timestamp - requests[0].timestamp,
            1e-6
        )
    else:
        duration_sec = 1.0

    request_rate = total_requests / duration_sec

    paths = [r.path for r in requests]
    unique_endpoints = len(set(paths)) if paths else 0

    status_codes = [r.status_code for r in requests]
    failed_auth_count = sum(1 for s in status_codes if s in {401, 403})
    status_404_count = sum(1 for s in status_codes if s == 404)

    failed_auth_ratio = failed_auth_count / max(total_requests, 1)
    status_404_ratio = status_404_count / max(total_requests, 1)

    methods = [
        getattr(r, "method", None)
        for r in requests
        if getattr(r, "method", None)
    ]
    method_diversity = len(set(methods)) if methods else 1

    from collections import Counter
    import math

    counts = Counter(paths)
    endpoint_entropy = 0.0
    for count in counts.values():
        p = count / max(total_requests, 1)
        if p > 0:
            endpoint_entropy -= p * math.log2(p)

    attack_type_map = {
        "brute_force": "credential_based_attacks",
        "credential_stuffing": "credential_based_attacks",
        "credential_attack": "credential_based_attacks",
        "credential_based_attacks": "credential_based_attacks",

        "scanning": "endpoint_scanning",
        "endpoint_scanning": "endpoint_scanning",

        "fraud": "financial_fraud",
        "financial_fraud": "financial_fraud",

        "account_creation": "account_creation",

        "unknown_suspicious": "endpoint_scanning",
        None: "credential_based_attacks",
    }

    raw_attack_type = getattr(window, "attack_type", None)
    candidate_attack_type = attack_type_map.get(
        raw_attack_type,
        "credential_based_attacks"
    )

    return SessionSummary(
        session_id=sid,
        candidate_attack_type=candidate_attack_type,
        signals=Signals(
            request_rate=request_rate,
            endpoint_entropy=endpoint_entropy,
            unique_endpoints=unique_endpoints,
            failed_auth_ratio=failed_auth_ratio,
            status_404_ratio=status_404_ratio,
            method_diversity=method_diversity,
        ),
        target_context=TargetContext(
            business_flow_targeted=False,
            authenticated=request_token_present(sid),
        ),
    )

def request_token_present(sid: str) -> bool:
    return sid.startswith("user:") or sid.startswith("admin:")

def get_configured_decoy(path: str, method: str):
    """
    Check if this path+method has a configured decoy in the backend DB.
    Returns the decoy_config row as a dict, or None if not found.
    """
    if not _backend_session_factory:
        return None
    try:
        db = _backend_session_factory()
        result = db.execute(
            text("""
                SELECT dc.status_code, dc.response_template, dc.delay_ms, dc.decoy_type
                FROM decoy_config dc
                JOIN endpoint_inventory ei ON dc.endpoint_id = ei.id
                WHERE ei.path = :path
                  AND ei.method = :method
                  AND ei.is_selected_for_decoy = 1
                  AND dc.is_enabled = 1
                LIMIT 1
            """),
            {"path": path, "method": method.upper()}
        ).fetchone()
        db.close()
        if result:
            return {
                "status_code": int(result[0] or 200),
                "body": result[1] or {"message": "OK"},
                "delay_ms": int(result[2] or 0),
                "decoy_type": result[3],
            }
    except Exception as e:
        logger.error("GATE80 ❌ decoy config lookup failed: %s", e)
    return None
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

    window = get_or_create_window(sid)

    body     = await request.body()
    body_str = body.decode("utf-8", errors="ignore") if body else None
    db       = SessionLocal()

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
    think_time_ms = (start_time - last_signal_time) * 1000

    # ─────────────────────────────────────────────────────────────────────────
    # Dataset generation mode — skip all detection, forward everything to
    # the real backend. No sessions are flagged, no decoy routing occurs.
    # ─────────────────────────────────────────────────────────────────────────
    if DETECTION_DISABLED:
        try:
            upstream = await forward(request, body, f"{BACKEND_URL}/{path}")
            response_time_ms = int((time.time() - start_time) * 1000)

            db_log(
                db, req_id, client_ip, request, body_str,
                upstream.status_code, response_time_ms,
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
            db.close()
            return Response(
                content=b'{"detail": "Backend unavailable"}',
                status_code=503,
                headers={"Content-Type": "application/json"},
            )
        finally:
            db.close()

    # ─────────────────────────────────────────────────────────────────────────
    # Normal operation — detection active
    # ─────────────────────────────────────────────────────────────────────────
    pre_flagged = False
    if detector is not None:
        state = detector.get_or_create_session(sid)
        pre_flagged = state.is_anomalous


    try:
        # ─────────────────────────────────────────────────────────────────────
        # Branch A: session already flagged → adaptive decoy inside proxy
        # ─────────────────────────────────────────────────────────────────────
        if pre_flagged:
            try:
                # Reclassify on every decoy request — two-layer model
                # handles both early (cumulative) and late (window) signals
                _reclassify(window, sid)

                response_time_ms = int((time.time() - start_time) * 1000)
                session_summary = build_session_summary(sid, window)

                # Check if this endpoint has a configured decoy in the DB
                configured = get_configured_decoy(request.url.path, request.method)
                if configured:
                    if configured["delay_ms"] > 0:
                         await asyncio.sleep(configured["delay_ms"] / 1000)
                    db_log(
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
                        content=json.dumps(configured["body"]).encode("utf-8"),
                        status_code=configured["status_code"],
                        headers={"Content-Type": "application/json"},
                    )

                upstream = await forward(
                    request, body,
                    f"{DECOY_URL}/{path}",
                    extra_headers={"X-Attack-Type": window.attack_type},
                )
                
                decoy_plan = choose_decoy_plan(
                    session=session_summary,
                    llm_raw_response=None,  # Gemini later
                )

                decoy_response = apply_decoy_plan(
                    plan=decoy_plan,
                    session=session_summary,
                    request_path=request.url.path,
                    request_method=request.method,
                )

                think_time_ms = 0
                window.add(RequestSignal(
                    timestamp=start_time,
                    path=request.url.path,
                    status_code=decoy_response["status_code"],
                    think_time_ms=think_time_ms,
                ))

                if detector is not None:
                    _, score = detector.process_request(
                        sid,
                        request.url.path,
                        decoy_response["status_code"],
                        response_time_ms,
                    )
                else:
                    score = 0.0

                    logger.info(
                    "GATE80 🎭 [ADAPTIVE DECOY] sid=%-40s score=%.4f "
                    "attack_type=%s strategy=%s depth=%s %s %s → %d",
                    sid,
                    score,
                    window.attack_type,
                    decoy_plan.strategy,
                    decoy_plan.decoy_depth,
                    request.method,
                    request.url.path,
                    decoy_response["status_code"],
                )

                db_log(
                    db, req_id, client_ip, request, body_str,
                    decoy_response["status_code"], response_time_ms,
                    forwarded_to_backend=False,
                    session_id=sid,
                    anomaly_score=score,
                    routed_to="adaptive_decoy",
                    flagged_as_suspicious=True,
                    suspicion_reason=f"Adaptive decoy: {decoy_plan.strategy}",
                    attack_type=window.attack_type,
                )

                return Response(
                    content=json.dumps(decoy_response["body"]).encode("utf-8"),
                    status_code=decoy_response["status_code"],
                    headers=decoy_response["headers"],
                    media_type="application/json",
                )

            except Exception as exc:
                response_time_ms = int((time.time() - start_time) * 1000)
                error_msg = (
                    "Decoy unavailable"
                    if isinstance(exc, httpx.ConnectError)
                    else "Decoy timeout"
                )
                logger.warning("GATE80 ⚠️  decoy unreachable: %s", exc)
                logger.error("GATE80 ❌ adaptive decoy failed: %s", exc)

                db_log(
                    db, req_id, client_ip, request, body_str,
                    503, response_time_ms,
                    forwarded_to_backend=False,
                    backend_error=f"Adaptive decoy failure: {exc}",
                    session_id=sid,
                    routed_to="error",
                    attack_type=window.attack_type,
                )

                return Response(
                    content=b'{"detail": "Adaptive decoy unavailable"}',
                    status_code=503,
                    headers={"Content-Type": "application/json"},
                )

        # ─────────────────────────────────────────────────────────────────────
        # Branch B: normal session → forward to real backend
        # ─────────────────────────────────────────────────────────────────────
        else:
            try:
                upstream = await forward(request, body, f"{BACKEND_URL}/{path}")
                response_time_ms = int((time.time() - start_time) * 1000)

                think_time_ms = 0
                window.add(RequestSignal(
                    timestamp=start_time,
                    path=request.url.path,
                    status_code=upstream.status_code,
                    think_time_ms=think_time_ms,
                ))

                if detector is not None:
                    is_anomalous, score = detector.process_request(
                        sid, request.url.path,
                        upstream.status_code, response_time_ms,
                    )
                else:
                    is_anomalous, score = False, 0.0

                

                attack_type = window.attack_type

                if is_anomalous:
                    # Classify immediately — cumulative layer has been
                    # accumulating evidence since the first request
                    attack_type = classify_behavior(window)
                    window.attack_type = attack_type

                    token = request.headers.get("X-User-Token")
                    if token:
                        mirror_token_to_decoy(token)
                        logger.warning(
                         "GATE80 🚨 [FLAGGED] sid=%-40s score=%.4f attack_type=%s "
                           "→ next requests → adaptive decoy",
                         sid,
                         score,
                         attack_type,
                                         )
                else:
                    logger.info(
                        "GATE80 ✅ [BACKEND]  sid=%-40s score=%.4f  "
                        "%s %s → %d",
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
                    attack_type=attack_type,
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