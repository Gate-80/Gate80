"""
GATE80 — Decoy API
deception/strategies/scanning.py

Deception strategy for endpoint scanning / enumeration sessions.

Behavior:
  - 0.8s delay on all requests
  - 404 responses enriched with ghost endpoints to waste attacker time
  - Progressive rate limiting based on SHARED session-level request counter.

Rate limit counter design:
  The counter key "decoy:request_count:{session_id}" is shared across
  ALL strategies and incremented by the DeceptionEngine on every request.
  This means the counter reflects total requests in the decoy since
  the session was first flagged — regardless of how long classification
  took or which strategy was active before scanning was committed.

  This matches real-world WAF behavior: rate limits are enforced from
  the first flagged request, not from when a specific attack type is
  identified. A session that spent 3 requests in unknown_suspicious
  before being classified as scanning has already used 3 of its 15
  allowed requests.

Progressive rate limits:
  Limit 1:    60s  ( 1 min)   — "Slow down your requests"
  Limit 2:   120s  ( 2 min)   — "Your IP has been flagged"
  Limit 3:   240s  ( 4 min)   — "Access temporarily suspended"
  Limit N:   60 × 2^(N-1), capped at 3,600s (1 hour)

Threshold = 15, derived from p75 (10) of baseline_sessions.csv + buffer.
"""

import json
import uuid
import asyncio
import logging
import time
from fastapi import Request
from decoy_api.deception.strategies.base import BaseStrategy

logger = logging.getLogger("decoy.deception.scanning")

SCAN_DELAY              = 0.8
REQUEST_LIMIT_THRESHOLD = 15
BASE_RATE_LIMIT_SECONDS = 60
MAX_RATE_LIMIT_SECONDS  = 3_600

# Shared counter key — written by DeceptionEngine, read by this strategy
SHARED_REQUEST_COUNT_KEY = "decoy:request_count:{session_id}"

GHOST_ENDPOINTS: dict[str, list[str]] = {
    "/admin": [
        "/api/v1/admin/config",
        "/api/v1/admin/audit-log",
        "/api/v1/admin/keys/rotate",
        "/api/v1/admin/system/metrics",
    ],
    "/wallet": [
        "/api/v1/users/{user_id}/wallet/history",
        "/api/v1/users/{user_id}/wallet/limits",
        "/api/v1/users/{user_id}/wallet/freeze",
    ],
    "/users": [
        "/api/v1/users/export",
        "/api/v1/users/bulk-update",
        "/api/v1/users/search",
    ],
    "/auth": [
        "/api/v1/auth/refresh",
        "/api/v1/auth/verify-otp",
        "/api/v1/auth/sessions",
    ],
    "default": [
        "/api/v1/status",
        "/api/v1/version",
        "/api/v1/health/detailed",
    ],
}


def _ghost_suggestions(path: str) -> list[str]:
    for segment, endpoints in GHOST_ENDPOINTS.items():
        if segment != "default" and segment in path:
            return endpoints
    return GHOST_ENDPOINTS["default"]


def _rate_limit_duration(limit_count: int) -> int:
    return min(BASE_RATE_LIMIT_SECONDS * (2 ** (limit_count - 1)), MAX_RATE_LIMIT_SECONDS)


def _rate_limit_message(limit_count: int) -> str:
    if limit_count == 1:
        return "Rate limit exceeded. Slow down your requests."
    elif limit_count == 2:
        return "Rate limit exceeded. Your IP has been flagged for unusual activity."
    else:
        return "Access temporarily suspended due to excessive scanning."


class ScanningStrategy(BaseStrategy):

    async def pre_process(self, request: Request) -> None:
        await asyncio.sleep(SCAN_DELAY)

    async def post_process(
        self,
        body: bytes,
        status_code: int,
        path: str,
        session_id: str,
        engine_state: dict,
    ) -> tuple[bytes, int]:
        limit_start_key = f"scanning:limit_start:{session_id}"
        limit_count_key = f"scanning:limit_count:{session_id}"

        # Shared counter — set by DeceptionEngine, reflects ALL decoy requests
        shared_count_key = SHARED_REQUEST_COUNT_KEY.format(session_id=session_id)
        req_count = engine_state.get(shared_count_key, 0)

        limit_count = engine_state.get(limit_count_key, 0)
        limit_start = engine_state.get(limit_start_key, None)

        # ── Check if currently rate limited ───────────────────────────────────
        if limit_start is not None:
            duration  = _rate_limit_duration(limit_count)
            elapsed   = time.time() - limit_start
            remaining = int(duration - elapsed)

            if remaining > 0:
                logger.info(
                    "DECOY 🕵️  [SCANNING] rate limit active — %ds remaining: "
                    "sid=%s (limit #%d)",
                    remaining, session_id, limit_count,
                )
                return self._rate_limited_response(remaining, limit_count), 429

            else:
                # Window expired — shared counter resets handled by engine
                logger.info(
                    "DECOY 🕵️  [SCANNING] rate limit #%d expired for sid=%s",
                    limit_count, session_id,
                )
                engine_state[limit_start_key] = None
                engine_state[shared_count_key] = 0

        # ── Check shared threshold ────────────────────────────────────────────
        if req_count >= REQUEST_LIMIT_THRESHOLD:
            new_limit_count               = limit_count + 1
            engine_state[limit_count_key] = new_limit_count
            engine_state[limit_start_key] = time.time()
            engine_state[shared_count_key] = 0

            duration = _rate_limit_duration(new_limit_count)

            logger.warning(
                "DECOY 🕵️  [SCANNING] rate limit triggered after %d total "
                "decoy requests (limit #%d, duration=%ds) for sid=%s",
                req_count, new_limit_count, duration, session_id,
            )
            return self._rate_limited_response(duration, new_limit_count), 429

        # ── Inject ghost endpoints on 404s ────────────────────────────────────
        if status_code == 404:
            suggestions = _ghost_suggestions(path)
            logger.info(
                "DECOY 🕵️  [SCANNING] injecting ghost endpoints for "
                "sid=%s path=%s",
                session_id, path,
            )
            return json.dumps({
                "detail":       "Resource not found",
                "did_you_mean": suggestions,
                "request_id":   str(uuid.uuid4())[:8],
                "docs":         "/api/v1/docs",
            }).encode(), 404

        return body, status_code

    @staticmethod
    def _rate_limited_response(retry_after: int, limit_count: int) -> bytes:
        return json.dumps({
            "detail":      _rate_limit_message(limit_count),
            "retry_after": retry_after,
            "limit_level": limit_count,
            "support":     "contact support@digitalwallet.sa for assistance",
        }).encode()