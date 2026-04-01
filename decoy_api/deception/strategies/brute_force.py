"""
GATE80 — Decoy API
deception/strategies/brute_force.py

Progressive lockout deception strategy for brute force sessions.

Lock durations (doubles each cycle, capped at 24h):
  Lock 1:  1,800s ( 30 min)
  Lock 2:  3,600s ( 60 min)
  Lock 3:  7,200s (120 min)
  Lock N:  30 × 2^(N-1) min, cap 86,400s (24h)
"""

import json
import asyncio
import logging
import time
from fastapi import Request
from decoy_api.deception.strategies.base import BaseStrategy

logger = logging.getLogger("decoy.deception.brute_force")

AUTH_DELAY               = 2.5
DEFAULT_DELAY            = 0.3
AUTH_FAIL_LOCK_THRESHOLD = 3
BASE_LOCK_SECONDS        = 1_800   # 30 minutes
MAX_LOCK_SECONDS         = 86_400  # 24 hours


def _lock_duration(lock_count: int) -> int:
    """
    Progressive lockout duration — doubles each cycle, capped at 24h.
    lock_count is 1-indexed (first lock = 1).
    """
    return min(BASE_LOCK_SECONDS * (2 ** (lock_count - 1)), MAX_LOCK_SECONDS)


class BruteForceStrategy(BaseStrategy):

    async def pre_process(self, request: Request) -> None:
        if "/auth" in request.url.path:
            await asyncio.sleep(AUTH_DELAY)
        else:
            await asyncio.sleep(DEFAULT_DELAY)

    async def post_process(
        self,
        body: bytes,
        status_code: int,
        path: str,
        session_id: str,
        engine_state: dict,
    ) -> tuple[bytes, int]:
        if "/auth/sign-in" not in path:
            return body, status_code

        fail_key       = f"brute_force:fails:{session_id}"
        lock_start_key = f"brute_force:lock_start:{session_id}"
        lock_count_key = f"brute_force:lock_count:{session_id}"

        lock_count = engine_state.get(lock_count_key, 0)
        lock_start = engine_state.get(lock_start_key, None)

        # ── Check if currently locked ─────────────────────────────────────────
        if lock_start is not None:
            duration  = _lock_duration(lock_count)
            elapsed   = time.time() - lock_start
            remaining = int(duration - elapsed)

            if remaining > 0:
                logger.info(
                    "DECOY 🔒 [BRUTE_FORCE] lock active — %ds remaining: sid=%s (lock #%d)",
                    remaining, session_id, lock_count,
                )
                return self._locked_response(remaining, lock_count), 423

            else:
                # Lock expired — reset fail counter, keep lock_count for escalation
                logger.info(
                    "DECOY 🔓 [BRUTE_FORCE] lock #%d expired for sid=%s — resetting fail counter",
                    lock_count, session_id,
                )
                engine_state[lock_start_key] = None
                engine_state[fail_key]       = 0

        # ── Track auth failures ───────────────────────────────────────────────
        if status_code == 401:
            fail_count = engine_state.get(fail_key, 0) + 1
            engine_state[fail_key] = fail_count

            logger.info(
                "DECOY 🔒 [BRUTE_FORCE] auth fail #%d/%d for sid=%s",
                fail_count, AUTH_FAIL_LOCK_THRESHOLD, session_id,
            )

            if fail_count >= AUTH_FAIL_LOCK_THRESHOLD:
                new_lock_count               = lock_count + 1
                engine_state[lock_count_key] = new_lock_count
                engine_state[lock_start_key] = time.time()
                engine_state[fail_key]       = 0

                duration = _lock_duration(new_lock_count)

                logger.warning(
                    "DECOY 🔒 [BRUTE_FORCE] account locked (lock #%d, duration=%ds) for sid=%s",
                    new_lock_count, duration, session_id,
                )
                return self._locked_response(duration, new_lock_count), 423

        return body, status_code

    @staticmethod
    def _locked_response(retry_after: int, lock_count: int) -> bytes:
        if lock_count == 1:
            reason = "Too many failed login attempts."
        elif lock_count == 2:
            reason = "Repeated failed login attempts. Security hold applied."
        else:
            reason = "Multiple security violations detected. Account under extended hold."

        return json.dumps({
            "detail":      f"Account temporarily locked. {reason}",
            "retry_after": retry_after,
            "lock_level":  lock_count,
            "support":     "contact support@digitalwallet.sa for assistance",
        }).encode()