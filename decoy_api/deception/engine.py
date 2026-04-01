"""
GATE80 — Decoy API
deception/engine.py

Central DeceptionEngine — single point of control for all adaptive
deception behavior.

Shared session-level request counter:
  engine_state["decoy:request_count:{session_id}"] is incremented on
  every post_process call, before dispatching to the strategy.
  This counter reflects total requests in the decoy since the session
  was first flagged — regardless of which attack_type was active.

  The scanning strategy reads this counter to enforce its rate limit
  threshold from the first flagged request, matching real-world WAF
  behavior where rate limits apply from the moment a session enters
  the mitigation layer.
"""

import logging
from fastapi import Request

from decoy_api.deception.strategies.brute_force import BruteForceStrategy
from decoy_api.deception.strategies.scanning    import ScanningStrategy
from decoy_api.deception.strategies.fraud       import FraudStrategy
from decoy_api.deception.strategies.unknown     import UnknownStrategy

logger = logging.getLogger("decoy.deception.engine")

# Shared counter key — incremented here, read by scanning strategy
SHARED_REQUEST_COUNT_KEY = "decoy:request_count:{session_id}"


class DeceptionEngine:

    def __init__(self):
        self._strategies = {
            "brute_force":        BruteForceStrategy(),
            "scanning":           ScanningStrategy(),
            "fraud":              FraudStrategy(),
            "unknown_suspicious": UnknownStrategy(),
        }
        self._engine_state: dict = {}

        logger.info(
            "GATE80 DeceptionEngine initialised — strategies: %s",
            list(self._strategies.keys()),
        )

    def _get_strategy(self, attack_type: str):
        strategy = self._strategies.get(attack_type)
        if strategy is None:
            logger.warning(
                "Unknown attack_type '%s' — falling back to unknown_suspicious",
                attack_type,
            )
            strategy = self._strategies["unknown_suspicious"]
        return strategy

    async def pre_process(self, request: Request, attack_type: str) -> None:
        strategy = self._get_strategy(attack_type)
        await strategy.pre_process(request)

    async def post_process(
        self,
        body: bytes,
        status_code: int,
        attack_type: str,
        path: str,
        session_id: str,
    ) -> tuple[bytes, int]:
        # ── Increment shared session-level request counter ────────────────────
        # This happens BEFORE dispatching to the strategy so the counter
        # reflects the current request. The scanning strategy reads this
        # to enforce its threshold from the first flagged request.
        count_key = SHARED_REQUEST_COUNT_KEY.format(session_id=session_id)
        self._engine_state[count_key] = self._engine_state.get(count_key, 0) + 1

        logger.debug(
            "DECOY [ENGINE] session=%s total_decoy_requests=%d attack_type=%s",
            session_id, self._engine_state[count_key], attack_type,
        )

        # ── Dispatch to strategy ──────────────────────────────────────────────
        strategy = self._get_strategy(attack_type)
        modified_body, modified_status = await strategy.post_process(
            body, status_code, path, session_id, self._engine_state
        )

        if modified_status != status_code or modified_body != body:
            logger.info(
                "DECOY 🎭 [ENGINE] transformed response: "
                "attack_type=%-20s  path=%-40s  %d → %d",
                attack_type, path, status_code, modified_status,
            )

        return modified_body, modified_status