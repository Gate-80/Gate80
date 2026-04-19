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
from decoy_api.deception.planner import (
    GeminiDeceptionPlanner,
    PlanApplicationResult,
    PlanContext,
    PlanGenerationResult,
)

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
        self._planner = GeminiDeceptionPlanner()

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
        method: str,
        path: str,
        session_id: str,
        request_id: str,
        query_params: dict | None = None,
        request_body: str | None = None,
    ) -> tuple[bytes, int, PlanGenerationResult, PlanApplicationResult]:
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

        context = PlanContext(
            request_id=request_id,
            session_id=session_id,
            attack_type=attack_type,
            method=method,
            path=path,
            query_params=query_params or {},
            request_body=request_body,
            response_status=modified_status,
            response_body_preview=modified_body.decode("utf-8", errors="ignore"),
            decoy_request_count=self._engine_state[count_key],
        )
        plan_result = await self._planner.generate_plan(context)
        final_body, final_status, application_result = self._planner.apply_plan(
            plan_result.plan,
            attack_type,
            modified_body,
            modified_status,
        )

        if final_status != status_code or final_body != body:
            logger.info(
                "DECOY 🎭 [ENGINE] transformed response: "
                "attack_type=%-20s  path=%-40s  %d → %d",
                attack_type, path, status_code, final_status,
            )

        logger.info(
            "DECOY 🧠 [PLAN] request=%s source=%s attack_type=%s applied=%d rejected=%d",
            request_id,
            plan_result.source,
            attack_type,
            len(application_result.applied_actions),
            len(application_result.rejected_actions),
        )

        return final_body, final_status, plan_result, application_result
