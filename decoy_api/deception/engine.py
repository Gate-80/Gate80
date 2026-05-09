"""
GATE80 — Decoy API
deception/engine.py

Central DeceptionEngine — single point of control for all adaptive
deception behavior.

Phase 9 — LLM short-circuit:
  When the deterministic strategy already returned a "strong" status
  (423 lockout, 429 rate-limit, 5xx error), the response is complete
  and Claude has nothing useful to add. Skip the LLM call entirely
  and surface a plan_result with source="skipped". Saves Claude API
  cost and ~1.5s of latency on lockout/rate-limit responses.

  Matches the canonical hybrid-honeypot architecture (Bridges et al.
  SoK Oct 2025): deterministic responder handles trivial/cached cases,
  LLM only invoked for novel cases.
"""

import logging
from fastapi import Request

from decoy_api.deception.strategies.credential_based_attacks import CredentialBasedAttacksStrategy
from decoy_api.deception.strategies.endpoint_scanning        import EndpointScanningStrategy
from decoy_api.deception.strategies.financial_fraud          import FinancialFraudStrategy
from decoy_api.deception.strategies.account_creation         import AccountCreationStrategy
from decoy_api.deception.strategies.unknown                  import UnknownStrategy
from decoy_api.audit_log import append_llm_audit
from decoy_api.deception.planner import (
    DeceptionPlan,
    DeceptionPlanner,
    PlanApplicationResult,
    PlanContext,
    PlanGenerationResult,
)

logger = logging.getLogger("decoy.deception.engine")

SHARED_REQUEST_COUNT_KEY = "decoy:request_count:{session_id}"


def _strategy_already_strong(status_code: int) -> bool:
    """True when the strategy's response is final and the LLM has nothing to add.

    - 423 Locked          credential_based_attacks lockout — message is complete
    - 429 Too Many Reqs   endpoint_scanning rate limit — message is complete
    - 5xx                 errors — don't decorate errors with fake data
    """
    if status_code == 423 or status_code == 429:
        return True
    if 500 <= status_code < 600:
        return True
    return False


class DeceptionEngine:

    def __init__(self):
        self._strategies = {
            "credential_based_attacks": CredentialBasedAttacksStrategy(),
            "endpoint_scanning":        EndpointScanningStrategy(),
            "financial_fraud":          FinancialFraudStrategy(),
            "account_creation":         AccountCreationStrategy(),
            "unknown_suspicious":       UnknownStrategy(),
        }
        self._engine_state: dict = {}
        self._planner = DeceptionPlanner()

        logger.info(
            "GATE80 DeceptionEngine initialised — strategies: %s — planner backend: %s",
            list(self._strategies.keys()),
            self._planner.backend_name,
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

        # ── Phase 9: short-circuit if strategy gave a strong response ─────────
        if _strategy_already_strong(modified_status):
            preview = modified_body.decode("utf-8", errors="ignore")
            if len(preview) > 2000:
                preview = preview[:2000] + "...[truncated]"

            plan_result = PlanGenerationResult(
                source="skipped",
                model_name="strategy-only",
                plan=DeceptionPlan(
                    rationale=f"Strategy returned strong override (status={modified_status}); LLM skipped",
                    confidence=1.0,
                ),
            )
            application_result = PlanApplicationResult(
                final_status_code=modified_status,
                final_body_preview=preview,
            )

            logger.info(
                "DECOY [PLAN] request=%s source=skipped attack_type=%s status=%d (LLM bypassed)",
                request_id, attack_type, modified_status,
            )
            append_llm_audit(
                request_id=request_id,
                session_id=session_id,
                attack_type=attack_type,
                method=method,
                path=path,
                model=plan_result.model_name,
                source=plan_result.source,
                prompt=None,
                raw_response=None,
                applied_actions=application_result.applied_actions,
                rejected_actions=application_result.rejected_actions,
                error_message=plan_result.error_message,
            )
            return modified_body, modified_status, plan_result, application_result

        # ── Otherwise: build context, call LLM, apply plan ────────────────────
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
                "DECOY [ENGINE] transformed response: "
                "attack_type=%-26s  path=%-40s  %d -> %d",
                attack_type, path, status_code, final_status,
            )

        logger.info(
            "DECOY [PLAN] request=%s source=%s attack_type=%s applied=%d rejected=%d",
            request_id,
            plan_result.source,
            attack_type,
            len(application_result.applied_actions),
            len(application_result.rejected_actions),
        )

        append_llm_audit(
            request_id=request_id,
            session_id=session_id,
            attack_type=attack_type,
            method=method,
            path=path,
            model=plan_result.model_name,
            source=plan_result.source,
            prompt=plan_result.prompt,
            raw_response=plan_result.raw_plan,
            applied_actions=application_result.applied_actions,
            rejected_actions=application_result.rejected_actions,
            error_message=plan_result.error_message,
        )

        return final_body, final_status, plan_result, application_result
