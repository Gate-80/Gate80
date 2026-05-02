from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import ValidationError

from .schemas import DecoyPlan, SessionSummary

logger = logging.getLogger(__name__)

ALLOWED_STRATEGIES_BY_ATTACK_TYPE = {
    "credential_based_attacks": {"auth_honey_flow"},
    "endpoint_scanning": {"fake_endpoint_surface"},
    "financial_fraud": {"fake_business_flow"},
    "account_creation": {"sinkhole_signup_flow"},
}

FALLBACK_PLANS = {
    "credential_based_attacks": {
        "attack_type": "credential_based_attacks",
        "confidence": 0.70,
        "strategy": "auth_honey_flow",
        "decoy_depth": "medium",
        "ttl_seconds": 180,
        "reason": "Fallback rule for credential-based activity",
    },
    "endpoint_scanning": {
        "attack_type": "endpoint_scanning",
        "confidence": 0.70,
        "strategy": "fake_endpoint_surface",
        "decoy_depth": "medium",
        "ttl_seconds": 180,
        "reason": "Fallback rule for endpoint scanning",
    },
    "financial_fraud": {
        "attack_type": "financial_fraud",
        "confidence": 0.70,
        "strategy": "fake_business_flow",
        "decoy_depth": "medium",
        "ttl_seconds": 180,
        "reason": "Fallback rule for financial fraud",
    },
    "account_creation": {
        "attack_type": "account_creation",
        "confidence": 0.70,
        "strategy": "sinkhole_signup_flow",
        "decoy_depth": "medium",
        "ttl_seconds": 180,
        "reason": "Fallback rule for suspicious account creation",
    },
}

SYSTEM_PROMPT = """
You are a decoy-strategy selector for an API defense system.

Return JSON only.
Do not add markdown.
Do not invent attack types, strategies, or fields.

Allowed mappings:
- credential_based_attacks -> auth_honey_flow
- endpoint_scanning -> fake_endpoint_surface
- financial_fraud -> fake_business_flow
- account_creation -> sinkhole_signup_flow

Allowed decoy_depth values:
- low
- medium
- high

Rules:
- confidence must be between 0.0 and 1.0
- ttl_seconds must be between 60 and 600
- keep reason short
- strategy must match the attack type
- prefer low or medium unless signals are clearly strong

Return exactly:
{
  "attack_type": "...",
  "confidence": 0.0,
  "strategy": "...",
  "decoy_depth": "...",
  "ttl_seconds": 0,
  "reason": "..."
}
""".strip()


def build_llm_payload(session: SessionSummary) -> dict[str, Any]:
    return {
        "system_prompt": SYSTEM_PROMPT,
        "user_input": session.model_dump(),
    }


def parse_llm_json(raw_text: str) -> dict[str, Any]:
    """
    Parses raw LLM text output into JSON.

    Assumes the LLM was instructed to return JSON only.
    """
    return json.loads(raw_text)


def validate_decoy_plan(
    plan_data: dict[str, Any],
    expected_attack_type: str,
) -> DecoyPlan:
    """
    Validates schema and policy constraints.
    Raises ValueError on any policy violation.
    """
    try:
        plan = DecoyPlan(**plan_data)
    except ValidationError as exc:
        raise ValueError(f"Schema validation failed: {exc}") from exc

    if plan.attack_type != expected_attack_type:
        raise ValueError(
            f"Attack type mismatch: expected {expected_attack_type}, got {plan.attack_type}"
        )

    allowed = ALLOWED_STRATEGIES_BY_ATTACK_TYPE.get(plan.attack_type, set())
    if plan.strategy not in allowed:
        raise ValueError(
            f"Invalid strategy {plan.strategy!r} for attack type {plan.attack_type!r}"
        )

    return plan


def get_fallback_plan(attack_type: str) -> DecoyPlan:
    if attack_type not in FALLBACK_PLANS:
        raise ValueError(f"No fallback plan configured for attack type: {attack_type}")
    return DecoyPlan(**FALLBACK_PLANS[attack_type])


def choose_decoy_plan(
    session: SessionSummary,
    llm_raw_response: str | None,
) -> DecoyPlan:
    """
    Main policy entrypoint.

    If the LLM response is missing or invalid, returns the fallback plan.
    """
    if not llm_raw_response:
        logger.warning("No LLM response received; using fallback plan.")
        return get_fallback_plan(session.candidate_attack_type)

    try:
        plan_data = parse_llm_json(llm_raw_response)
        return validate_decoy_plan(
            plan_data=plan_data,
            expected_attack_type=session.candidate_attack_type,
        )
    except Exception as exc:
        logger.warning(
            "Invalid LLM decoy plan for session %s; using fallback. Error: %s",
            session.session_id,
            exc,
        )
        return get_fallback_plan(session.candidate_attack_type)