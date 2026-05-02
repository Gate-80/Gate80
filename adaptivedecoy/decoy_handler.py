from __future__ import annotations

from typing import Any

from .schemas import DecoyPlan, SessionSummary


def apply_decoy_plan(
    plan: DecoyPlan,
    session: SessionSummary,
    request_path: str,
    request_method: str,
) -> dict[str, Any]:
    """
    Dispatches the decoy strategy to the correct handler.

    Returns a normalized response dict so your proxy/backend can
    translate it into an HTTP response.
    """
    if plan.strategy == "fake_endpoint_surface":
        return handle_fake_endpoint_surface(plan, session, request_path, request_method)

    if plan.strategy == "auth_honey_flow":
        return handle_auth_honey_flow(plan, session, request_path, request_method)

    if plan.strategy == "fake_business_flow":
        return handle_fake_business_flow(plan, session, request_path, request_method)

    if plan.strategy == "sinkhole_signup_flow":
        return handle_sinkhole_signup_flow(plan, session, request_path, request_method)

    raise ValueError(f"Unsupported decoy strategy: {plan.strategy}")


def handle_fake_endpoint_surface(
    plan: DecoyPlan,
    session: SessionSummary,
    request_path: str,
    request_method: str,
) -> dict[str, Any]:
    """
    Best first handler for your current scope.

    Returns plausible but fake API guidance for endpoint scanning.
    """
    endpoint_sets = {
        "low": [
            "/api/v2/status/extended",
            "/api/internal/diagnostics",
        ],
        "medium": [
            "/api/v2/status/extended",
            "/api/internal/diagnostics",
            "/api/admin/audit/export",
            "/api/debug/health-expanded",
        ],
        "high": [
            "/api/v2/status/extended",
            "/api/internal/diagnostics",
            "/api/admin/audit/export",
            "/api/debug/health-expanded",
            "/api/v3/partner/shadow-sync",
            "/api/private/schema/cache-index",
        ],
    }

    fake_hints = endpoint_sets[plan.decoy_depth]

    response_body = {
        "message": "Additional API surfaces may be available.",
        "hint_type": "supplemental_inventory",
        "candidate_endpoints": fake_hints,
        "request_echo": {
            "path": request_path,
            "method": request_method,
        },
        "session_id": session.session_id,
        "note": "Authentication may be required for some routes.",
    }

    return {
        "mode": "decoy",
        "strategy": plan.strategy,
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-Decoy-Strategy": plan.strategy,
            "X-Decoy-TTL": str(plan.ttl_seconds),
        },
        "body": response_body,
    }


def handle_auth_honey_flow(
    plan: DecoyPlan,
    session: SessionSummary,
    request_path: str,
    request_method: str,
) -> dict[str, Any]:
    return {
        "mode": "decoy",
        "strategy": plan.strategy,
        "status_code": 401,
        "headers": {
            "Content-Type": "application/json",
            "X-Decoy-Strategy": plan.strategy,
        },
        "body": {
            "message": "Authentication challenge issued.",
            "challenge_type": "step_up_verification",
            "next": "/api/auth/verify-device",
            "session_id": session.session_id,
        },
    }


def handle_fake_business_flow(
    plan: DecoyPlan,
    session: SessionSummary,
    request_path: str,
    request_method: str,
) -> dict[str, Any]:
    return {
        "mode": "decoy",
        "strategy": plan.strategy,
        "status_code": 202,
        "headers": {
            "Content-Type": "application/json",
            "X-Decoy-Strategy": plan.strategy,
        },
        "body": {
            "message": "Transaction queued for review.",
            "review_state": "pending_manual_settlement",
            "reference": f"decoy-{session.session_id[:8]}",
            "session_id": session.session_id,
        },
    }


def handle_sinkhole_signup_flow(
    plan: DecoyPlan,
    session: SessionSummary,
    request_path: str,
    request_method: str,
) -> dict[str, Any]:
    return {
        "mode": "decoy",
        "strategy": plan.strategy,
        "status_code": 201,
        "headers": {
            "Content-Type": "application/json",
            "X-Decoy-Strategy": plan.strategy,
        },
        "body": {
            "message": "Account created successfully.",
            "next": "/api/onboarding/verify-email",
            "verification_state": "pending",
            "session_id": session.session_id,
        },
    }