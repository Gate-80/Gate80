from __future__ import annotations

from typing import Any

from backend_api.db.models import EndpointInventory


def _target(endpoint: EndpointInventory) -> str:
    return f"{endpoint.method or ''} {endpoint.path or ''} {endpoint.tag or ''} {endpoint.summary or ''}".lower()


def generate_decoy_for_endpoint(endpoint: EndpointInventory) -> dict[str, Any]:
    target = _target(endpoint)
    method = (endpoint.method or "GET").upper()

    if any(word in target for word in ("login", "signin", "sign-in", "auth", "token", "otp")):
        return {
            "name": "Authentication decoy",
            "description": "Returns a believable fake session response for suspicious authentication attempts.",
            "decoy_type": "fake_success",
            "status_code": "200",
            "delay_ms": "250",
            "response_template": {
                "access_token": "decoy_token_${request_id}",
                "token_type": "bearer",
                "expires_in": 900,
                "user": {
                    "id": "u_decoy",
                    "email": "verified.user@example.com",
                    "status": "verified",
                },
            },
            "headers_template": {"X-Gate80-Decoy": "auth"},
            "trigger_condition": {"when": "suspicious_session", "endpoint_class": "authentication"},
        }

    if any(word in target for word in ("transfer", "withdraw", "payment", "pay", "bill", "wallet")):
        return {
            "name": "Financial action decoy",
            "description": "Accepts suspicious financial actions into a fake pending state.",
            "decoy_type": "honey_data",
            "status_code": "202",
            "delay_ms": "400",
            "response_template": {
                "transaction_id": "tx_decoy_${request_id}",
                "status": "processing",
                "message": "Request accepted and pending verification.",
                "risk_review": "manual_review_required",
            },
            "headers_template": {"X-Gate80-Decoy": "financial"},
            "trigger_condition": {"when": "suspicious_session", "endpoint_class": "financial"},
        }

    if "admin" in target:
        return {
            "name": "Admin surface decoy",
            "description": "Slows suspicious admin requests and returns harmless fake admin data.",
            "decoy_type": "delayed_response",
            "status_code": "200",
            "delay_ms": "900",
            "response_template": {
                "status": "queued",
                "message": "Admin request accepted for processing.",
                "reference": "adm_decoy_${request_id}",
            },
            "headers_template": {"X-Gate80-Decoy": "admin"},
            "trigger_condition": {"when": "suspicious_session", "endpoint_class": "admin"},
        }

    if method == "DELETE":
        return {
            "name": "Delete protection decoy",
            "description": "Blocks suspicious destructive requests with a safe fake failure.",
            "decoy_type": "fake_failure",
            "status_code": "403",
            "delay_ms": "150",
            "response_template": {
                "detail": "Operation requires additional verification.",
                "reference": "deny_decoy_${request_id}",
            },
            "headers_template": {"X-Gate80-Decoy": "destructive"},
            "trigger_condition": {"when": "suspicious_session", "endpoint_class": "destructive"},
        }

    return {
        "name": "Generic API decoy",
        "description": "Returns harmless synthetic data for suspicious requests to this endpoint.",
        "decoy_type": "honey_data",
        "status_code": "200",
        "delay_ms": "200",
        "response_template": {
            "id": "decoy_${request_id}",
            "status": "ok",
            "message": "Request completed.",
        },
        "headers_template": {"X-Gate80-Decoy": "generic"},
        "trigger_condition": {"when": "suspicious_session", "endpoint_class": "generic"},
    }
