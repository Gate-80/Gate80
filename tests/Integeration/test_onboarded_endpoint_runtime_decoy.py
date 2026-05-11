import json
import time

import requests

PROXY_URL = "http://127.0.0.1:8090"

LOGIN_ENDPOINT = "/api/v1/auth/sign-in"
ONBOARDING_ENDPOINT = "/api/v1/onboarding/parse-openapi-file"
TRANSFER_ENDPOINT = "/api/v1/wallet/transfer"

DECOY_CONFIG_ENDPOINT_TEMPLATE = (
    "/api/v1/onboarding/projects/{project_id}/decoy-configs"
)


def extract_token(login_json: dict) -> str | None:
    return (
        login_json.get("token")
        or login_json.get("access_token")
        or login_json.get("user_token")
        or login_json.get("session_token")
    )


def test_onboarded_wallet_transfer_endpoint_enforces_deception(tmp_path):
    """
    Integration test:
    - Authenticates user.
    - Uploads OpenAPI file containing wallet transfer endpoint.
    - Verifies wallet transfer is extracted and selected as high-risk decoy candidate.
    - Creates decoy_config for the extracted wallet transfer endpoint.
    - Triggers suspicious behavior until the proxy flags the session.
    - Sends wallet transfer request and verifies deception behavior is applied.
    """

    # 1. Login
    login_response = requests.post(
        f"{PROXY_URL}{LOGIN_ENDPOINT}",
        json={
            "email": "user@example.com",
            "password": "password123",
        },
        timeout=10,
    )

    print("\nLogin status:", login_response.status_code)
    print("Login body:", login_response.text)

    assert login_response.status_code == 200, login_response.text

    token = extract_token(login_response.json())
    assert token, login_response.text

    # 2. Build OpenAPI file
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Runtime Decoy Test API",
            "version": "1.0.0",
        },
        "paths": {
            "/api/v1/auth/sign-in": {
                "post": {
                    "summary": "User login",
                    "responses": {
                        "200": {"description": "Login successful"},
                        "401": {"description": "Invalid credentials"},
                    },
                }
            },
            "/api/v1/wallet/transfer": {
                "post": {
                    "summary": "Transfer money",
                    "responses": {
                        "200": {"description": "Transfer successful"},
                        "400": {"description": "Invalid transfer"},
                    },
                }
            },
        },
    }

    openapi_file = tmp_path / "runtime_decoy_openapi.json"
    openapi_file.write_text(json.dumps(openapi_spec), encoding="utf-8")

    # 3. Upload OpenAPI file
    with open(openapi_file, "rb") as file:
        onboarding_response = requests.post(
            f"{PROXY_URL}{ONBOARDING_ENDPOINT}",
            headers={"X-User-Token": token},
            data={
                "project_name": "Runtime Decoy Test API",
                "customer_name": "Integration Test Customer",
            },
            files={
                "file": ("runtime_decoy_openapi.json", file, "application/json"),
            },
            timeout=15,
        )

    print("\nOnboarding status:", onboarding_response.status_code)
    print("Onboarding body:", onboarding_response.text)

    assert onboarding_response.status_code == 200, onboarding_response.text

    onboarding_data = onboarding_response.json()
    project_id = onboarding_data["project"]["id"]
    endpoints = onboarding_data["endpoints"]

    transfer_endpoint = next(
        endpoint
        for endpoint in endpoints
        if endpoint["path"] == TRANSFER_ENDPOINT
        and endpoint["method"] == "POST"
    )

    assert transfer_endpoint["risk_level"] == "high"
    assert transfer_endpoint["is_selected_for_decoy"] is True

    # 4. Create decoy config for the extracted wallet transfer endpoint
    decoy_config_endpoint = DECOY_CONFIG_ENDPOINT_TEMPLATE.format(
        project_id=project_id
    )

    decoy_config_response = requests.post(
        f"{PROXY_URL}{decoy_config_endpoint}",
        headers={"X-User-Token": token},
        json={
            "endpoint_id": transfer_endpoint["id"],
            "decoy_type": "fake_success",
            "status_code": "200",
            "response_template": {
                "message": "Transfer submitted for processing",
                "transaction_id": "fake_tx_integration_001",
                "status": "pending",
            },
            "delay_ms": "1000",
            "is_enabled": True,
        },
        timeout=15,
    )

    print("\nDecoy config status:", decoy_config_response.status_code)
    print("Decoy config body:", decoy_config_response.text)

    assert decoy_config_response.status_code == 200, decoy_config_response.text

    # 5. Trigger suspicious session until deception starts.
    # These requests intentionally do not use the valid token, so the proxy groups
    # them by IP and should flag the session after repeated failures.
    wrong_login_payload = {
        "email": "user@example.com",
        "password": "wrong_password",
    }

    session_flagged = False

    for i in range(12):
        response = requests.post(
            f"{PROXY_URL}{LOGIN_ENDPOINT}",
            json=wrong_login_payload,
            timeout=20,
        )

        elapsed_ms = response.elapsed.total_seconds() * 1000
        body_lower = response.text.lower()

        print(f"\nSuspicious login attempt {i + 1}")
        print("Status:", response.status_code)
        print("Elapsed ms:", elapsed_ms)
        print("Body:", response.text)

        if (
            elapsed_ms >= 800
            or "invalid credentials" in body_lower
            or "temporarily locked" in body_lower
            or "support" in body_lower
        ):
            session_flagged = True
            break

        time.sleep(0.15)

    assert session_flagged, (
        "Suspicious session was not flagged before wallet transfer. "
        "Check proxy RF threshold/model logs."
    )

    # 6. Send wallet transfer request after suspicious session is flagged
    transfer_payload = {
        "to_account": "SA9999999999999999999999",
        "amount": 10000,
        "currency": "SAR",
        "description": "integration test suspicious transfer",
    }

    transfer_response = requests.post(
        f"{PROXY_URL}{TRANSFER_ENDPOINT}",
        json=transfer_payload,
        timeout=20,
    )

    elapsed_ms = transfer_response.elapsed.total_seconds() * 1000
    body_lower = transfer_response.text.lower()

    print("\nTransfer status:", transfer_response.status_code)
    print("Transfer elapsed ms:", elapsed_ms)
    print("Transfer body:", transfer_response.text)

    deception_detected = (
        elapsed_ms >= 800
        or "fake" in body_lower
        or "fake_tx" in body_lower
        or "transfer submitted" in body_lower
        or "pending" in body_lower
        or "support" in body_lower
        or "deception" in body_lower
        or "temporarily" in body_lower
    )

    assert deception_detected, (
        "Expected wallet transfer request to receive deception behavior "
        "after suspicious session was flagged."
    )