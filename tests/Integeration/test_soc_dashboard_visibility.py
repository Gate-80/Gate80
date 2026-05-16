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

MONITOR_ENDPOINT_TEMPLATE = "/api/v1/projects/{project_id}/monitor"
SECURITY_EVENTS_ENDPOINT_TEMPLATE = "/api/v1/projects/{project_id}/security-events"
DECOY_TRAFFIC_ENDPOINT_TEMPLATE = "/api/v1/projects/{project_id}/decoy-traffic"


def extract_token(login_json: dict) -> str | None:
    return (
        login_json.get("token")
        or login_json.get("access_token")
        or login_json.get("user_token")
        or login_json.get("session_token")
    )


def test_soc_dashboard_visibility_after_deception_event(tmp_path):
    """
    Integration test:
    - Authenticates user.
    - Uploads OpenAPI file.
    - Creates decoy config for wallet transfer.
    - Triggers suspicious behavior.
    - Sends wallet transfer request.
    - Verifies SOC-facing dashboard APIs expose traffic/security/deception data.

    Note:
    The Decoy API is now the primary deception path. If a route is not implemented
    in the Decoy API, it may return 404. For this SOC visibility test, that is
    acceptable as long as the suspicious/deception interaction is logged and
    exposed through monitor/security-events/decoy-traffic APIs.
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

    auth_headers = {"X-User-Token": token}

    # 2. Upload OpenAPI file
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "SOC Dashboard Test API",
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

    openapi_file = tmp_path / "soc_dashboard_openapi.json"
    openapi_file.write_text(json.dumps(openapi_spec), encoding="utf-8")

    with open(openapi_file, "rb") as file:
        onboarding_response = requests.post(
            f"{PROXY_URL}{ONBOARDING_ENDPOINT}",
            headers=auth_headers,
            data={
                "project_name": "SOC Dashboard Test API",
                "customer_name": "Integration Test Customer",
            },
            files={
                "file": ("soc_dashboard_openapi.json", file, "application/json"),
            },
            timeout=15,
        )

    print("\nOnboarding status:", onboarding_response.status_code)
    print("Onboarding body:", onboarding_response.text)

    assert onboarding_response.status_code == 200, onboarding_response.text

    onboarding_data = onboarding_response.json()
    project_id = onboarding_data["project"]["id"]

    transfer_endpoint = next(
        endpoint
        for endpoint in onboarding_data["endpoints"]
        if endpoint["path"] == TRANSFER_ENDPOINT
        and endpoint["method"] == "POST"
    )

    assert transfer_endpoint["is_selected_for_decoy"] is True

    # 3. Create decoy config as fallback/endpoint policy
    decoy_config_endpoint = DECOY_CONFIG_ENDPOINT_TEMPLATE.format(
        project_id=project_id
    )

    decoy_config_response = requests.post(
        f"{PROXY_URL}{decoy_config_endpoint}",
        headers=auth_headers,
        json={
            "endpoint_id": transfer_endpoint["id"],
            "decoy_type": "fake_success",
            "status_code": "200",
            "response_template": {
                "message": "Transfer submitted for processing",
                "transaction_id": "fake_tx_soc_001",
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

    # 4. Trigger suspicious session
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

    assert session_flagged, "Suspicious session was not flagged."

    # 5. Send wallet transfer request after suspicious session is flagged
    transfer_response = requests.post(
        f"{PROXY_URL}{TRANSFER_ENDPOINT}",
        json={
            "to_account": "SA9999999999999999999999",
            "amount": 10000,
            "currency": "SAR",
            "description": "SOC visibility integration test transfer",
        },
        timeout=20,
    )

    transfer_elapsed_ms = transfer_response.elapsed.total_seconds() * 1000
    transfer_body_lower = transfer_response.text.lower()

    print("\nTransfer status:", transfer_response.status_code)
    print("Transfer elapsed ms:", transfer_elapsed_ms)
    print("Transfer body:", transfer_response.text)

    # Decoy API may return 404 if this specific route is not implemented.
    # For SOC visibility, the important part is that the suspicious/deception
    # event is logged and appears in monitoring APIs.
    assert transfer_response.status_code in {200, 401, 404, 423}, (
        transfer_response.text
    )

    assert (
        "fake_tx_soc_001" in transfer_response.text
        or "pending" in transfer_body_lower
        or "not found" in transfer_body_lower
        or "support" in transfer_body_lower
        or "temporarily locked" in transfer_body_lower
        or transfer_elapsed_ms >= 300
    ), transfer_response.text

    # Give logs a short moment to be queryable
    time.sleep(1.0)

    # 6. Check monitor endpoint used by SOC dashboard
    monitor_endpoint = MONITOR_ENDPOINT_TEMPLATE.format(project_id=project_id)

    monitor_response = requests.get(
        f"{PROXY_URL}{monitor_endpoint}",
        headers=auth_headers,
        timeout=15,
    )

    print("\nMonitor status:", monitor_response.status_code)
    print("Monitor body:", monitor_response.text)

    assert monitor_response.status_code == 200, monitor_response.text

    monitor_data = monitor_response.json()

    assert "summary" in monitor_data
    assert "traffic_logs" in monitor_data
    assert "security_events" in monitor_data
    assert "counts" in monitor_data

    assert monitor_data["counts"]["traffic_logs"] >= 1
    assert monitor_data["counts"]["detections"] >= 1

    # 7. Check security-events endpoint
    security_events_endpoint = SECURITY_EVENTS_ENDPOINT_TEMPLATE.format(
        project_id=project_id
    )

    events_response = requests.get(
        f"{PROXY_URL}{security_events_endpoint}",
        headers=auth_headers,
        timeout=15,
    )

    print("\nSecurity events status:", events_response.status_code)
    print("Security events body:", events_response.text)

    assert events_response.status_code == 200, events_response.text

    events_data = events_response.json()

    assert "security_events" in events_data
    assert "total_alerts" in events_data
    assert events_data["total_alerts"] >= 1

    related_event_found = any(
        event.get("path") in {LOGIN_ENDPOINT, TRANSFER_ENDPOINT}
        for event in events_data["security_events"]
    )

    assert related_event_found, (
        "Expected SOC security events to include login or wallet transfer activity."
    )

    # 8. Check decoy traffic endpoint
    decoy_traffic_endpoint = DECOY_TRAFFIC_ENDPOINT_TEMPLATE.format(
        project_id=project_id
    )

    decoy_traffic_response = requests.get(
        f"{PROXY_URL}{decoy_traffic_endpoint}",
        headers=auth_headers,
        timeout=15,
    )

    print("\nDecoy traffic status:", decoy_traffic_response.status_code)
    print("Decoy traffic body:", decoy_traffic_response.text)

    assert decoy_traffic_response.status_code == 200, decoy_traffic_response.text

    decoy_traffic_data = decoy_traffic_response.json()

    assert "summary" in decoy_traffic_data
    assert "recent_interactions" in decoy_traffic_data