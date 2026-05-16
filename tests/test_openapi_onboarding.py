import json
from pathlib import Path

import requests

PROXY_URL = "http://127.0.0.1:8090"

LOGIN_ENDPOINT = "/api/v1/auth/sign-in"
ONBOARDING_ENDPOINT = "/api/v1/onboarding/parse-openapi-file"


def extract_token(login_json: dict) -> str | None:
    """
    Handles different possible token response formats.
    Adjust this if your backend uses a different field name.
    """
    return (
        login_json.get("token")
        or login_json.get("access_token")
        or login_json.get("user_token")
        or login_json.get("session_token")
    )


def test_openapi_file_upload_extracts_endpoints(tmp_path):
    """
    Integration test:
    - Authenticates through the proxy.
    - Uploads an OpenAPI file through the onboarding route.
    - Verifies project creation and endpoint extraction.
    """

    # 1. Login first because onboarding requires X-User-Token
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

    login_data = login_response.json()
    token = extract_token(login_data)

    assert token, f"No token found in login response: {login_data}"

    # 2. Build temporary OpenAPI file
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Test Bank API",
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
            "/api/v1/wallet/balance": {
                "get": {
                    "summary": "Get wallet balance",
                    "responses": {
                        "200": {"description": "Balance returned"},
                    },
                }
            },
        },
    }

    openapi_file = tmp_path / "test_openapi.json"
    openapi_file.write_text(json.dumps(openapi_spec), encoding="utf-8")

    # 3. Upload OpenAPI file with user token
    with open(openapi_file, "rb") as file:
        response = requests.post(
            f"{PROXY_URL}{ONBOARDING_ENDPOINT}",
            headers={
                "X-User-Token": token,
            },
            data={
                "project_name": "Integration Test Bank API",
                "customer_name": "Integration Test Customer",
            },
            files={
                "file": ("test_openapi.json", file, "application/json"),
            },
            timeout=15,
        )

    print("\nOnboarding status:", response.status_code)
    print("Onboarding body:", response.text)

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["message"] == "OpenAPI parsed and project created successfully"

    assert "project" in data
    assert "id" in data["project"]
    assert data["project"]["name"] == "Integration Test Bank API"
    assert data["project"]["customer_name"] == "Integration Test Customer"

    assert data["total_endpoints"] == 3
    assert "endpoints" in data
    assert len(data["endpoints"]) == 3

    extracted_paths = {endpoint["path"] for endpoint in data["endpoints"]}

    assert "/api/v1/auth/sign-in" in extracted_paths
    assert "/api/v1/wallet/transfer" in extracted_paths
    assert "/api/v1/wallet/balance" in extracted_paths

    for endpoint in data["endpoints"]:
        assert "id" in endpoint
        assert "path" in endpoint
        assert "method" in endpoint
        assert "risk_score" in endpoint
        assert "risk_level" in endpoint
        assert "is_selected_for_decoy" in endpoint

    high_risk_endpoints = [
        endpoint for endpoint in data["endpoints"]
        if endpoint["risk_level"] == "high"
    ]

    assert len(high_risk_endpoints) >= 1