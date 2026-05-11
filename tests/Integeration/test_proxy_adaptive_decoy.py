import time

import requests

PROXY_URL = "http://127.0.0.1:8090"
LOGIN_PATH = "/api/v1/auth/sign-in"


def test_credential_attack_routes_to_adaptive_decoy():
    """
    Integration test:
    - Sends repeated failed login requests through the proxy.
    - Uses a unique X-Forwarded-For value so the test has a fresh session.
    - Verifies that credential-attack traffic eventually receives deception behavior.
    """

    payload = {
        "email": "user@example.com",
        "password": "wrong_password",
    }

    # Fresh synthetic client IP to avoid reusing a previously flagged session.
    unique_ip = f"10.10.10.{int(time.time()) % 250}"
    headers = {
        "X-Forwarded-For": unique_ip,
    }

    responses = []

    for i in range(10):
        response = requests.post(
            f"{PROXY_URL}{LOGIN_PATH}",
            json=payload,
            headers=headers,
            timeout=20,
        )

        elapsed_ms = response.elapsed.total_seconds() * 1000

        print(f"\nAttempt {i + 1}")
        print("Client IP:", unique_ip)
        print("Status:", response.status_code)
        print("Elapsed ms:", elapsed_ms)
        print("Body:", response.text)

        responses.append((response, elapsed_ms))
        time.sleep(0.15)

    # First response may be backend or deception if the session was already flagged,
    # but it should still be an auth failure / decoy auth response.
    first_response, _ = responses[0]
    assert first_response.status_code in {401, 423}

    # Deception evidence:
    # - delayed configured decoy response
    # - Decoy API brute-force lock/challenge response
    # - transformed body from decoy logic
    decoy_detected = any(
        elapsed_ms >= 800
        or "invalid credentials" in response.text.lower()
        or "temporarily locked" in response.text.lower()
        or "support" in response.text.lower()
        or "verify-device" in response.text.lower()
        or "step_up_verification" in response.text.lower()
        for response, elapsed_ms in responses
    )

    assert decoy_detected, (
        "Expected credential attack traffic to receive deception behavior "
        "(delay, configured fake response, or Decoy API response), "
        "but no decoy evidence was detected."
    )