"""
GATE80 — Full Adaptive Deception Test Suite
scripts/test_adaptive_decoy.py

Tests all 4 scenarios:
  1. Normal traffic  — should reach real backend, no flagging
  2. Brute force     — fast repeated auth failures → brute_force classification
  3. Scanning        — broad endpoint enumeration → scanning classification
  4. Fraud           — heavy financial operations → fraud classification

Tokens for tests 3 and 4 are obtained BEFORE the brute force test runs,
because brute force flags ip:127.0.0.1 and all subsequent IP-based requests
(including sign-ins) would hit the decoy.

Run from project root:
    python3 scripts/test_adaptive_decoy.py
"""

import httpx
import time
import json

PROXY = "http://127.0.0.1:8080/api/v1"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def sep(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def log(label: str, status: int, body, elapsed_ms: int):
    flag = "✅" if status < 400 else ("🔒" if status in (401, 423, 429) else "❌")
    print(f"  {flag} [{status}] {label:<45} {elapsed_ms}ms")
    if isinstance(body, dict):
        for k, v in body.items():
            if k in ("detail", "retry_after", "lock_level", "limit_level",
                     "new_balance", "message", "status", "did_you_mean",
                     "review_id", "balance"):
                print(f"       {k}: {v}")
    print()


def request(client: httpx.Client, method: str, path: str,
            headers: dict = None, json_body: dict = None,
            label: str = "") -> tuple:
    h = headers or {}
    start = time.time()
    try:
        r = client.request(
            method, f"{PROXY}{path}",
            headers=h, json=json_body, timeout=15
        )
        elapsed = int((time.time() - start) * 1000)
        try:
            body = r.json()
        except Exception:
            body = r.text
        log(label or path, r.status_code, body, elapsed)
        return r.status_code, body
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        print(f"  ❌ [{label}] ERROR: {e}  {elapsed}ms\n")
        return 0, {}


def get_token(client: httpx.Client, email: str, password: str) -> tuple:
    """Sign in and return (token, user_id) or (None, None) on failure."""
    start = time.time()
    try:
        r = client.post(
            f"{PROXY}/auth/sign-in",
            json={"email": email, "password": password},
            timeout=10
        )
        elapsed = int((time.time() - start) * 1000)
        body = r.json()
        if r.status_code == 200 and "token" in body:
            print(f"  ✅ [200] sign-in OK for {email}  {elapsed}ms")
            return body["token"], body["user_id"]
        else:
            print(f"  ❌ [sign-in failed for {email}] {body}  {elapsed}ms")
            return None, None
    except Exception as e:
        print(f"  ❌ sign-in error for {email}: {e}")
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — Normal Traffic
# ─────────────────────────────────────────────────────────────────────────────

def test_normal_traffic(token: str, user_id: str):
    sep("TEST 1 — NORMAL TRAFFIC (should reach real backend)")
    headers = {"X-User-Token": token}

    with httpx.Client() as c:
        time.sleep(0.3)
        request(c, "GET", "/auth/me", headers=headers, label="GET /auth/me")

        time.sleep(0.3)
        request(c, "GET", f"/users/{user_id}/wallet",
                headers=headers, label="GET /wallet")

        time.sleep(0.3)
        request(c, "POST", f"/users/{user_id}/wallet/topup",
                headers=headers, json_body={"amount": "50.00"},
                label="POST /wallet/topup")

        time.sleep(0.3)
        request(c, "GET", f"/users/{user_id}/wallet",
                headers=headers, label="GET /wallet (after topup)")

        time.sleep(0.3)
        request(c, "POST", "/auth/sign-out",
                headers=headers, label="POST /auth/sign-out")

    print("  → Expected: all 200, routed_to=backend, no attack_type in DB.")


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — Brute Force
# ─────────────────────────────────────────────────────────────────────────────

def test_brute_force():
    sep("TEST 2 — BRUTE FORCE (expect: brute_force + progressive lock)")

    with httpx.Client() as c:
        print("  Phase 1: Rapid auth failures to trigger detection...\n")
        for i in range(1, 11):
            request(c, "POST", "/auth/sign-in",
                    json_body={"email": "victim@example.com",
                               "password": f"wrongpass{i}"},
                    label=f"POST /auth/sign-in attempt #{i}")
            time.sleep(0.1)

        print("\n  Phase 2: Continued attempts — expect lock escalation...\n")
        for i in range(1, 7):
            request(c, "POST", "/auth/sign-in",
                    json_body={"email": "victim@example.com",
                               "password": f"wrongpass{i}"},
                    label=f"POST /auth/sign-in (decoy) attempt #{i}")
            time.sleep(0.2)

    print("  → Expected:")
    print("     Attempts 1-2:   401 (before flag)")
    print("     Attempt 3+:     401 with 2.5s delay (decoy, brute_force)")
    print("     After 3 fails:  423 lock_level=1  retry_after=1800")
    print("     Subsequent:     423 with countdown retry_after")


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — Scanning
# ─────────────────────────────────────────────────────────────────────────────

def test_scanning(token: str, user_id: str):
    sep("TEST 3 — ENDPOINT SCANNING (expect: scanning + rate limiting)")

    headers = {"X-User-Token": token}

    endpoints = [
        ("GET",  "/admin/users",                    "GET /admin/users"),
        ("GET",  "/admin/wallets",                  "GET /admin/wallets"),
        ("GET",  "/admin/transactions",             "GET /admin/transactions"),
        ("GET",  "/admin/overview/financial",       "GET /admin/overview/financial"),
        ("GET",  f"/users/{user_id}",               "GET /users/{id}"),
        ("GET",  f"/users/{user_id}/bank-accounts", "GET /bank-accounts"),
        ("GET",  f"/users/{user_id}/payments",      "GET /payments"),
        ("GET",  f"/users/{user_id}/wallet",        "GET /wallet"),
        ("GET",  "/nonexistent-endpoint",           "GET /nonexistent-1"),
        ("GET",  "/api/v1/config",                  "GET /config"),
        ("GET",  "/api/v1/admin/keys",              "GET /admin/keys"),
        ("GET",  "/api/v1/system/metrics",          "GET /system/metrics"),
        ("GET",  "/nonexistent-2",                  "GET /nonexistent-2"),
        ("GET",  "/nonexistent-3",                  "GET /nonexistent-3"),
        ("GET",  "/nonexistent-4",                  "GET /nonexistent-4"),
        ("GET",  "/nonexistent-5",                  "GET /nonexistent-5"),
        ("GET",  "/nonexistent-6",                  "GET /nonexistent-6"),
        ("GET",  "/nonexistent-7",                  "GET /nonexistent-7"),
    ]

    with httpx.Client() as c:
        print("  Probing many endpoints rapidly...\n")
        for method, path, label in endpoints:
            request(c, method, path, headers=headers, label=label)
            time.sleep(0.15)

    print("  → Expected:")
    print("     Requests 1-14:  normal responses + ghost endpoints on 404s  (0.8s delay)")
    print("     Request 15:     429 limit_level=1  retry_after=60")
    print("     Request 16+:    429 with countdown retry_after")


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Fraud
# ─────────────────────────────────────────────────────────────────────────────

def test_fraud(token: str, user_id: str):
    sep("TEST 4 — FINANCIAL FRAUD (expect: fraud + distorted responses)")

    headers = {"X-User-Token": token}

    with httpx.Client() as c:
        print("  Phase 1: Heavy financial ops to trigger fraud detection...\n")

        for i in range(1, 6):
            request(c, "POST", f"/users/{user_id}/wallet/topup",
                    headers=headers, json_body={"amount": "1000.00"},
                    label=f"POST /wallet/topup #{i}")
            time.sleep(0.1)

        for i in range(1, 5):
            request(c, "POST", f"/users/{user_id}/wallet/withdraw",
                    headers=headers, json_body={"amount": "100.00"},
                    label=f"POST /wallet/withdraw #{i}")
            time.sleep(0.1)

        print("  Phase 2: Check balance — should be distorted...\n")
        request(c, "GET", f"/users/{user_id}/wallet",
                headers=headers, label="GET /wallet (expect distorted balance)")

        print("  Phase 3: Transfer — should return 202 + queued...\n")
        request(c, "POST", f"/users/{user_id}/wallet/transfer/u_1001",
                headers=headers, json_body={"amount": "500.00"},
                label="POST /wallet/transfer (expect 202)")

    print("  → Expected:")
    print("     Topups/withdraws:  202  'Transaction submitted for compliance review'")
    print("     Balance:           200 but distorted ±10%")
    print("     Transfer:          202 with review_id")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔬 GATE80 Adaptive Deception — Full Test Suite")
    print("   Checking all servers...\n")

    for name, url in [("Proxy  :8080", "http://127.0.0.1:8080/health"),
                      ("Backend:8000", "http://127.0.0.1:8000/health"),
                      ("Decoy  :8001", "http://127.0.0.1:8001/health")]:
        try:
            httpx.get(url, timeout=3)
            print(f"  ✅ {name} reachable")
        except Exception:
            print(f"  ❌ {name} not reachable — start it first")
            exit(1)

    # ── Obtain all tokens BEFORE brute force flags the IP ────────────────────
    sep("PRE-TEST — Obtaining tokens for all tests")
    print("  Getting tokens before brute force flags ip:127.0.0.1...\n")

    with httpx.Client() as c:
        normal_token,   normal_uid   = get_token(c, "user@example.com",  "password123")
        scanning_token, scanning_uid = get_token(c, "user@example.com",  "password123")
        fraud_token,    fraud_uid    = get_token(c, "user@example.com",  "password123")

    if not all([normal_token, scanning_token, fraud_token]):
        print("\n  ❌ Could not obtain all tokens — check backend is running")
        exit(1)

    print("\n  ✅ All tokens obtained — running tests\n")

    # ── Run tests in order ────────────────────────────────────────────────────
    test_normal_traffic(normal_token, normal_uid)
    time.sleep(1)

    test_brute_force()
    time.sleep(1)

    test_scanning(scanning_token, scanning_uid)
    time.sleep(1)

    test_fraud(fraud_token, fraud_uid)

    sep("ALL TESTS COMPLETE")
    print("  Run this to verify DB:\n")
    print('  sqlite3 proxy_logs.db "SELECT session_id, routed_to, attack_type, anomaly_score, flagged_as_suspicious FROM proxy_requests ORDER BY id DESC LIMIT 30;"')
    print()