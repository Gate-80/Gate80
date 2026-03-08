# scripts/generate_traffic.py
import random
import time
from typing import Dict, List, Optional

import requests
from faker import Faker

print("✅ generate_traffic.py started")

# ---------------------------
# Config
# ---------------------------
BASE_URL = "http://127.0.0.1:8080"  # proxy port
fake = Faker()

TOTAL_USERS = 50
TOTAL_SESSIONS = 300

FAILED_LOGIN_RATE = 0.05     # 5% failed logins
ADMIN_SESSION_RATE = 0.20    # 20% of sessions are admin-like

# Swagger "Test Credentials"
USER_EMAIL = "taif.alsaadi@gmail.com"
USER_PASSWORD = "password123"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# IMPORTANT:
# From your Swagger screenshot, protected user endpoints use: X-User-Token
USER_TOKEN_HEADER = "X-User-Token"

# If your Swagger shows admin token header as X-Admin-Token, keep this.
# If your Swagger shows something else, change it here.
ADMIN_TOKEN_HEADER = "X-Admin-Token"


# ---------------------------
# Helpers
# ---------------------------
def think_time(min_s: float = 0.3, max_s: float = 2.5) -> None:
    """Simulate human think time between actions."""
    time.sleep(random.uniform(min_s, max_s))


def safe_get(url: str, headers: Dict[str, str]) -> None:
    """Fire-and-forget GET (we only care that it generates logs)."""
    try:
        requests.get(url, headers=headers, timeout=10)
    except requests.RequestException:
        pass


def safe_post(url: str, headers: Dict[str, str], json: Optional[dict] = None) -> None:
    """Fire-and-forget POST."""
    try:
        requests.post(url, headers=headers, json=json, timeout=10)
    except requests.RequestException:
        pass


# ---------------------------
# Generate realistic users
# ---------------------------
def generate_users(n: int) -> List[Dict[str, str]]:
    """
    Normal traffic only needs different client fingerprints (UA, client_type).
    The backend test user is fixed (user@example.com / password123) per handout.
    """
    users: List[Dict[str, str]] = []
    for _ in range(n):
        users.append(
            {
                "email": USER_EMAIL,
                "password": USER_PASSWORD,
                "user_agent": fake.user_agent(),
                "client_type": random.choice(["web", "ios", "android"]),
            }
        )
    return users


# ---------------------------
# Auth
# ---------------------------
def login(user: Dict[str, str]) -> Optional[str]:
    """
    IMPORTANT:
    - Login request does NOT include X-User-Token (you don't have it yet).
    - It returns token in JSON response, which we use later.
    """
    password = user["password"]
    if random.random() < FAILED_LOGIN_RATE:
        password = "wrongpass"  # simulate failed login

    headers = {
        "User-Agent": user["user_agent"],
        "X-Client-Type": user["client_type"],
    }

    try:
        r = requests.post(
            f"{BASE_URL}/api/v1/auth/sign-in",
            json={"email": user["email"], "password": password},
            headers=headers,
            timeout=10,
        )
    except requests.RequestException:
        return None

    if r.status_code == 200:
        return r.json().get("token")
    return None


def admin_login(user: Dict[str, str]) -> Optional[str]:
    """
    Admin login request also does NOT include X-Admin-Token.
    NOTE:
    - Some APIs use 'username', some use 'email'. If you get 422 here,
      change the JSON key from 'username' to 'email' based on Swagger.
    """
    headers = {
        "User-Agent": user["user_agent"],
        "X-Client-Type": user["client_type"],
    }

    try:
        r = requests.post(
            f"{BASE_URL}/api/v1/admin/auth/sign-in",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            headers=headers,
            timeout=10,
        )
    except requests.RequestException:
        return None

    if r.status_code == 200:
        return r.json().get("token")
    return None


# ---------------------------
# Sessions (Normal-only dataset style)
# ---------------------------
def normal_user_session(user: Dict[str, str]) -> None:
    token = login(user)
    if not token:
        # failed login session ends here (still useful logs)
        return

    headers = {
        USER_TOKEN_HEADER: token,
        "User-Agent": user["user_agent"],
        "X-Client-Type": user["client_type"],
    }

    # Session length distribution (human-ish)
    session_length = random.choices(
        [3, 5, 8, 12, 20],
        weights=[30, 30, 20, 15, 5],
        k=1
    )[0]

    for _ in range(session_length):
        endpoint = random.choices(
            ["/api/v1/auth/me", "/health", "/hello"],
            weights=[60, 20, 20],
            k=1
        )[0]

        safe_get(BASE_URL + endpoint, headers=headers)
        think_time()

    # sign out (some systems need token header on sign-out too)
    safe_post(f"{BASE_URL}/api/v1/auth/sign-out", headers=headers)


def admin_session(user: Dict[str, str]) -> None:
    token = admin_login(user)
    if not token:
        return

    headers = {
        ADMIN_TOKEN_HEADER: token,
        "User-Agent": user["user_agent"],
        "X-Client-Type": user["client_type"],
    }

    session_length = random.choices(
        [5, 10, 20, 40],
        weights=[30, 30, 25, 15],
        k=1
    )[0]

    for _ in range(session_length):
        endpoint = random.choices(
            [
                "/api/v1/admin/users",
                "/api/v1/admin/wallets",
                "/api/v1/admin/transactions",
                "/api/v1/admin/overview/financial",
            ],
            weights=[30, 25, 25, 20],
            k=1
        )[0]

        safe_get(BASE_URL + endpoint, headers=headers)
        think_time()

    safe_post(f"{BASE_URL}/api/v1/admin/auth/sign-out", headers=headers)


# ---------------------------
# Main loop
# ---------------------------
def main() -> None:
    users = generate_users(TOTAL_USERS)

    for i in range(TOTAL_SESSIONS):
        user = random.choice(users)

        # Admin-like sessions
        if random.random() < ADMIN_SESSION_RATE:
            admin_session(user)
        else:
            normal_user_session(user)

        # Gap between sessions
        time.sleep(random.uniform(0.5, 3.0))

        if i != 0 and i % 50 == 0:
            print(f"Generated {i} sessions...")

    print("✅ Done generating normal behavioral traffic.")


if __name__ == "__main__":
    main()