"""
GATE80 — Unified Labeled Traffic Generator
dataset/generate_unified_traffic.py

Generates 2,000 labeled sessions combining normal and abnormal traffic
into a single CSV with ground-truth labels for supervised ML training.

Dataset composition (research-grounded):
  Normal   : 1,700 sessions (85%) — reflects real-world API traffic baseline
             Source: Imperva State of API Security 2024 — API calls constitute
             the majority of legitimate web traffic in fintech platforms.
  Abnormal :   300 sessions (15%) distributed across 5 attack types:
             Source: OWASP API Security Top 10 2023, Imperva 2024, Akamai 2023,
             Salt Security Q1 2023, Traceable 2023.

Normal sub-composition:
  1,615 user sessions   (95%) — 4 behavioral personas
     85 admin sessions  ( 5%) — reflects least-privilege principle (NIST SP 800-53)

Abnormal sub-composition (proportional to reported attack frequency):
   90 brute_force         (30%) — Imperva 2024: most common ATO vector
   75 credential_stuffing (25%) — Akamai 2023: 26B attempts/month
   60 account_takeover    (20%) — Imperva 2024: 46% of ATO targets financial APIs
   45 scanning            (15%) — Salt Security 2023: OWASP API7 second most common
   30 financial_fraud     (10%) — Traceable 2023: fraud 29% of API breach causes

Labels:
  label = 0 → normal
  label = 1 → abnormal (all attack types)
  session_type → internal diversity label (not seen by model)

Normal session design:
  Personas reflect purposeful user archetypes with defined behavioral
  probability distributions — not random behavior. Users interact with
  the system with intent, consistent with their role and financial needs.
  Per supervisor feedback: "persona-driven behavioral profiles with
  probabilistic endpoint selection" replaces "randomized" terminology.

Balance seeding:
  Each registered user's wallet is funded once at registration time
  (500–2000 SAR) drawn from a realistic distribution. This reflects that
  active authenticated sessions are performed by users who have already
  funded their accounts. Prevents artificial inflation of error ratios
  from insufficient-balance 400s in normal sessions, which would
  contaminate the training data boundary between normal and abnormal.

Attack behavioral profiles (distinct feature signatures):
  brute_force:         high error_ratio, high failed_login_count,
                       very low avg_think_time, auth-only endpoints
  credential_stuffing: high failed_login_count across many fake emails,
                       very low avg_think_time, no wallet ops
  account_takeover:    low error_ratio (successful login), then high
                       wallet_action_ratio and transfer_count, low think time
  scanning:            high unique_endpoints, high admin_action_count,
                       high error_4xx_count, many 401/403/404 responses
  financial_fraud:     very high wallet_action_ratio, high transfer_count,
                       very low avg_think_time, rapid sequential ops

Output: dataset/output/unified_traffic_log_{RUN_ID}.csv
Columns: 22 (20 base + label + session_type)

Run:
    python dataset/generate_unified_traffic.py
    nohup python3 dataset/unified/generate_unified_traffic.py > dataset/unified/output/run_log.txt 2>&1 &
    tail -f dataset/unified/output/run_log.txt
"""

from __future__ import annotations

import asyncio
import csv
import json
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from faker import Faker
from playwright.async_api import async_playwright

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
BASE_URL      = "http://127.0.0.1:8080/api/v1"
BASE_URL_ROOT = "http://127.0.0.1:8080"

# User pool size — registered at startup, wallets funded immediately
NUM_REGISTER_USERS = 500
MAX_CONCURRENT     = 10

RUN_ID   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"dataset/output/unified_traffic_log_{RUN_ID}.csv"

SOURCE_TOOL = "playwright"

ADMIN_CREDS = {"username": "admin", "password": "admin123"}

# ── Session counts ────────────────────────────────────────────────────────────
# TEST MODE — small numbers to verify output correctness before full run.
# Switch to PRODUCTION counts (commented below) once output is confirmed clean.
NORMAL_USER_SESSIONS  = 8075
NORMAL_ADMIN_SESSIONS = 425
ABNORMAL_COUNTS = {
    "brute_force":         450,
    "credential_stuffing": 375,
    "account_takeover":    300,
    "scanning":            225,
    "financial_fraud":     150,
}

SAUDI_CITIES = [
    "Jeddah", "Riyadh", "Mecca", "Medina",
    "Dammam", "Khobar", "Tabuk", "Abha", "Taif", "Buraidah"
]
CLIENT_TYPES = ["web", "ios", "android"]

# No seeded users in pool — generator uses only newly registered users.
# Seeded users (u_1001-u_1004) remain in DB but are excluded from all sessions
# to keep the dataset clean and independent of pre-existing test data.

fake = Faker()

# ─────────────────────────────────────────────────────────────────────────────
# PERSONAS
# Purposeful behavioral archetypes with probabilistic endpoint selection.
# Each persona reflects a realistic user role with defined intent.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PersonaConfig:
    name:             str
    think_min:        float   # seconds
    think_max:        float
    actions_min:      int
    actions_max:      int
    # Endpoint selection weights — reflect purposeful behavior, not random choice
    w_health:         int
    w_hello:          int
    w_auth_me:        int
    w_wallet_view:    int
    w_topup:          int
    w_withdraw:       int
    w_transfer:       int
    w_pay_bill:       int
    w_view_profile:   int
    w_update_profile: int
    w_payments:       int
    w_bank_accounts:  int


PERSONAS: Dict[str, PersonaConfig] = {
    # Casual: infrequent user, checks balance and profile — low financial activity
    "casual": PersonaConfig(
        name="casual",
        think_min=3.0, think_max=12.0,
        actions_min=2, actions_max=6,
        w_health=5,  w_hello=5,  w_auth_me=20,
        w_wallet_view=20, w_topup=5,  w_withdraw=5,
        w_transfer=5,  w_pay_bill=5,
        w_view_profile=15, w_update_profile=5,
        w_payments=5,  w_bank_accounts=5,
    ),
    # Power user: frequent, heavy wallet activity — primary financial user
    "power_user": PersonaConfig(
        name="power_user",
        think_min=0.5, think_max=2.5,
        actions_min=7, actions_max=15,
        w_health=2,  w_hello=2,  w_auth_me=8,
        w_wallet_view=15, w_topup=15, w_withdraw=12,
        w_transfer=15, w_pay_bill=12,
        w_view_profile=8,  w_update_profile=3,
        w_payments=5,  w_bank_accounts=3,
    ),
    # Confused: uncertain user, few actions, slow — navigates without clear intent
    "confused": PersonaConfig(
        name="confused",
        think_min=8.0, think_max=25.0,
        actions_min=1, actions_max=3,
        w_health=10, w_hello=10, w_auth_me=30,
        w_wallet_view=10, w_topup=5,  w_withdraw=5,
        w_transfer=5,  w_pay_bill=5,
        w_view_profile=15, w_update_profile=0,
        w_payments=5,  w_bank_accounts=0,
    ),
    # Transactor: focused on moving money — transfers and payments primary intent
    "transactor": PersonaConfig(
        name="transactor",
        think_min=1.0, think_max=5.0,
        actions_min=4, actions_max=9,
        w_health=2,  w_hello=2,  w_auth_me=8,
        w_wallet_view=12, w_topup=12, w_withdraw=10,
        w_transfer=25, w_pay_bill=15,
        w_view_profile=5,  w_update_profile=3,
        w_payments=4,  w_bank_accounts=2,
    ),
}

PERSONA_NAMES   = list(PERSONAS.keys())
# Persona weights reflect realistic user distribution in fintech:
# casual users are most common, power users and transactors form active minority
PERSONA_WEIGHTS = [40, 20, 10, 30]  # casual, power_user, confused, transactor

ACTION_NAMES = [
    "health", "hello", "auth_me",
    "wallet_view", "topup", "withdraw", "transfer", "pay_bill",
    "view_profile", "update_profile", "payments", "bank_accounts",
]

MISTAKE_WEIGHTS = {
    "wrong_password":        30,
    "overdraft":             20,
    "double_submit":         15,
    "transfer_to_self":      10,
    "transfer_nonexistent":   8,
    "wrong_email_format":     6,
    "signout_no_token":       5,
    "zero_negative_amount":   4,
    "bad_data_format":        2,
}
MISTAKE_TYPES  = list(MISTAKE_WEIGHTS.keys())
MISTAKE_VALUES = list(MISTAKE_WEIGHTS.values())
MISTAKE_SESSION_RATE = 0.08

PRE_LOGIN_MISTAKES  = {"wrong_password", "wrong_email_format", "signout_no_token"}
POST_LOGIN_MISTAKES = {
    "overdraft", "double_submit", "transfer_to_self",
    "transfer_nonexistent", "zero_negative_amount", "bad_data_format"
}

# ─────────────────────────────────────────────────────────────────────────────
# CSV — 22 columns (20 base + label + session_type)
# ─────────────────────────────────────────────────────────────────────────────
CSV_COLUMNS = [
    "timestamp", "session_id", "persona", "email", "user_id",
    "action", "method", "path", "status_code", "is_failed_login",
    "response_time_ms", "think_time_ms", "body_size",
    "has_auth_token", "endpoint_category", "response_length",
    "geo_location", "client_type", "user_agent", "source_tool",
    "label",        # 0 = normal, 1 = abnormal — ground truth for ML model
    "session_type", # normal / brute_force / credential_stuffing /
                    # account_takeover / scanning / financial_fraud
]

csv_lock = asyncio.Lock()


def init_csv():
    import os
    os.makedirs("dataset/output", exist_ok=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(CSV_COLUMNS)


async def log_row(row: dict):
    async with csv_lock:
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([row.get(col, "") for col in CSV_COLUMNS])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def endpoint_category(path: str) -> str:
    if "/admin" in path:           return "admin"
    if any(x in path for x in ["/auth/sign-in", "/auth/sign-up",
                                "/auth/sign-out", "/auth/me"]): return "auth"
    if "/wallet" in path:          return "wallet"
    if "/bank-accounts" in path or "/payments" in path: return "account"
    if path.startswith("/users/"): return "account"
    if path in ["/health", "/hello"]: return "system"
    return "other"


def make_row(
    session_id, persona, email, user_id, action,
    method, path, status_code,
    label=0, session_type="normal",
    is_failed_login=False, response_time_ms=0, think_time_ms=0,
    body_size=0, has_auth_token=False,
    response_length=0, geo_location="", client_type="web",
    user_agent="", source_tool=SOURCE_TOOL,
) -> dict:
    return {
        "timestamp":         now_iso(),
        "session_id":        session_id,
        "persona":           persona,
        "email":             email,
        "user_id":           user_id,
        "action":            action,
        "method":            method,
        "path":              path,
        "status_code":       status_code,
        "is_failed_login":   is_failed_login,
        "response_time_ms":  response_time_ms,
        "think_time_ms":     think_time_ms,
        "body_size":         body_size,
        "has_auth_token":    has_auth_token,
        "endpoint_category": endpoint_category(path),
        "response_length":   response_length,
        "geo_location":      geo_location,
        "client_type":       client_type,
        "user_agent":        user_agent,
        "source_tool":       source_tool,
        "label":             label,
        "session_type":      session_type,
    }


def clog(sid: str, tag: str, action: str, status, rt_ms=None):
    ts = datetime.now().strftime("%H:%M:%S")
    rt = f"{rt_ms}ms" if rt_ms is not None else ""
    print(f"[{ts}] {sid[:8]} | {tag:<22} | {action:<48} | {status} {rt}")


# ─────────────────────────────────────────────────────────────────────────────
# USER POOL — registered and funded at startup
# ─────────────────────────────────────────────────────────────────────────────
registered_users  = []   # {"email", "password", "user_id", "geo_location", ...}
registration_lock = asyncio.Lock()

session_counter = 0
counter_lock    = asyncio.Lock()

total_sessions = (
    NORMAL_USER_SESSIONS + NORMAL_ADMIN_SESSIONS +
    sum(ABNORMAL_COUNTS.values())
)


async def tick_progress():
    global session_counter
    async with counter_lock:
        session_counter += 1
        count = session_counter
    if count % 100 == 0 or count == total_sessions:
        pct = count / total_sessions * 100
        print(f"\n  ▶ Progress: {count}/{total_sessions} ({pct:.1f}%)\n")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────────────────────────────────────
async def api_post(ctx, path: str, payload=None, token=None,
                   token_type="user", client_type="web", user_agent="") -> Tuple:
    headers = {"Content-Type": "application/json",
               "User-Agent": user_agent, "X-Client-Type": client_type}
    if token:
        key = "X-User-Token" if token_type == "user" else "X-Admin-Token"
        headers[key] = token
    body_str  = json.dumps(payload) if payload else ""
    body_size = len(body_str.encode("utf-8"))
    try:
        t = time.time()
        r = await ctx.post(f"{BASE_URL}{path}",
                           data=body_str if payload else None, headers=headers)
        rt_ms = int((time.time() - t) * 1000)
        return r, rt_ms, body_size, len(await r.body())
    except Exception:
        return None, 0, body_size, 0


async def api_get(ctx, path: str, token=None, token_type="user",
                  client_type="web", user_agent="") -> Tuple:
    headers = {"User-Agent": user_agent, "X-Client-Type": client_type}
    if token:
        key = "X-User-Token" if token_type == "user" else "X-Admin-Token"
        headers[key] = token
    url = (f"{BASE_URL_ROOT}{path}"
           if path in ["/health", "/hello"] else f"{BASE_URL}{path}")
    try:
        t = time.time()
        r = await ctx.get(url, headers=headers)
        rt_ms = int((time.time() - t) * 1000)
        return r, rt_ms, len(await r.body())
    except Exception:
        return None, 0, 0


async def api_put(ctx, path: str, payload=None, token=None,
                  client_type="web", user_agent="") -> Tuple:
    headers = {"Content-Type": "application/json",
               "User-Agent": user_agent, "X-Client-Type": client_type}
    if token:
        headers["X-User-Token"] = token
    body_str  = json.dumps(payload) if payload else ""
    body_size = len(body_str.encode("utf-8"))
    try:
        t = time.time()
        r = await ctx.put(f"{BASE_URL}{path}",
                          data=body_str if payload else None, headers=headers)
        rt_ms = int((time.time() - t) * 1000)
        return r, rt_ms, body_size, len(await r.body())
    except Exception:
        return None, 0, body_size, 0


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRATION + WALLET FUNDING
# Every registered user gets a starting balance of 500–2000 SAR.
# This reflects that active wallet users have funded their accounts.
# Funded at registration time, not per-session, to avoid artificial
# error ratio inflation from insufficient-balance failures in normal sessions.
# ─────────────────────────────────────────────────────────────────────────────
async def register_and_fund(ctx) -> Optional[dict]:
    email    = fake.unique.email()
    password = fake.password(length=random.randint(8, 14), special_chars=False)
    city     = random.choice(SAUDI_CITIES)
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    payload = {
        "full_name": fake.name(),
        "email":     email,
        "password":  password,
        "phone":     f"+9665{random.randint(10000000, 99999999)}",
        "city":      city,
    }
    r, _, _, _ = await api_post(ctx, "/auth/sign-up", payload,
                                client_type=ct, user_agent=ua)
    if not r or r.status != 201:
        status = r.status if r else "NO RESPONSE"
        print(f"[WARN] Registration failed: {status} for {email}")
        return None

    body    = await r.json()
    user_id = body.get("user_id")

    # Sign in to get token for wallet funding
    r2, _, _, _ = await api_post(ctx, "/auth/sign-in",
                                 {"email": email, "password": password},
                                 client_type=ct, user_agent=ua)
    if not r2 or r2.status != 200:
        status = r2.status if r2 else "NO RESPONSE"
        print(f"[WARN] Sign-in after registration failed: {status} for {email}")
        return None

    body2 = await r2.json()
    token = body2.get("token")

    # Fund wallet: 500–2000 SAR, reflects realistic funded account state
    # Distribution skewed toward lower amounts (most users have modest balances)
    fund_amount = round(random.triangular(500, 2000, 800), 2)
    await api_post(ctx, f"/users/{user_id}/wallet/topup",
                   {"amount": fund_amount}, token=token,
                   client_type=ct, user_agent=ua)

    # Sign out — session will be created fresh per simulated session
    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)

    user = {
        "email":        email,
        "password":     password,
        "user_id":      user_id,
        "geo_location": city,
        "client_type":  ct,
        "user_agent":   ua,
    }
    async with registration_lock:
        registered_users.append(user)
    return user


async def get_random_user() -> dict:
    async with registration_lock:
        pool = list(registered_users)
    if not pool:
        raise RuntimeError("User pool is empty — registration must complete before sessions start")
    return dict(random.choice(pool))


# ─────────────────────────────────────────────────────────────────────────────
# THINK TIME HELPERS
# ─────────────────────────────────────────────────────────────────────────────
async def think(persona: PersonaConfig) -> int:
    delay = random.uniform(persona.think_min, persona.think_max)
    await asyncio.sleep(delay)
    return int(delay * 1000)


async def think_ms(min_ms: float, max_ms: float) -> int:
    delay = random.uniform(min_ms / 1000, max_ms / 1000)
    await asyncio.sleep(delay)
    return int(delay * 1000)


# ─────────────────────────────────────────────────────────────────────────────
# MISTAKE HELPERS (for normal sessions)
# ─────────────────────────────────────────────────────────────────────────────
def pick_mistake() -> str:
    return random.choices(MISTAKE_TYPES, weights=MISTAKE_VALUES, k=1)[0]


def typo_password(pwd: str) -> str:
    # Ensure base is always >= 8 chars so FastAPI min_length validation passes
    # but the password is still wrong (wrong content, not wrong length)
    base = pwd if len(pwd) >= 8 else pwd + "x" * (8 - len(pwd))
    chars = list(base)
    mutation = random.choice(["swap", "insert_digit", "wrong_case", "replace"])
    if mutation == "swap" and len(chars) >= 2:
        i = random.randint(0, len(chars) - 2)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    elif mutation == "insert_digit":
        chars.insert(random.randint(0, len(chars)), str(random.randint(0, 9)))
    elif mutation == "wrong_case":
        chars[0] = chars[0].upper() if chars[0].islower() else chars[0].lower()
    elif mutation == "replace":
        # Replace a char with a wrong one — keeps length, still wrong password
        idx = random.randint(0, len(chars) - 1)
        chars[idx] = random.choice("abcdefghijklmnopqrstuvwxyz")
    result = "".join(chars)
    # Final safety: pad if somehow still short
    return result if len(result) >= 8 else result + "pad12345"


def wrong_email(email: str) -> str:
    mutation = random.choice(["remove_at", "double_dot", "truncate"])
    if mutation == "remove_at":   return email.replace("@", "")
    elif mutation == "double_dot": return email.replace(".", "..", 1)
    return email[:max(3, len(email) - 4)]


# ─────────────────────────────────────────────────────────────────────────────
# ACTION EXECUTOR (normal sessions)
# ─────────────────────────────────────────────────────────────────────────────
def pick_action(persona: PersonaConfig) -> str:
    weights = [
        persona.w_health, persona.w_hello, persona.w_auth_me,
        persona.w_wallet_view, persona.w_topup, persona.w_withdraw,
        persona.w_transfer, persona.w_pay_bill,
        persona.w_view_profile, persona.w_update_profile,
        persona.w_payments, persona.w_bank_accounts,
    ]
    return random.choices(ACTION_NAMES, weights=weights, k=1)[0]


async def execute_action(ctx, action_name: str, sid: str, uid: str,
                         token: str, email: str, persona: PersonaConfig,
                         geo: str, ct: str, ua: str,
                         label: int, session_type: str) -> None:

    async def log(method, path, status, rt, r_len, body_size=0,
                  failed_login=False, has_token=True, tt=0):
        await log_row(make_row(
            sid, persona.name, email, uid, action_name,
            method, path, status,
            label=label, session_type=session_type,
            is_failed_login=failed_login,
            response_time_ms=rt, think_time_ms=tt,
            body_size=body_size, has_auth_token=has_token,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

    if action_name == "health":
        r, rt, r_len = await api_get(ctx, "/health", client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        clog(sid, f"{session_type}", "GET /health", status, rt)
        await log("GET", "/health", status, rt, r_len, has_token=False, tt=tt)

    elif action_name == "hello":
        r, rt, r_len = await api_get(ctx, "/hello", client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("GET", "/hello", status, rt, r_len, has_token=False, tt=tt)

    elif action_name == "auth_me":
        r, rt, r_len = await api_get(ctx, "/auth/me", token=token,
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("GET", "/auth/me", status, rt, r_len, tt=tt)

    elif action_name == "wallet_view":
        path = f"/users/{uid}/wallet"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("GET", path, status, rt, r_len, tt=tt)

    elif action_name == "topup":
        path = f"/users/{uid}/wallet/topup"
        amount = round(random.uniform(10, 500), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("POST", path, status, rt, r_len, body_size=bs, tt=tt)

    elif action_name == "withdraw":
        path = f"/users/{uid}/wallet/withdraw"
        amount = round(random.uniform(5, 100), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("POST", path, status, rt, r_len, body_size=bs, tt=tt)

    elif action_name == "transfer":
        async with registration_lock:
            targets = [u["user_id"] for u in registered_users if u.get("user_id")]
        if not targets:
            targets = ["u_1001", "u_1002", "u_1003"]
        target = random.choice([t for t in targets if t != uid] or targets)
        path = f"/users/{uid}/wallet/transfer/{target}"
        amount = round(random.uniform(5, 80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("POST", path, status, rt, r_len, body_size=bs, tt=tt)

    elif action_name == "pay_bill":
        path = f"/users/{uid}/wallet/pay-bill"
        amount = round(random.uniform(20, 200), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("POST", path, status, rt, r_len, body_size=bs, tt=tt)

    elif action_name == "view_profile":
        path = f"/users/{uid}"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("GET", path, status, rt, r_len, tt=tt)

    elif action_name == "update_profile":
        city = random.choice(SAUDI_CITIES)
        path = f"/users/{uid}"
        r, rt, bs, r_len = await api_put(ctx, path, {"city": city},
                                         token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("PUT", path, status, rt, r_len, body_size=bs, tt=tt)

    elif action_name == "payments":
        path = f"/users/{uid}/payments"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("GET", path, status, rt, r_len, tt=tt)

    elif action_name == "bank_accounts":
        path = f"/users/{uid}/bank-accounts"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("GET", path, status, rt, r_len, tt=tt)


# ─────────────────────────────────────────────────────────────────────────────
# MISTAKE INJECTION (normal sessions only)
# ─────────────────────────────────────────────────────────────────────────────
async def inject_mistake(ctx, sid, uid, token, email, password,
                         persona, geo, ct, ua, mtype,
                         label=0, session_type="normal") -> None:

    async def log(action, method, path, status, rt, r_len,
                  body_size=0, failed_login=False, has_token=False, tt=0):
        await log_row(make_row(
            sid, persona.name, email, uid or "unknown", action,
            method, path, status,
            label=label, session_type=session_type,
            is_failed_login=failed_login,
            response_time_ms=rt, think_time_ms=tt,
            body_size=body_size, has_auth_token=has_token,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

    if mtype == "wrong_password":
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email": email, "password": typo_password(password)},
            client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("failed_login", "POST", "/auth/sign-in", status, rt, r_len,
                  body_size=bs, failed_login=True, tt=tt)

    elif mtype == "overdraft" and uid and token:
        path = f"/users/{uid}/wallet/withdraw"
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": 999999},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("withdraw_overdraft", "POST", path, status, rt, r_len,
                  body_size=bs, has_token=True, tt=tt)

    elif mtype == "double_submit" and uid and token:
        path = f"/users/{uid}/wallet/topup"
        amount = round(random.uniform(10, 100), 2)
        for i in range(2):
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)
            status = r.status if r else "ERR"
            action = "topup" if i == 0 else "topup_double_submit"
            await log(action, "POST", path, status, rt, r_len,
                      body_size=bs, has_token=True)
            if i == 0:
                await asyncio.sleep(random.uniform(0, 0.5))
        await think(persona)

    elif mtype == "transfer_to_self" and uid and token:
        path = f"/users/{uid}/wallet/transfer/{uid}"
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": 50},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("transfer_to_self", "POST", path, status, rt, r_len,
                  body_size=bs, has_token=True, tt=tt)

    elif mtype == "wrong_email_format":
        bad_em = wrong_email(email)
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email": bad_em, "password": password},
            client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("failed_login_bad_email", "POST", "/auth/sign-in", status, rt, r_len,
                  body_size=bs, failed_login=True, tt=tt)

    elif mtype == "signout_no_token":
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-out",
                                          client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think(persona)
        await log("signout_no_token", "POST", "/auth/sign-out", status, rt, r_len,
                  body_size=bs, tt=tt)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

# ── NORMAL USER SESSION ───────────────────────────────────────────────────────
async def run_normal_user_session(ctx) -> None:
    sid          = str(uuid.uuid4())
    persona_name = random.choices(PERSONA_NAMES, weights=PERSONA_WEIGHTS, k=1)[0]
    persona      = PERSONAS[persona_name]
    user         = await get_random_user()
    email        = user["email"]
    password     = user["password"]
    geo          = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct           = user.get("client_type",  random.choice(CLIENT_TYPES))
    ua           = user.get("user_agent",   fake.user_agent())

    await asyncio.sleep(random.uniform(0, 3))

    mistake = pick_mistake() if random.random() < MISTAKE_SESSION_RATE else None

    if mistake in PRE_LOGIN_MISTAKES:
        await inject_mistake(ctx, sid, None, None, email, password,
                             persona, geo, ct, ua, mistake)
        mistake = None

    r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in",
                                      {"email": email, "password": password},
                                      client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        await log_row(make_row(sid, persona_name, email, "unknown", "sign_in",
                               "POST", "/auth/sign-in",
                               r.status if r else "ERR",
                               label=0, session_type="normal",
                               response_time_ms=rt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")
    tt      = await think(persona)

    clog(sid, f"normal/{persona_name}", "POST /auth/sign-in", "200", rt)
    await log_row(make_row(sid, persona_name, email, user_id, "sign_in",
                           "POST", "/auth/sign-in", 200,
                           label=0, session_type="normal",
                           response_time_ms=rt, think_time_ms=tt,
                           body_size=bs, response_length=r_len,
                           geo_location=geo, client_type=ct, user_agent=ua))

    if mistake in POST_LOGIN_MISTAKES:
        await inject_mistake(ctx, sid, user_id, token, email, password,
                             persona, geo, ct, ua, mistake)

    n_actions = random.randint(persona.actions_min, persona.actions_max)
    for _ in range(n_actions):
        await execute_action(ctx, pick_action(persona), sid, user_id,
                             token, email, persona, geo, ct, ua,
                             label=0, session_type="normal")

    r, rt, _, r_len = await api_post(ctx, "/auth/sign-out", token=token,
                                     client_type=ct, user_agent=ua)
    status = r.status if r else "ERR"
    await log_row(make_row(sid, persona_name, email, user_id, "sign_out",
                           "POST", "/auth/sign-out", status,
                           label=0, session_type="normal",
                           response_time_ms=rt, has_auth_token=True,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))


# ── NORMAL ADMIN SESSION ──────────────────────────────────────────────────────
async def run_normal_admin_session(ctx) -> None:
    sid = str(uuid.uuid4())
    geo = random.choice(SAUDI_CITIES)
    ct  = random.choice(CLIENT_TYPES)
    ua  = fake.user_agent()

    await asyncio.sleep(random.uniform(0, 2))

    r, rt, bs, r_len = await api_post(ctx, "/admin/auth/sign-in", ADMIN_CREDS,
                                      client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        return

    body        = await r.json()
    admin_token = body.get("token")
    tt          = int(random.uniform(600, 2200))
    await asyncio.sleep(tt / 1000)

    await log_row(make_row(sid, "admin", "admin", "admin_1", "admin_sign_in",
                           "POST", "/admin/auth/sign-in", 200,
                           label=0, session_type="normal",
                           response_time_ms=rt, think_time_ms=tt,
                           body_size=bs, response_length=r_len,
                           geo_location=geo, client_type=ct, user_agent=ua))

    session_length = random.choices([5, 10, 20, 35], weights=[30, 30, 25, 15], k=1)[0]
    admin_paths    = ["/admin/users", "/admin/wallets",
                      "/admin/transactions", "/admin/overview/financial"]
    admin_weights  = [30, 25, 25, 20]

    for _ in range(session_length):
        path = random.choices(admin_paths, weights=admin_weights, k=1)[0]
        r, rt, r_len = await api_get(ctx, path, token=admin_token,
                                     token_type="admin",
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = int(random.uniform(600, 2200))
        await asyncio.sleep(tt / 1000)
        action = f"admin_{path.split('/')[-1]}"
        await log_row(make_row(sid, "admin", "admin", "admin_1", action,
                               "GET", path, status,
                               label=0, session_type="normal",
                               response_time_ms=rt, think_time_ms=tt,
                               has_auth_token=True, response_length=r_len,
                               geo_location=geo, client_type=ct, user_agent=ua))

    r, rt, _, r_len = await api_post(ctx, "/admin/auth/sign-out",
                                     token=admin_token, token_type="admin",
                                     client_type=ct, user_agent=ua)
    status = r.status if r else "ERR"
    await log_row(make_row(sid, "admin", "admin", "admin_1", "admin_sign_out",
                           "POST", "/admin/auth/sign-out", status,
                           label=0, session_type="normal",
                           response_time_ms=rt, has_auth_token=True,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))


# ── ATTACK: BRUTE FORCE ───────────────────────────────────────────────────────
# Behavioral profile: rapid repeated login attempts on one account using
# mutated passwords. High failed_login_count, error_ratio ≈ 1.0,
# very low avg_think_time (<500ms), concentrated on /auth/sign-in.
# Source: OWASP API2:2023 Broken Authentication
async def run_brute_force(ctx) -> None:
    sid   = str(uuid.uuid4())
    user  = await get_random_user()
    email = user["email"]
    geo   = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct    = random.choice(CLIENT_TYPES)
    ua    = fake.user_agent()

    n_attempts = random.randint(10, 30)
    clog(sid, "BRUTE_FORCE", f"hammering {email} x{n_attempts}", "→")

    for i in range(n_attempts):
        # Use mutated/wrong password — never the real one
        # min length 8 to pass FastAPI validation, still wrong content
        bad_password = typo_password(
            fake.password(length=random.randint(8, 14), special_chars=False)
        )
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email": email, "password": bad_password},
            client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"

        tt = await think_ms(50, 400)  # machine-speed: 50–400ms
        await log_row(make_row(
            sid, "attacker", email, "unknown", "failed_login",
            "POST", "/auth/sign-in", status,
            label=1, session_type="brute_force",
            is_failed_login=True,
            response_time_ms=rt, think_time_ms=tt,
            body_size=bs, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))

        if i % 5 == 0:
            clog(sid, "BRUTE_FORCE", f"attempt {i+1}/{n_attempts}", status, rt)


# ── ATTACK: CREDENTIAL STUFFING ───────────────────────────────────────────────
# Behavioral profile: many different fake email/password combinations tried
# against the login endpoint. Spread across many accounts (not one).
# Very low think time, no successful login, no wallet operations.
# Source: OWASP API2:2023 + Akamai 2023 (26B attempts/month)
async def run_credential_stuffing(ctx) -> None:
    sid = str(uuid.uuid4())
    geo = random.choice(SAUDI_CITIES)
    ct  = random.choice(CLIENT_TYPES)
    ua  = fake.user_agent()

    n_attempts = random.randint(15, 40)
    clog(sid, "CRED_STUFFING", f"trying {n_attempts} credential pairs", "→")

    for i in range(n_attempts):
        # Each attempt uses a completely different fake email — simulates
        # using a breached credential list across many accounts
        fake_email    = fake.unique.email()
        fake_password = fake.password(length=random.randint(8, 14), special_chars=False)

        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email": fake_email, "password": fake_password},
            client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"

        tt = await think_ms(30, 250)  # automated tool speed
        await log_row(make_row(
            sid, "attacker", fake_email, "unknown", "credential_stuffing",
            "POST", "/auth/sign-in", status,
            label=1, session_type="credential_stuffing",
            is_failed_login=True,
            response_time_ms=rt, think_time_ms=tt,
            body_size=bs, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))

        if i % 8 == 0:
            clog(sid, "CRED_STUFFING", f"attempt {i+1}/{n_attempts}", status, rt)


# ── ATTACK: ACCOUNT TAKEOVER ─────────────────────────────────────────────────
# Behavioral profile: successful login using valid stolen credentials,
# followed immediately by rapid financial operations — draining the account.
# Low error_ratio (successful login), high wallet_action_ratio, high
# transfer_count, very low think time after login.
# Source: Imperva State of API Security 2024 — 46% of ATO targets financial APIs
async def run_account_takeover(ctx) -> None:
    sid  = str(uuid.uuid4())
    user = await get_random_user()
    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    clog(sid, "ACCOUNT_TAKEOVER", f"logging in as {email}", "→")

    r, rt, bs, r_len = await api_post(
        ctx, "/auth/sign-in",
        {"email": email, "password": password},
        client_type=ct, user_agent=ua)

    if not r or r.status != 200:
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")

    await log_row(make_row(
        sid, "attacker", email, user_id, "sign_in_ato",
        "POST", "/auth/sign-in", 200,
        label=1, session_type="account_takeover",
        response_time_ms=rt, body_size=bs,
        response_length=r_len, geo_location=geo,
        client_type=ct, user_agent=ua,
    ))

    # Immediate rapid financial activity — drain the account
    async with registration_lock:
        targets = [u["user_id"] for u in registered_users if u.get("user_id") and u["user_id"] != user_id]
    if not targets:
        targets = ["u_1001", "u_1002", "u_1003"]

    n_ops = random.randint(8, 15)
    for i in range(n_ops):
        action = random.choices(
            ["withdraw", "transfer", "pay_bill"],
            weights=[40, 40, 20], k=1
        )[0]

        if action == "withdraw":
            path   = f"/users/{user_id}/wallet/withdraw"
            amount = round(random.uniform(50, 300), 2)
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)
        elif action == "transfer":
            target = random.choice(targets)
            path   = f"/users/{user_id}/wallet/transfer/{target}"
            amount = round(random.uniform(50, 300), 2)
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)
        else:
            path   = f"/users/{user_id}/wallet/pay-bill"
            amount = round(random.uniform(30, 200), 2)
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)

        status = r.status if r else "ERR"
        tt = await think_ms(80, 400)

        await log_row(make_row(
            sid, "attacker", email, user_id, f"{action}_ato",
            "POST", path, status,
            label=1, session_type="account_takeover",
            response_time_ms=rt, think_time_ms=tt,
            body_size=bs, has_auth_token=True,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

        if i % 4 == 0:
            clog(sid, "ACCOUNT_TAKEOVER", f"{action} attempt {i+1}", status, rt)

    # Sign out
    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)


# ── ATTACK: ENDPOINT SCANNING / ENUMERATION ───────────────────────────────────
# Behavioral profile: broad probing of many different endpoints including
# admin paths, non-existent paths, and unauthorized paths.
# High unique_endpoints, high admin_action_count, many 401/403/404 responses.
# Source: OWASP API7:2023 Security Misconfiguration +
#         Salt Security Q1 2023 (second most common OWASP method at 23%)
async def run_scanning(ctx) -> None:
    sid  = str(uuid.uuid4())
    user = await get_random_user()
    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    clog(sid, "SCANNING", "probing API surface", "→")

    # Login first to get a token for authenticated endpoint probing
    r, rt, bs, r_len = await api_post(
        ctx, "/auth/sign-in",
        {"email": email, "password": password},
        client_type=ct, user_agent=ua)

    token   = None
    user_id = None
    if r and r.status == 200:
        body    = await r.json()
        token   = body.get("token")
        user_id = body.get("user_id")

    await log_row(make_row(
        sid, "attacker", email, user_id or "unknown", "sign_in_scan",
        "POST", "/auth/sign-in", r.status if r else "ERR",
        label=1, session_type="scanning",
        response_time_ms=rt, body_size=bs,
        response_length=r_len, geo_location=geo,
        client_type=ct, user_agent=ua,
    ))

    # Diverse endpoint probing — mix of admin, unknown, and legitimate paths
    # Static probes (no login required)
    probe_targets = [
        # Admin endpoints without admin token
        ("/admin/users",              "GET",  False, "admin"),
        ("/admin/wallets",            "GET",  False, "admin"),
        ("/admin/transactions",       "GET",  False, "admin"),
        ("/admin/overview/financial", "GET",  False, "admin"),
        # Non-existent paths
        ("/config",                   "GET",  False, "unknown"),
        ("/api/v1/config",            "GET",  False, "unknown"),
        ("/system/metrics",           "GET",  False, "unknown"),
        ("/admin/keys",               "GET",  False, "unknown"),
        ("/admin/logs",               "GET",  False, "unknown"),
        ("/admin/export",             "GET",  False, "unknown"),
        ("/debug/users",              "GET",  False, "unknown"),
        ("/.env",                     "GET",  False, "unknown"),
        ("/backup",                   "GET",  False, "unknown"),
        # Cross-user probing (uses known seeded user IDs)
        ("/users/u_1001/wallet",      "GET",  True,  "wallet"),
        ("/users/u_1002/wallet",      "GET",  True,  "wallet"),
        ("/users/u_1003/wallet",      "GET",  True,  "wallet"),
    ]
    # Add user-specific probes only if login succeeded
    if user_id:
        probe_targets += [
            (f"/users/{user_id}/wallet",        "GET",  True,  "wallet"),
            (f"/users/{user_id}/payments",      "GET",  True,  "account"),
            (f"/users/{user_id}/bank-accounts", "GET",  True,  "account"),
            ("/auth/me",                        "GET",  True,  "auth"),
        ]

    # Shuffle and take a random subset to vary session length
    random.shuffle(probe_targets)
    n_probes = random.randint(12, len(probe_targets))
    probes   = probe_targets[:n_probes]

    for i, (path, method, use_token, _) in enumerate(probes):
        use_tok = token if use_token else None
        if method == "GET":
            r, rt, r_len = await api_get(ctx, path,
                                         token=use_tok,
                                         client_type=ct, user_agent=ua)
            bs = 0
        else:
            r, rt, bs, r_len = await api_post(ctx, path, None,
                                              token=use_tok,
                                              client_type=ct, user_agent=ua)

        status = r.status if r else "ERR"
        tt = await think_ms(80, 350)

        await log_row(make_row(
            sid, "attacker", email, user_id or "unknown", "probe",
            method, path, status,
            label=1, session_type="scanning",
            response_time_ms=rt, think_time_ms=tt,
            body_size=bs, has_auth_token=bool(use_tok),
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

        if i % 5 == 0:
            clog(sid, "SCANNING", f"probe {i+1}/{n_probes} {path}", status, rt)

    if token:
        await api_post(ctx, "/auth/sign-out", token=token,
                       client_type=ct, user_agent=ua)


# ── ATTACK: FINANCIAL FRAUD ───────────────────────────────────────────────────
# Behavioral profile: successful login then rapid sequential financial
# operations — many small transactions to stay below detection thresholds
# while maximizing extracted value. Very high wallet_action_ratio,
# high transfer_count, very low avg_think_time (automated tool behavior).
# Source: Traceable AI State of API Security 2023 (fraud = 29% of API breaches)
#         Imperva 2024 (27% of attacks target financial business logic)
async def run_financial_fraud(ctx) -> None:
    sid  = str(uuid.uuid4())
    user = await get_random_user()
    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    clog(sid, "FINANCIAL_FRAUD", f"logging in as {email}", "→")

    r, rt, bs, r_len = await api_post(
        ctx, "/auth/sign-in",
        {"email": email, "password": password},
        client_type=ct, user_agent=ua)

    if not r or r.status != 200:
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")

    await log_row(make_row(
        sid, "attacker", email, user_id, "sign_in_fraud",
        "POST", "/auth/sign-in", 200,
        label=1, session_type="financial_fraud",
        response_time_ms=rt, body_size=bs,
        response_length=r_len, geo_location=geo,
        client_type=ct, user_agent=ua,
    ))

    async with registration_lock:
        targets = [u["user_id"] for u in registered_users
                   if u.get("user_id") and u["user_id"] != user_id]
    if not targets:
        targets = ["u_1001", "u_1002", "u_1003"]

    # Rapid financial operations — automated, many and varied
    n_ops = random.randint(10, 20)
    for i in range(n_ops):
        action = random.choices(
            ["topup", "transfer", "withdraw", "pay_bill"],
            weights=[20, 40, 25, 15], k=1
        )[0]

        # Small amounts — staying below typical fraud thresholds
        amount = round(random.uniform(10, 150), 2)

        if action == "topup":
            path = f"/users/{user_id}/wallet/topup"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)
        elif action == "transfer":
            target = random.choice(targets)
            path   = f"/users/{user_id}/wallet/transfer/{target}"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)
        elif action == "withdraw":
            path = f"/users/{user_id}/wallet/withdraw"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)
        else:
            path = f"/users/{user_id}/wallet/pay-bill"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                              token=token, client_type=ct, user_agent=ua)

        status = r.status if r else "ERR"
        tt = await think_ms(30, 180)  # very fast — automated tool

        await log_row(make_row(
            sid, "attacker", email, user_id, f"{action}_fraud",
            "POST", path, status,
            label=1, session_type="financial_fraud",
            response_time_ms=rt, think_time_ms=tt,
            body_size=bs, has_auth_token=True,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

        if i % 5 == 0:
            clog(sid, "FINANCIAL_FRAUD", f"{action} x{i+1}", status, rt)

    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
async def main():
    init_csv()

    print("=" * 90)
    print("  GATE80 Unified Labeled Traffic Generator")
    print(f"  Normal     : {NORMAL_USER_SESSIONS} user + {NORMAL_ADMIN_SESSIONS} admin = {NORMAL_USER_SESSIONS + NORMAL_ADMIN_SESSIONS}")
    print(f"  Abnormal   : {sum(ABNORMAL_COUNTS.values())} sessions across {len(ABNORMAL_COUNTS)} attack types")
    for atype, count in ABNORMAL_COUNTS.items():
        print(f"               {atype:<25} {count} sessions")
    print(f"  Total      : {total_sessions}")
    print(f"  Output     : {CSV_FILE}")
    print("=" * 90)

    async with async_playwright() as playwright:

        # ── Register + fund user pool ─────────────────────────────────────────
        print(f"\n[SETUP] Registering and funding {NUM_REGISTER_USERS} users...")
        sb = await playwright.chromium.launch()
        sc = await sb.new_context()
        for i in range(NUM_REGISTER_USERS):
            await register_and_fund(sc.request)
            if (i + 1) % 20 == 0:
                print(f"  {i + 1}/{NUM_REGISTER_USERS} registered and funded...")
            await asyncio.sleep(0.2)  # slight delay to prevent SQLite write lock contention
        await sc.close()
        await sb.close()
        print(f"[SETUP] ✅ {len(registered_users)} users ready with funded wallets\n")

        # ── Launch browser workers ────────────────────────────────────────────
        print(f"[SETUP] Launching {MAX_CONCURRENT} browser workers...")
        browsers, contexts, ctxs = [], [], []
        for _ in range(MAX_CONCURRENT):
            bw = await playwright.chromium.launch()
            cx = await bw.new_context()
            browsers.append(bw)
            contexts.append(cx)
            ctxs.append(cx.request)
        print(f"[SETUP] ✅ Workers ready\n")

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        def make_task(coro_fn, worker_idx):
            async def _task():
                async with semaphore:
                    await coro_fn(ctxs[worker_idx % MAX_CONCURRENT])
                    await tick_progress()
            return _task()

        # Build all tasks
        all_tasks = []

        # Normal user sessions
        for i in range(NORMAL_USER_SESSIONS):
            all_tasks.append(make_task(run_normal_user_session, i))

        # Normal admin sessions
        for i in range(NORMAL_ADMIN_SESSIONS):
            all_tasks.append(make_task(run_normal_admin_session, i))

        # Abnormal sessions
        attack_runners = {
            "brute_force":         run_brute_force,
            "credential_stuffing": run_credential_stuffing,
            "account_takeover":    run_account_takeover,
            "scanning":            run_scanning,
            "financial_fraud":     run_financial_fraud,
        }
        idx = 0
        for atype, count in ABNORMAL_COUNTS.items():
            runner = attack_runners[atype]
            for _ in range(count):
                all_tasks.append(make_task(runner, idx))
                idx += 1

        # Shuffle to interleave normal and abnormal — realistic mixed traffic
        random.shuffle(all_tasks)

        print(f"[RUN] Generating {len(all_tasks)} sessions...\n")
        await asyncio.gather(*all_tasks)

        for cx in contexts:
            await cx.close()
        for bw in browsers:
            await bw.close()

    print("\n" + "=" * 90)
    print(f"  ✅ Done! {total_sessions} sessions generated.")
    print(f"  CSV     : {CSV_FILE}")
    print(f"  Columns : {len(CSV_COLUMNS)} (including label + session_type)")
    print(f"\n  Label distribution:")
    print(f"    label=0 (normal)   : {NORMAL_USER_SESSIONS + NORMAL_ADMIN_SESSIONS}")
    print(f"    label=1 (abnormal) : {sum(ABNORMAL_COUNTS.values())}")
    print("=" * 90)


if __name__ == "__main__":
    asyncio.run(main())