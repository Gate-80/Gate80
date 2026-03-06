"""
RASD - Unified Realistic Behavioral Traffic Generator
Week 4 - Task 1: Baseline Normal Traffic

Combines the best of Playwright (async, concurrency, 80 users, 9 mistake types)
and Faker (persona endpoint weights, client_type, user_agent, uuid4 session IDs,
UTC timestamps, health/hello endpoints, variable admin sessions).

Architecture:
  - Playwright async engine — persistent browser per worker slot
  - 80 users registered at startup (all get wallet + bank account via backend fix)
  - 9 mistake types at 8% session rate
  - 4 personas with per-endpoint probability weights
  - All 20 endpoints covered
  - 20 CSV columns (17 base + client_type + user_agent + source_tool)

notes applied:
  - session_id = uuid4 (consistent, groupable for feature engineering)
  - timestamp  = UTC ISO format (consistent across all tools)
  - source_tool column for merge traceability
  - Clear session summaries printed to console

Install:
    pip install playwright faker
    playwright install chromium

Run:
    python generate_traffic.py
"""

from __future__ import annotations

import asyncio
import csv
import json
import random
import string
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from faker import Faker
from playwright.async_api import async_playwright

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
BASE_URL           = "http://127.0.0.1:8080/api/v1"
BASE_URL_ROOT      = "http://127.0.0.1:8080"      # for /health and /hello
NUM_USERS          = 80
NUM_SESSIONS       = 400
NUM_ADMIN_SESSIONS = 30
MAX_CONCURRENT     = 10


CSV_FILE           = "dataset/output/traffic_log.csv"
SOURCE_TOOL        = "playwright"

MISTAKE_SESSION_RATE = 0.08

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

PRE_LOGIN_MISTAKES  = {"wrong_password", "wrong_email_format", "signout_no_token"}
POST_LOGIN_MISTAKES = {
    "overdraft", "double_submit", "transfer_to_self",
    "transfer_nonexistent", "zero_negative_amount", "bad_data_format"
}

SAUDI_CITIES = [
    "Jeddah", "Riyadh", "Mecca", "Medina",
    "Dammam", "Khobar", "Tabuk", "Abha", "Taif", "Buraidah"
]

CLIENT_TYPES = ["web", "ios", "android"]

ADMIN_CREDS = {"username": "admin", "password": "admin123"}

# Seeded users — guaranteed full DB records
SEEDED_USERS = [
    {"email": "user@example.com",        "password": "password123", "geo_location": "Jeddah"},
    {"email": "hanan.alharbi@gmail.com", "password": "password123", "geo_location": "Riyadh"},
    {"email": "taif.alsaadi@gmail.com",  "password": "password123", "geo_location": "Mecca"},
    {"email": "queenrama@gmail.com",     "password": "imthequ33n",  "geo_location": "Jeddah"},
]

fake = Faker()

# ─────────────────────────────────────────────
# PERSONAS
# Dataclass with per-endpoint weights (from Faker code).
# Think time ranges and action counts (from Playwright code).
# ─────────────────────────────────────────────
@dataclass
class PersonaConfig:
    name:             str
    think_min:        float
    think_max:        float
    actions_min:      int
    actions_max:      int
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
PERSONA_WEIGHTS = [40, 20, 10, 30]  # casual, power_user, confused, transactor

ACTION_NAMES = [
    "health", "hello", "auth_me",
    "wallet_view", "topup", "withdraw", "transfer", "pay_bill",
    "view_profile", "update_profile", "payments", "bank_accounts",
]


def pick_persona() -> str:
    return random.choices(PERSONA_NAMES, weights=PERSONA_WEIGHTS, k=1)[0]


def pick_action(persona: PersonaConfig) -> str:
    weights = [
        persona.w_health, persona.w_hello, persona.w_auth_me,
        persona.w_wallet_view, persona.w_topup, persona.w_withdraw,
        persona.w_transfer, persona.w_pay_bill,
        persona.w_view_profile, persona.w_update_profile,
        persona.w_payments, persona.w_bank_accounts,
    ]
    return random.choices(ACTION_NAMES, weights=weights, k=1)[0]


def pick_client_type() -> str:
    return random.choice(CLIENT_TYPES)


def pick_user_agent() -> str:
    return fake.user_agent()


# ─────────────────────────────────────────────
# MISTAKE HELPERS
# ─────────────────────────────────────────────
def pick_mistake() -> str:
    return random.choices(MISTAKE_TYPES, weights=MISTAKE_VALUES, k=1)[0]


def typo_password(pwd: str) -> str:
    chars    = list(pwd)
    mutation = random.choice(["swap", "drop", "insert_digit", "wrong_case"])
    if mutation == "swap" and len(chars) >= 2:
        i = random.randint(0, len(chars) - 2)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    elif mutation == "drop" and len(chars) > 1:
        chars.pop(random.randint(0, len(chars) - 1))
    elif mutation == "insert_digit":
        chars.insert(random.randint(0, len(chars)), str(random.randint(0, 9)))
    elif mutation == "wrong_case":
        chars[0] = chars[0].upper() if chars[0].islower() else chars[0].lower()
    return "".join(chars)


def wrong_email(email: str) -> str:
    mutation = random.choice(["remove_at", "double_dot", "truncate"])
    if mutation == "remove_at":
        return email.replace("@", "")
    elif mutation == "double_dot":
        return email.replace(".", "..", 1)
    return email[:max(3, len(email) - 4)]


def overdraft_amount() -> float:
    return round(random.uniform(50000, 200000), 2)


def zero_or_negative() -> float:
    return random.choice([0, round(-abs(random.uniform(1, 500)), 2)])


def bad_format() -> str:
    return random.choice(["abc", "null", "", "NaN", "one hundred"])


# ─────────────────────────────────────────────
# ENDPOINT CATEGORY
# ─────────────────────────────────────────────
def endpoint_category(path: str) -> str:
    if "/admin" in path:
        return "admin"
    if any(x in path for x in ["/auth/sign-in", "/auth/sign-up",
                                 "/auth/sign-out", "/auth/me"]):
        return "auth"
    if "/wallet" in path:
        return "wallet"
    if "/bank-accounts" in path or "/payments" in path:
        return "account"
    if path.startswith("/users/"):
        return "account"
    if path in ["/health", "/hello"]:
        return "system"
    return "other"


# ─────────────────────────────────────────────
# CSV — 20 columns
# ─────────────────────────────────────────────
CSV_COLUMNS = [
    "timestamp", "session_id", "persona", "email", "user_id",
    "action", "method", "path", "status_code", "is_failed_login",
    "response_time_ms", "think_time_ms", "body_size",
    "has_auth_token", "endpoint_category", "response_length",
    "geo_location", "client_type", "user_agent", "source_tool",
]

csv_lock = asyncio.Lock()


def init_csv():
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(CSV_COLUMNS)


async def log_row(row: dict):
    async with csv_lock:
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([row.get(col, "") for col in CSV_COLUMNS])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_row(
    session_id, persona, email, user_id, action,
    method, path, status_code,
    is_failed_login=False, response_time_ms=0, think_time_ms=0,
    body_size=0, has_auth_token=False,
    response_length=0, geo_location="", client_type="web",
    user_agent="", source_tool=SOURCE_TOOL,
) -> dict:
    return {
        "timestamp":        now_iso(),
        "session_id":       session_id,
        "persona":          persona,
        "email":            email,
        "user_id":          user_id,
        "action":           action,
        "method":           method,
        "path":             path,
        "status_code":      status_code,
        "is_failed_login":  is_failed_login,
        "response_time_ms": response_time_ms,
        "think_time_ms":    think_time_ms,
        "body_size":        body_size,
        "has_auth_token":   has_auth_token,
        "endpoint_category": endpoint_category(path),
        "response_length":  response_length,
        "geo_location":     geo_location,
        "client_type":      client_type,
        "user_agent":       user_agent,
        "source_tool":      source_tool,
    }


# ─────────────────────────────────────────────
# CONSOLE LOG
# ─────────────────────────────────────────────
def clog(sid: str, email: str, action: str, status, rt_ms=None):
    ts = datetime.now().strftime("%H:%M:%S")
    rt = f"{rt_ms}ms" if rt_ms is not None else ""
    print(f"[{ts}] {sid[:8]} | {email[:26]:<26} | {action:<50} | {status} {rt}")


# ─────────────────────────────────────────────
# PROGRESS
# ─────────────────────────────────────────────
session_counter = 0
counter_lock    = asyncio.Lock()


async def tick_progress():
    global session_counter
    async with counter_lock:
        session_counter += 1
        count = session_counter
    total = NUM_SESSIONS + NUM_ADMIN_SESSIONS
    if count % 50 == 0:
        print(f"\n  ▶ Progress: {count}/{total} ({count / total * 100:.1f}%)\n")


# ─────────────────────────────────────────────
# THINK TIME
# ─────────────────────────────────────────────
async def think(persona: PersonaConfig) -> int:
    delay = random.uniform(persona.think_min, persona.think_max)
    await asyncio.sleep(delay)
    return int(delay * 1000)


async def think_admin() -> int:
    delay = random.uniform(0.6, 2.2)
    await asyncio.sleep(delay)
    return int(delay * 1000)


# ─────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────
async def api_post(ctx, path: str, payload=None, token=None,
                   token_type="user", client_type="web", user_agent="") -> Tuple:
    headers = {"Content-Type": "application/json",
               "User-Agent": user_agent, "X-Client-Type": client_type}
    if token:
        headers["X-User-Token" if token_type == "user" else "X-Admin-Token"] = token
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
        headers["X-User-Token" if token_type == "user" else "X-Admin-Token"] = token
    # /health and /hello live at root, not under /api/v1
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


# ─────────────────────────────────────────────
# USER POOL
# ─────────────────────────────────────────────
registered_users  = []
registration_lock = asyncio.Lock()


async def register_new_user(ctx) -> Optional[dict]:
    email       = fake.unique.email()
    password    = fake.password(length=random.randint(8, 14), special_chars=False)
    city        = random.choice(SAUDI_CITIES)
    ct          = pick_client_type()
    ua          = pick_user_agent()
    payload = {
        "full_name": fake.name(),
        "email":     email,
        "password":  password,
        "phone":     f"+9665{random.randint(10000000, 99999999)}",
        "city":      city,
    }
    r, _, _, _ = await api_post(ctx, "/auth/sign-up", payload,
                                 client_type=ct, user_agent=ua)
    if r and r.status == 201:
        body = await r.json()
        user = {
            "email":        email,
            "password":     password,
            "user_id":      body.get("user_id"),
            "geo_location": city,
            "client_type":  ct,
            "user_agent":   ua,
        }
        async with registration_lock:
            registered_users.append(user)
        return user
    return None


async def get_random_user() -> dict:
    async with registration_lock:
        pool = SEEDED_USERS + registered_users
    user = dict(random.choice(pool))
    # seeded users don't have client_type/user_agent — assign consistently
    if "client_type" not in user:
        user["client_type"] = pick_client_type()
        user["user_agent"]  = pick_user_agent()
    return user


# ─────────────────────────────────────────────
# ACTION EXECUTOR
# All 12 user-facing actions dispatched by name.
# ─────────────────────────────────────────────
async def execute_action(ctx, action_name: str, sid: str, uid: str,
                         token: str, email: str, persona: PersonaConfig,
                         geo: str, ct: str, ua: str) -> None:

    if action_name == "health":
        r, rt, r_len = await api_get(ctx, "/health", client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  /health", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "health",
                               "GET", "/health", status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=bool(token),
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "hello":
        r, rt, r_len = await api_get(ctx, "/hello", client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  /hello", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "hello",
                               "GET", "/hello", status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=bool(token),
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "auth_me":
        r, rt, r_len = await api_get(ctx, "/auth/me", token=token,
                                      client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  /auth/me", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "auth_me",
                               "GET", "/auth/me", status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "wallet_view":
        path         = f"/users/{uid}/wallet"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                      client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  wallet/balance", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "wallet_view",
                               "GET", path, status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "topup":
        path             = f"/users/{uid}/wallet/topup"
        amount           = round(random.uniform(10, 500), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/topup ({amount})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "topup",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "withdraw":
        path             = f"/users/{uid}/wallet/withdraw"
        amount           = round(random.uniform(5, 150), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/withdraw ({amount})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "withdraw",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "transfer":
        async with registration_lock:
            targets = [u.get("user_id", "") for u in registered_users[:4]]
        if not targets:
            targets = ["u_1001", "u_1002", "u_1003", "u_1004"]
        target           = random.choice([t for t in targets if t != uid] or targets)
        path             = f"/users/{uid}/wallet/transfer/{target}"
        amount           = round(random.uniform(5, 80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/transfer ({amount} → {target})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "transfer",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "pay_bill":
        path             = f"/users/{uid}/wallet/pay-bill"
        amount           = round(random.uniform(20, 300), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/pay-bill ({amount})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "pay_bill",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "view_profile":
        path         = f"/users/{uid}"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                      client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  user/profile", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "view_profile",
                               "GET", path, status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "update_profile":
        city             = random.choice(SAUDI_CITIES)
        path             = f"/users/{uid}"
        r, rt, bs, r_len = await api_put(ctx, path, {"city": city},
                                          token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"PUT  user/profile (city={city})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "update_profile",
                               "PUT", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "payments":
        path         = f"/users/{uid}/payments"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                      client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  user/payments", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "payments",
                               "GET", path, status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif action_name == "bank_accounts":
        path         = f"/users/{uid}/bank-accounts"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                      client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "GET  user/bank-accounts", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "bank_accounts",
                               "GET", path, status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))


# ─────────────────────────────────────────────
# MISTAKE INJECTION
# ─────────────────────────────────────────────
async def inject_mistake(ctx, sid: str, uid: Optional[str],
                         token: Optional[str], email: str, password: str,
                         persona: PersonaConfig, geo: str,
                         ct: str, ua: str, mtype: str) -> None:

    if mtype == "wrong_password":
        payload          = {"email": email, "password": typo_password(password)}
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in", payload,
                                           client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "POST auth/sign-in (typo password)", status, rt)
        await log_row(make_row(sid, persona.name, email, "unknown", "failed_login",
                               "POST", "/auth/sign-in", status, is_failed_login=True,
                               response_time_ms=rt, think_time_ms=tt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "overdraft":
        path             = f"/users/{uid}/wallet/withdraw"
        amount           = overdraft_amount()
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/withdraw OVERDRAFT ({amount})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "withdraw_overdraft",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "double_submit":
        path   = f"/users/{uid}/wallet/topup"
        amount = round(random.uniform(10, 200), 2)
        for i in range(2):
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                               token=token, client_type=ct, user_agent=ua)
            status      = r.status if r else "ERR"
            action_name = "topup" if i == 0 else "topup_double_submit"
            clog(sid, email, f"POST wallet/topup DOUBLE ({amount}) #{i+1}", status, rt)
            await log_row(make_row(sid, persona.name, email, uid, action_name,
                                   "POST", path, status, response_time_ms=rt,
                                   think_time_ms=0, body_size=bs, has_auth_token=True,
                                   response_length=r_len, geo_location=geo,
                                   client_type=ct, user_agent=ua))
            if i == 0:
                await asyncio.sleep(random.uniform(0, 0.8))
        await think(persona)

    elif mtype == "transfer_to_self":
        path             = f"/users/{uid}/wallet/transfer/{uid}"
        amount           = round(random.uniform(5, 80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/transfer SELF ({amount})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "transfer_to_self",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "transfer_nonexistent":
        fake_uid         = f"u_{random.randint(9000, 9999)}"
        path             = f"/users/{uid}/wallet/transfer/{fake_uid}"
        amount           = round(random.uniform(5, 80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/transfer NONEXISTENT ({fake_uid})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "transfer_nonexistent",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "wrong_email_format":
        bad_em           = wrong_email(email)
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in",
                                           {"email": bad_em, "password": password},
                                           client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST auth/sign-in BAD EMAIL ({bad_em})", status, rt)
        await log_row(make_row(sid, persona.name, email, "unknown",
                               "failed_login_bad_email",
                               "POST", "/auth/sign-in", status, is_failed_login=True,
                               response_time_ms=rt, think_time_ms=tt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "signout_no_token":
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-out",
                                           client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, "POST auth/sign-out NO TOKEN", status, rt)
        await log_row(make_row(sid, persona.name, email, "unknown", "signout_no_token",
                               "POST", "/auth/sign-out", status,
                               response_time_ms=rt, think_time_ms=tt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "zero_negative_amount":
        ep               = random.choice(["topup", "withdraw", "pay-bill"])
        path             = f"/users/{uid}/wallet/{ep}"
        amount           = zero_or_negative()
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/{ep} ZERO/NEG ({amount})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, f"{ep}_bad_amount",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    elif mtype == "bad_data_format":
        path             = f"/users/{uid}/wallet/topup"
        amount           = bad_format()
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                           token=token, client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think(persona)
        clog(sid, email, f"POST wallet/topup BAD FORMAT ({repr(amount)})", status, rt)
        await log_row(make_row(sid, persona.name, email, uid, "topup_bad_format",
                               "POST", path, status, response_time_ms=rt,
                               think_time_ms=tt, body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))


# ─────────────────────────────────────────────
# USER SESSION RUNNER
# ─────────────────────────────────────────────
async def run_session(ctx) -> None:
    sid          = str(uuid.uuid4())
    persona_name = pick_persona()
    persona      = PERSONAS[persona_name]
    user         = await get_random_user()
    email        = user["email"]
    password     = user["password"]
    geo          = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct           = user.get("client_type", pick_client_type())
    ua           = user.get("user_agent",  pick_user_agent())

    # Stagger start — creates genuine server load contention for RT variance
    await asyncio.sleep(random.uniform(0, 8))

    # Decide mistake for this session
    mistake = pick_mistake() if random.random() < MISTAKE_SESSION_RATE else None

    # ── Pre-login mistakes ──
    if mistake in PRE_LOGIN_MISTAKES:
        await inject_mistake(ctx, sid, None, None, email, password,
                             persona, geo, ct, ua, mistake)
        mistake = None

    # ── Login ──
    r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in",
                                       {"email": email, "password": password},
                                       client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        status = r.status if r else "NO RESPONSE"
        clog(sid, email, "POST auth/sign-in", f"FAILED ({status})", rt)
        await log_row(make_row(sid, persona_name, email, "unknown", "sign_in",
                               "POST", "/auth/sign-in", status,
                               response_time_ms=rt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")
    tt      = await think(persona)
    clog(sid, email, "POST auth/sign-in", f"200 OK [{persona_name}]", rt)
    await log_row(make_row(sid, persona_name, email, user_id, "sign_in",
                           "POST", "/auth/sign-in", 200,
                           response_time_ms=rt, think_time_ms=tt, body_size=bs,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))

    # ── Seed balance if zero (prevents 400s on withdraw/pay-bill) ──
    if random.random() < 0.7:  # 70% of sessions start with a topup
        seed_amount = round(random.uniform(100, 500), 2)
        await api_post(ctx, f"/users/{user_id}/wallet/topup",
                       {"amount": seed_amount}, token=token,
                       client_type=ct, user_agent=ua)
    # ── Post-login mistakes ──
    if mistake in POST_LOGIN_MISTAKES:
        await inject_mistake(ctx, sid, user_id, token, email, password,
                             persona, geo, ct, ua, mistake)

    # ── Normal actions ──
    n_actions = random.randint(persona.actions_min, persona.actions_max)
    for _ in range(n_actions):
        await execute_action(ctx, pick_action(persona), sid, user_id,
                             token, email, persona, geo, ct, ua)

    # ── Logout ──
    r, rt, _, r_len = await api_post(ctx, "/auth/sign-out", token=token,
                                      client_type=ct, user_agent=ua)
    status = r.status if r else "ERR"
    clog(sid, email, "POST auth/sign-out", status, rt)
    await log_row(make_row(sid, persona_name, email, user_id, "sign_out",
                           "POST", "/auth/sign-out", status,
                           response_time_ms=rt, has_auth_token=True,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))


# ─────────────────────────────────────────────
# ADMIN SESSION RUNNER
# Variable session length from Faker code (5–35 actions).
# Weighted endpoint selection across all 4 admin endpoints.
# ─────────────────────────────────────────────
async def run_admin_session(ctx) -> None:
    sid = str(uuid.uuid4())
    geo = random.choice(SAUDI_CITIES)
    ct  = pick_client_type()
    ua  = pick_user_agent()

    await asyncio.sleep(random.uniform(0, 4))

    r, rt, bs, r_len = await api_post(ctx, "/admin/auth/sign-in", ADMIN_CREDS,
                                       client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        status = r.status if r else "NO RESPONSE"
        clog(sid, "admin", "POST admin/sign-in", f"FAILED ({status})", rt)
        await log_row(make_row(sid, "admin", "admin@rasd.local", "admin_1",
                               "admin_sign_in", "POST", "/admin/auth/sign-in", status,
                               response_time_ms=rt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))
        return

    body        = await r.json()
    admin_token = body.get("token")
    tt          = await think_admin()
    clog(sid, "admin", "POST admin/sign-in", "200 OK [admin]", rt)
    await log_row(make_row(sid, "admin", "admin@rasd.local", "admin_1",
                           "admin_sign_in", "POST", "/admin/auth/sign-in", 200,
                           response_time_ms=rt, think_time_ms=tt, body_size=bs,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))

    # Variable session length — admin reviews different amounts of data per session
    session_length = random.choices([5, 10, 20, 35], weights=[30, 30, 25, 15], k=1)[0]
    admin_paths    = ["/admin/users", "/admin/wallets",
                      "/admin/transactions", "/admin/overview/financial"]
    admin_weights  = [30, 25, 25, 20]

    for _ in range(session_length):
        path         = random.choices(admin_paths, weights=admin_weights, k=1)[0]
        r, rt, r_len = await api_get(ctx, path, token=admin_token,
                                      token_type="admin", client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt     = await think_admin()
        clog(sid, "admin", f"GET  {path}", status, rt)
        await log_row(make_row(sid, "admin", "admin@rasd.local", "admin_1",
                               f"admin_{path.split('/')[-1]}",
                               "GET", path, status, response_time_ms=rt,
                               think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    r, rt, _, r_len = await api_post(ctx, "/admin/auth/sign-out",
                                      token=admin_token, token_type="admin",
                                      client_type=ct, user_agent=ua)
    status = r.status if r else "ERR"
    clog(sid, "admin", "POST admin/sign-out", status, rt)
    await log_row(make_row(sid, "admin", "admin@rasd.local", "admin_1",
                           "admin_sign_out", "POST", "/admin/auth/sign-out", status,
                           response_time_ms=rt, has_auth_token=True,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
async def main():
    init_csv()
    total = NUM_SESSIONS + NUM_ADMIN_SESSIONS

    print("=" * 90)
    print("  RASD Unified Traffic Generator — Week 4 Task 1")
    print(f"  Sessions      : {NUM_SESSIONS} user  +  {NUM_ADMIN_SESSIONS} admin  =  {total} total")
    print(f"  Users         : {NUM_USERS}  |  Concurrency: {MAX_CONCURRENT}")
    print(f"  Mistake rate  : {int(MISTAKE_SESSION_RATE * 100)}%  |  9 mistake types")
    print(f"  Personas      : casual / power_user / confused / transactor")
    print(f"  Endpoints     : 20 (health, hello, auth x3, wallet x5, account x4, admin x6)")
    print(f"  CSV columns   : {len(CSV_COLUMNS)}")
    print(f"  Output        : {CSV_FILE}")
    print("=" * 90)

    async with async_playwright() as playwright:

        # ── Pre-register users ──
        target = NUM_USERS - len(SEEDED_USERS)
        print(f"\n[SETUP] Registering {target} new users...")
        sb = await playwright.chromium.launch()
        sc = await sb.new_context()
        for i in range(target):
            await register_new_user(sc.request)
            if (i + 1) % 10 == 0:
                print(f"  {i + 1}/{target} registered...")
            await asyncio.sleep(0.2)
        await sc.close()
        await sb.close()
        print(f"[SETUP] ✅ {len(SEEDED_USERS) + len(registered_users)} users ready\n")

        # ── Launch persistent browser workers ──
        print(f"[SETUP] Launching {MAX_CONCURRENT} persistent browser workers...")
        browsers, contexts, ctxs = [], [], []
        for _ in range(MAX_CONCURRENT):
            bw = await playwright.chromium.launch()
            cx = await bw.new_context()
            browsers.append(bw)
            contexts.append(cx)
            ctxs.append(cx.request)
        print(f"[SETUP] ✅ Workers ready\n")

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        async def run_user_task(wid: int):
            async with semaphore:
                await run_session(ctxs[wid % MAX_CONCURRENT])
                await tick_progress()

        async def run_admin_task(wid: int):
            async with semaphore:
                await run_admin_session(ctxs[wid % MAX_CONCURRENT])
                await tick_progress()

        all_tasks = (
            [run_user_task(i)  for i in range(NUM_SESSIONS)] +
            [run_admin_task(i) for i in range(NUM_ADMIN_SESSIONS)]
        )
        random.shuffle(all_tasks)
        await asyncio.gather(*all_tasks)

        for cx in contexts:
            await cx.close()
        for bw in browsers:
            await bw.close()

    print("\n" + "=" * 90)
    print(f"  ✅ Done! {total} sessions completed.")
    print(f"  CSV : {CSV_FILE}  |  Columns: {len(CSV_COLUMNS)}  |  Source: {SOURCE_TOOL}")
    print("=" * 90)


if __name__ == "__main__":
    asyncio.run(main())