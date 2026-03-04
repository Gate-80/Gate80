"""
RASD - Realistic Human Behavioral Traffic Generator
Week 4 - Task 1: Baseline Normal Traffic

All modifications applied:
  ✅ Response time variance  — one persistent browser per worker slot, reused
                               across sessions. Eliminates per-session launch
                               overhead. Aggressive stagger (0-8s) creates
                               genuine server contention and natural variance.
  ✅ 9 mistake types (8% of sessions get exactly one mistake):
       30% wrong_password       — mutates real password (swap/drop/insert/case)
       20% overdraft            — withdraw/transfer way above any real balance
       15% double_submit        — same POST re-fired within 0-800ms
       10% transfer_to_self     — uid == target_uid
        8% transfer_nonexistent — target u_9000-9999 (does not exist)
        6% wrong_email_format   — malformed email on sign-in
        5% signout_no_token     — logout attempt with no auth token
        4% zero_negative_amount — zero or negative on any money action
        2% bad_data_format      — string instead of number for amount
  ✅ 404 fix        — wallet/payment/bank restricted to seeded users only.
  ✅ Admin coverage — 20 admin sessions covering all 4 admin endpoints.
  ✅ geo_location   — consistent Saudi city per user assigned at signup.
  ✅ /auth/me       — included in action pool.
  ✅ 17 features    — all agreed features per row.

Features per row:
    timestamp, session_id, persona, email, user_id, action,
    method, path, status_code, is_failed_login,
    response_time_ms, think_time_ms, body_size,
    has_auth_token, endpoint_category, response_length, geo_location

Install:
    pip install playwright faker
    playwright install chromium

Run:
    python generate_traffic.py
"""

import asyncio
import random
import json
import csv
import time
from faker import Faker
from datetime import datetime
from playwright.async_api import async_playwright

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
BASE_URL           = "http://127.0.0.1:8080/api/v1"
NUM_USERS          = 80
NUM_SESSIONS       = 280  # regular user sessions
NUM_ADMIN_SESSIONS = 20   # admin-only sessions
MAX_CONCURRENT     = 20
CSV_FILE           = "traffic_log.csv"

# 8% of user sessions will contain exactly one mistake
MISTAKE_SESSION_RATE = 0.08

# Weights for each mistake type (sum = 100)
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

SAUDI_CITIES = [
    "Jeddah", "Riyadh", "Mecca", "Medina",
    "Dammam", "Khobar", "Tabuk", "Abha", "Taif", "Buraidah"
]

ADMIN_CREDS = {"username": "admin", "password": "admin123"}

fake = Faker()

# ─────────────────────────────────────────────
# ENDPOINT CATEGORY MAPPING
# ─────────────────────────────────────────────
def get_endpoint_category(path: str) -> str:
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
    return "other"

# ─────────────────────────────────────────────
# USER POOL
#
# SEEDED     → full wallet/payment/bank records in DB → all actions safe
# REGISTERED → auth record only → restricted to auth + profile actions
# ─────────────────────────────────────────────
SEEDED_USERS = [
    {"email": "user@example.com",        "password": "password123",
     "geo_location": "Jeddah",  "full_db": True},
    {"email": "hanan.alharbi@gmail.com", "password": "password123",
     "geo_location": "Riyadh",  "full_db": True},
    {"email": "taif.alsaadi@gmail.com",  "password": "password123",
     "geo_location": "Mecca",   "full_db": True},
]

registered_users  = []
registration_lock = asyncio.Lock()
csv_lock          = asyncio.Lock()
session_counter   = 0
counter_lock      = asyncio.Lock()

# ─────────────────────────────────────────────
# PERSONAS
# ─────────────────────────────────────────────
PERSONAS = {
    "casual": {
        "think_min": 3.0,  "think_max": 12.0,
        "actions_min": 2,  "actions_max": 6,
        "fail_login_chance": 0.05,
    },
    "power_user": {
        "think_min": 0.5,  "think_max": 2.5,
        "actions_min": 7,  "actions_max": 15,
        "fail_login_chance": 0.01,
    },
    "confused": {
        "think_min": 8.0,  "think_max": 25.0,
        "actions_min": 1,  "actions_max": 3,
        "fail_login_chance": 0.30,
    },
    "transactor": {
        "think_min": 1.0,  "think_max": 5.0,
        "actions_min": 4,  "actions_max": 9,
        "fail_login_chance": 0.02,
    },
}

def pick_persona():
    return random.choices(list(PERSONAS.keys()), weights=[40, 20, 10, 30])[0]

# ─────────────────────────────────────────────
# MISTAKE HELPERS
# ─────────────────────────────────────────────
def pick_mistake() -> str:
    return random.choices(MISTAKE_TYPES, weights=MISTAKE_VALUES, k=1)[0]

def typo_password(pwd: str) -> str:
    """Mutate real password the way a human would mistype it."""
    chars     = list(pwd)
    mutation  = random.choice(["swap", "drop", "insert_digit", "wrong_case"])
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
    """Produce a plausibly mistyped email."""
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
# CSV
# ─────────────────────────────────────────────
def init_csv():
    with open(CSV_FILE, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp", "session_id", "persona", "email", "user_id",
            "action", "method", "path", "status_code", "is_failed_login",
            "response_time_ms", "think_time_ms", "body_size",
            "has_auth_token", "endpoint_category", "response_length",
            "geo_location",
        ])

async def log_to_csv(
    session_id, persona, email, user_id, action,
    method, path, status_code,
    is_failed_login=False,
    response_time_ms=0, think_time_ms=0, body_size=0,
    has_auth_token=False, endpoint_category="other",
    response_length=0, geo_location="unknown"
):
    async with csv_lock:
        with open(CSV_FILE, "a", newline="") as f:
            csv.writer(f).writerow([
                datetime.now().isoformat(),
                session_id, persona, email, user_id,
                action, method, path, status_code, is_failed_login,
                response_time_ms, think_time_ms, body_size,
                has_auth_token, endpoint_category, response_length,
                geo_location,
            ])

# ─────────────────────────────────────────────
# CONSOLE LOG
# ─────────────────────────────────────────────
def log(session_id, email, action, status, rt_ms=None):
    ts = datetime.now().strftime("%H:%M:%S")
    rt = f"{rt_ms}ms" if rt_ms is not None else ""
    print(f"[{ts}] #{session_id:05d} | {email[:26]:<26} | {action:<48} | {status} {rt}")

# ─────────────────────────────────────────────
# PROGRESS
# ─────────────────────────────────────────────
async def tick_progress():
    global session_counter
    async with counter_lock:
        session_counter += 1
        count = session_counter
    total = NUM_SESSIONS + NUM_ADMIN_SESSIONS
    if count % 50 == 0:
        print(f"\n  ▶ Progress: {count}/{total} ({count/total*100:.1f}%)\n")

# ─────────────────────────────────────────────
# THINK TIME
# ─────────────────────────────────────────────
async def think(persona_name) -> int:
    p     = PERSONAS[persona_name]
    delay = random.uniform(p["think_min"], p["think_max"])
    await asyncio.sleep(delay)
    return int(delay * 1000)

async def think_admin() -> int:
    delay = random.uniform(1.0, 5.0)
    await asyncio.sleep(delay)
    return int(delay * 1000)

# ─────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────
async def api_post(ctx, path, payload=None, token=None, token_type="user"):
    headers  = {"Content-Type": "application/json"}
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

async def api_get(ctx, path, token=None, token_type="user"):
    headers = {}
    if token:
        headers["X-User-Token" if token_type == "user" else "X-Admin-Token"] = token
    try:
        t = time.time()
        r = await ctx.get(f"{BASE_URL}{path}", headers=headers)
        rt_ms = int((time.time() - t) * 1000)
        return r, rt_ms, len(await r.body())
    except Exception:
        return None, 0, 0

async def api_put(ctx, path, payload=None, token=None):
    headers  = {"Content-Type": "application/json"}
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
# USER REGISTRATION
# ─────────────────────────────────────────────
async def register_new_user(ctx):
    email    = fake.unique.email()
    password = fake.password(length=random.randint(8, 14), special_chars=False)
    city     = random.choice(SAUDI_CITIES)
    payload  = {
        "full_name": fake.name(), "email": email,
        "password": password,
        "phone": f"+9665{random.randint(10000000, 99999999)}",
        "city": city,
    }
    r, _, _, _ = await api_post(ctx, "/auth/sign-up", payload)
    if r and r.status == 201:
        body = await r.json()
        user = {
            "email": email, "password": password,
            "user_id": body.get("user_id"),
            "geo_location": city,
            "full_db": False,
        }
        async with registration_lock:
            registered_users.append(user)
        return user
    return None

async def get_seeded_user():
    return random.choice(SEEDED_USERS)

async def get_any_user():
    async with registration_lock:
        pool = SEEDED_USERS + registered_users
    return random.choice(pool)

# ─────────────────────────────────────────────
# NORMAL ACTIONS — WALLET (seeded users only)
# ─────────────────────────────────────────────
async def action_view_balance(ctx, sid, uid, token, email, persona, geo):
    path         = f"/users/{uid}/wallet"
    r, rt, r_len = await api_get(ctx, path, token=token)
    status       = r.status if r else "ERR"
    tt           = await think(persona)
    log(sid, email, "GET  wallet/balance", status, rt)
    await log_to_csv(sid, persona, email, uid, "view_balance",
                     "GET", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=0, has_auth_token=True, endpoint_category="wallet",
                     response_length=r_len, geo_location=geo)

async def action_topup(ctx, sid, uid, token, email, persona, geo):
    path             = f"/users/{uid}/wallet/topup"
    amount           = round(random.uniform(10, 500), 2)
    r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
    status           = r.status if r else "ERR"
    tt               = await think(persona)
    log(sid, email, f"POST wallet/topup ({amount})", status, rt)
    await log_to_csv(sid, persona, email, uid, "topup",
                     "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=bs, has_auth_token=True, endpoint_category="wallet",
                     response_length=r_len, geo_location=geo)

async def action_withdraw(ctx, sid, uid, token, email, persona, geo):
    path             = f"/users/{uid}/wallet/withdraw"
    amount           = round(random.uniform(5, 150), 2)
    r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
    status           = r.status if r else "ERR"
    tt               = await think(persona)
    log(sid, email, f"POST wallet/withdraw ({amount})", status, rt)
    await log_to_csv(sid, persona, email, uid, "withdraw",
                     "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=bs, has_auth_token=True, endpoint_category="wallet",
                     response_length=r_len, geo_location=geo)

async def action_transfer(ctx, sid, uid, token, email, persona, geo):
    targets          = ["u_1001", "u_1002", "u_1003", "u_1004"]
    target           = random.choice([t for t in targets if t != uid] or targets)
    path             = f"/users/{uid}/wallet/transfer/{target}"
    amount           = round(random.uniform(5, 80), 2)
    r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
    status           = r.status if r else "ERR"
    tt               = await think(persona)
    log(sid, email, f"POST wallet/transfer ({amount} → {target})", status, rt)
    await log_to_csv(sid, persona, email, uid, "transfer",
                     "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=bs, has_auth_token=True, endpoint_category="wallet",
                     response_length=r_len, geo_location=geo)

async def action_pay_bill(ctx, sid, uid, token, email, persona, geo):
    path             = f"/users/{uid}/wallet/pay-bill"
    amount           = round(random.uniform(20, 300), 2)
    r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
    status           = r.status if r else "ERR"
    tt               = await think(persona)
    log(sid, email, f"POST wallet/pay-bill ({amount})", status, rt)
    await log_to_csv(sid, persona, email, uid, "pay_bill",
                     "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=bs, has_auth_token=True, endpoint_category="wallet",
                     response_length=r_len, geo_location=geo)

# ─────────────────────────────────────────────
# NORMAL ACTIONS — ACCOUNT (all users)
# ─────────────────────────────────────────────
async def action_view_profile(ctx, sid, uid, token, email, persona, geo):
    path         = f"/users/{uid}"
    r, rt, r_len = await api_get(ctx, path, token=token)
    status       = r.status if r else "ERR"
    tt           = await think(persona)
    log(sid, email, "GET  user/profile", status, rt)
    await log_to_csv(sid, persona, email, uid, "view_profile",
                     "GET", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=0, has_auth_token=True, endpoint_category="account",
                     response_length=r_len, geo_location=geo)

async def action_view_payments(ctx, sid, uid, token, email, persona, geo):
    path         = f"/users/{uid}/payments"
    r, rt, r_len = await api_get(ctx, path, token=token)
    status       = r.status if r else "ERR"
    tt           = await think(persona)
    log(sid, email, "GET  user/payments", status, rt)
    await log_to_csv(sid, persona, email, uid, "view_payments",
                     "GET", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=0, has_auth_token=True, endpoint_category="account",
                     response_length=r_len, geo_location=geo)

async def action_view_bank_accounts(ctx, sid, uid, token, email, persona, geo):
    path         = f"/users/{uid}/bank-accounts"
    r, rt, r_len = await api_get(ctx, path, token=token)
    status       = r.status if r else "ERR"
    tt           = await think(persona)
    log(sid, email, "GET  user/bank-accounts", status, rt)
    await log_to_csv(sid, persona, email, uid, "view_bank_accounts",
                     "GET", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=0, has_auth_token=True, endpoint_category="account",
                     response_length=r_len, geo_location=geo)

async def action_update_profile(ctx, sid, uid, token, email, persona, geo):
    city             = random.choice(SAUDI_CITIES)
    path             = f"/users/{uid}"
    r, rt, bs, r_len = await api_put(ctx, path, {"city": city}, token=token)
    status           = r.status if r else "ERR"
    tt               = await think(persona)
    log(sid, email, f"PUT  user/profile (city={city})", status, rt)
    await log_to_csv(sid, persona, email, uid, "update_profile",
                     "PUT", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=bs, has_auth_token=True, endpoint_category="account",
                     response_length=r_len, geo_location=geo)

async def action_auth_me(ctx, sid, uid, token, email, persona, geo):
    path         = "/auth/me"
    r, rt, r_len = await api_get(ctx, path, token=token)
    status       = r.status if r else "ERR"
    tt           = await think(persona)
    log(sid, email, "GET  auth/me", status, rt)
    await log_to_csv(sid, persona, email, uid, "auth_me",
                     "GET", path, status, response_time_ms=rt, think_time_ms=tt,
                     body_size=0, has_auth_token=True, endpoint_category="auth",
                     response_length=r_len, geo_location=geo)

# ─────────────────────────────────────────────
# ACTION POOLS
# ─────────────────────────────────────────────
FULL_ACTIONS = [
    action_view_balance,        # ~27%
    action_view_balance,
    action_view_balance,
    action_topup,               # ~10%
    action_topup,
    action_withdraw,            # ~9%
    action_withdraw,
    action_transfer,            # ~9%
    action_transfer,
    action_view_profile,        # ~9%
    action_view_profile,
    action_view_payments,       # ~9%
    action_view_payments,
    action_view_bank_accounts,  # ~7%
    action_view_bank_accounts,
    action_pay_bill,            # ~5%
    action_update_profile,      # ~3%
    action_auth_me,             # ~5%
]

LIMITED_ACTIONS = [
    action_view_profile,        # ~33%
    action_view_profile,
    action_view_profile,
    action_auth_me,             # ~33%
    action_auth_me,
    action_auth_me,
    action_update_profile,      # ~22%
    action_update_profile,
    action_view_payments,       # ~11%
]

# ─────────────────────────────────────────────
# MISTAKE INJECTION
# One mistake per session, injected at the right point in the lifecycle.
# Pre-login mistakes: wrong_password, wrong_email_format, signout_no_token
# Post-login mistakes: everything else (needs valid token + uid)
# ─────────────────────────────────────────────
PRE_LOGIN_MISTAKES  = {"wrong_password", "wrong_email_format", "signout_no_token"}
POST_LOGIN_MISTAKES = {
    "overdraft", "double_submit", "transfer_to_self",
    "transfer_nonexistent", "zero_negative_amount", "bad_data_format"
}

async def inject_mistake(ctx, sid, uid, token, email, password, persona, geo, mtype):

    # 1. Wrong password typo
    if mtype == "wrong_password":
        payload          = {"email": email, "password": typo_password(password)}
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in", payload)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, "POST auth/sign-in (typo password)", status, rt)
        await log_to_csv(sid, persona, email, "unknown", "failed_login",
                         "POST", "/auth/sign-in", status, is_failed_login=True,
                         response_time_ms=rt, think_time_ms=tt, body_size=bs,
                         has_auth_token=False, endpoint_category="auth",
                         response_length=r_len, geo_location=geo)

    # 2. Overdraft
    elif mtype == "overdraft":
        path             = f"/users/{uid}/wallet/withdraw"
        amount           = overdraft_amount()
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, f"POST wallet/withdraw OVERDRAFT ({amount})", status, rt)
        await log_to_csv(sid, persona, email, uid, "withdraw_overdraft",
                         "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                         body_size=bs, has_auth_token=True, endpoint_category="wallet",
                         response_length=r_len, geo_location=geo)

    # 3. Double-submit — topup fired twice with 0-800ms gap
    elif mtype == "double_submit":
        path   = f"/users/{uid}/wallet/topup"
        amount = round(random.uniform(10, 200), 2)
        for i in range(2):
            r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
            status           = r.status if r else "ERR"
            action_name      = "topup" if i == 0 else "topup_double_submit"
            log(sid, email, f"POST wallet/topup DOUBLE ({amount}) #{i+1}", status, rt)
            await log_to_csv(sid, persona, email, uid, action_name,
                             "POST", path, status, response_time_ms=rt, think_time_ms=0,
                             body_size=bs, has_auth_token=True, endpoint_category="wallet",
                             response_length=r_len, geo_location=geo)
            if i == 0:
                await asyncio.sleep(random.uniform(0, 0.8))
        await think(persona)

    # 4. Transfer to self
    elif mtype == "transfer_to_self":
        path             = f"/users/{uid}/wallet/transfer/{uid}"
        amount           = round(random.uniform(5, 80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, f"POST wallet/transfer SELF ({amount})", status, rt)
        await log_to_csv(sid, persona, email, uid, "transfer_to_self",
                         "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                         body_size=bs, has_auth_token=True, endpoint_category="wallet",
                         response_length=r_len, geo_location=geo)

    # 5. Transfer to nonexistent user
    elif mtype == "transfer_nonexistent":
        fake_uid         = f"u_{random.randint(9000, 9999)}"
        path             = f"/users/{uid}/wallet/transfer/{fake_uid}"
        amount           = round(random.uniform(5, 80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, f"POST wallet/transfer NONEXISTENT ({fake_uid})", status, rt)
        await log_to_csv(sid, persona, email, uid, "transfer_nonexistent",
                         "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                         body_size=bs, has_auth_token=True, endpoint_category="wallet",
                         response_length=r_len, geo_location=geo)

    # 6. Wrong email format on sign-in
    elif mtype == "wrong_email_format":
        bad_em           = wrong_email(email)
        payload          = {"email": bad_em, "password": password}
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in", payload)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, f"POST auth/sign-in BAD EMAIL ({bad_em})", status, rt)
        await log_to_csv(sid, persona, email, "unknown", "failed_login_bad_email",
                         "POST", "/auth/sign-in", status, is_failed_login=True,
                         response_time_ms=rt, think_time_ms=tt, body_size=bs,
                         has_auth_token=False, endpoint_category="auth",
                         response_length=r_len, geo_location=geo)

    # 7. Sign-out with no token
    elif mtype == "signout_no_token":
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-out")  # no token
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, "POST auth/sign-out NO TOKEN", status, rt)
        await log_to_csv(sid, persona, email, "unknown", "signout_no_token",
                         "POST", "/auth/sign-out", status,
                         response_time_ms=rt, think_time_ms=tt, body_size=bs,
                         has_auth_token=False, endpoint_category="auth",
                         response_length=r_len, geo_location=geo)

    # 8. Zero or negative amount
    elif mtype == "zero_negative_amount":
        endpoint         = random.choice(["topup", "withdraw", "pay-bill"])
        path             = f"/users/{uid}/wallet/{endpoint}"
        amount           = zero_or_negative()
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, f"POST wallet/{endpoint} ZERO/NEG ({amount})", status, rt)
        await log_to_csv(sid, persona, email, uid, f"{endpoint}_bad_amount",
                         "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                         body_size=bs, has_auth_token=True, endpoint_category="wallet",
                         response_length=r_len, geo_location=geo)

    # 9. Bad data format
    elif mtype == "bad_data_format":
        path             = f"/users/{uid}/wallet/topup"
        amount           = bad_format()
        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount}, token=token)
        status           = r.status if r else "ERR"
        tt               = await think(persona)
        log(sid, email, f"POST wallet/topup BAD FORMAT ({repr(amount)})", status, rt)
        await log_to_csv(sid, persona, email, uid, "topup_bad_format",
                         "POST", path, status, response_time_ms=rt, think_time_ms=tt,
                         body_size=bs, has_auth_token=True, endpoint_category="wallet",
                         response_length=r_len, geo_location=geo)

# ─────────────────────────────────────────────
# USER SESSION RUNNER
# ctx is passed in — shared persistent browser context per worker slot
# ─────────────────────────────────────────────
async def run_session(session_id, ctx):
    persona_name = pick_persona()
    persona_cfg  = PERSONAS[persona_name]

    # 70% seeded (full wallet access), 30% registered (profile/auth only)
    if random.random() < 0.70:
        user        = await get_seeded_user()
        action_pool = FULL_ACTIONS
    else:
        user        = await get_any_user()
        action_pool = FULL_ACTIONS if user.get("full_db") else LIMITED_ACTIONS

    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", "unknown")

    # Aggressive stagger — creates genuine server load contention
    await asyncio.sleep(random.uniform(0, 8))

    # Decide once if this session gets a mistake
    mistake = pick_mistake() if random.random() < MISTAKE_SESSION_RATE else None

    # ── Pre-login mistakes ──
    if mistake in PRE_LOGIN_MISTAKES:
        await inject_mistake(ctx, session_id, None, None,
                             email, password, persona_name, geo, mistake)
        mistake = None  # consumed

    # ── Login ──
    payload          = {"email": email, "password": password}
    r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in", payload)

    if not r or r.status != 200:
        status = r.status if r else "NO RESPONSE"
        log(session_id, email, "POST auth/sign-in", f"FAILED ({status})", rt)
        await log_to_csv(session_id, persona_name, email, "unknown", "sign_in",
                         "POST", "/auth/sign-in", status,
                         response_time_ms=rt, think_time_ms=0, body_size=bs,
                         has_auth_token=False, endpoint_category="auth",
                         response_length=r_len, geo_location=geo)
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")
    tt      = await think(persona_name)
    log(session_id, email, "POST auth/sign-in", f"200 OK [{persona_name}]", rt)
    await log_to_csv(session_id, persona_name, email, user_id, "sign_in",
                     "POST", "/auth/sign-in", 200,
                     response_time_ms=rt, think_time_ms=tt, body_size=bs,
                     has_auth_token=False, endpoint_category="auth",
                     response_length=r_len, geo_location=geo)

    # ── Post-login mistakes (wallet mistakes only for seeded users) ──
    if mistake in POST_LOGIN_MISTAKES and action_pool == FULL_ACTIONS:
        await inject_mistake(ctx, session_id, user_id, token,
                             email, password, persona_name, geo, mistake)

    # ── Normal actions ──
    num_actions = random.randint(persona_cfg["actions_min"], persona_cfg["actions_max"])
    for action_fn in random.choices(action_pool, k=num_actions):
        await action_fn(ctx, session_id, user_id, token, email, persona_name, geo)

    # ── Logout ──
    r, rt, _, r_len = await api_post(ctx, "/auth/sign-out", token=token)
    status          = r.status if r else "ERR"
    log(session_id, email, "POST auth/sign-out", status, rt)
    await log_to_csv(session_id, persona_name, email, user_id, "sign_out",
                     "POST", "/auth/sign-out", status,
                     response_time_ms=rt, think_time_ms=0, body_size=0,
                     has_auth_token=True, endpoint_category="auth",
                     response_length=r_len, geo_location=geo)

# ─────────────────────────────────────────────
# ADMIN SESSION RUNNER
# ─────────────────────────────────────────────
async def run_admin_session(session_id, ctx):
    geo = "Riyadh"
    await asyncio.sleep(random.uniform(0, 4))

    r, rt, bs, r_len = await api_post(ctx, "/admin/auth/sign-in", ADMIN_CREDS)
    if not r or r.status != 200:
        status = r.status if r else "NO RESPONSE"
        log(session_id, "admin", "POST admin/sign-in", f"FAILED ({status})", rt)
        await log_to_csv(session_id, "admin", "admin", "admin", "admin_sign_in",
                         "POST", "/admin/auth/sign-in", status,
                         response_time_ms=rt, think_time_ms=0, body_size=bs,
                         has_auth_token=False, endpoint_category="admin",
                         response_length=r_len, geo_location=geo)
        return

    body        = await r.json()
    admin_token = body.get("token")
    tt          = await think_admin()
    log(session_id, "admin", "POST admin/sign-in", "200 OK [admin]", rt)
    await log_to_csv(session_id, "admin", "admin", "admin", "admin_sign_in",
                     "POST", "/admin/auth/sign-in", 200,
                     response_time_ms=rt, think_time_ms=tt, body_size=bs,
                     has_auth_token=False, endpoint_category="admin",
                     response_length=r_len, geo_location=geo)

    # All 4 admin endpoints in random order each session
    admin_actions = [
        ("/admin/users",             "admin_view_users"),
        ("/admin/wallets",           "admin_view_wallets"),
        ("/admin/transactions",      "admin_view_transactions"),
        ("/admin/overview/financial","admin_view_financial"),
    ]
    random.shuffle(admin_actions)
    for path, action_name in admin_actions:
        r, rt, r_len = await api_get(ctx, path, token=admin_token, token_type="admin")
        status       = r.status if r else "ERR"
        tt           = await think_admin()
        log(session_id, "admin", f"GET  {path}", status, rt)
        await log_to_csv(session_id, "admin", "admin", "admin", action_name,
                         "GET", path, status, response_time_ms=rt, think_time_ms=tt,
                         body_size=0, has_auth_token=True, endpoint_category="admin",
                         response_length=r_len, geo_location=geo)

    r, rt, _, r_len = await api_post(ctx, "/admin/auth/sign-out",
                                      token=admin_token, token_type="admin")
    status          = r.status if r else "ERR"
    log(session_id, "admin", "POST admin/sign-out", status, rt)
    await log_to_csv(session_id, "admin", "admin", "admin", "admin_sign_out",
                     "POST", "/admin/auth/sign-out", status,
                     response_time_ms=rt, think_time_ms=0, body_size=0,
                     has_auth_token=True, endpoint_category="admin",
                     response_length=r_len, geo_location=geo)

# ─────────────────────────────────────────────
# MAIN
# One persistent browser launched per worker slot at startup.
# Reused across all sessions — removes launch overhead, enables genuine
# server load contention for natural response time variance.
# ─────────────────────────────────────────────
async def main():
    init_csv()
    total = NUM_SESSIONS + NUM_ADMIN_SESSIONS

    print("=" * 90)
    print("  RASD Traffic Generator — Week 4 Task 1")
    print(f"  User sessions : {NUM_SESSIONS}  |  Admin sessions: {NUM_ADMIN_SESSIONS}  |  Total: {total}")
    print(f"  Users         : {NUM_USERS}  |  Concurrency: {MAX_CONCURRENT}")
    print(f"  Mistake rate  : {int(MISTAKE_SESSION_RATE*100)}% of sessions  |  9 mistake types")
    print(f"  CSV           : {CSV_FILE}")
    print("=" * 90)

    async with async_playwright() as playwright:

        # ── Pre-register users ──
        print(f"\n[SETUP] Pre-registering {NUM_USERS - len(SEEDED_USERS)} users...")
        sb  = await playwright.chromium.launch()
        sc  = await sb.new_context()
        target = NUM_USERS - len(SEEDED_USERS)
        for i in range(target):
            await register_new_user(sc.request)
            if (i + 1) % 10 == 0:
                print(f"  Registered {i+1}/{target}...")
            await asyncio.sleep(0.2)
        await sc.close()
        await sb.close()
        print(f"[SETUP] ✅ {len(SEEDED_USERS) + len(registered_users)} users ready\n")

        # ── Launch one persistent browser per worker slot ──
        print(f"[SETUP] Launching {MAX_CONCURRENT} persistent browser workers...")
        browsers = []
        contexts = []
        ctxs     = []
        for _ in range(MAX_CONCURRENT):
            bw = await playwright.chromium.launch()
            cx = await bw.new_context()
            browsers.append(bw)
            contexts.append(cx)
            ctxs.append(cx.request)
        print(f"[SETUP] ✅ Workers ready\n")

        # ── Build and shuffle all session tasks ──
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        async def run_user_task(sid, wid):
            async with semaphore:
                await run_session(sid, ctxs[wid % MAX_CONCURRENT])
                await tick_progress()

        async def run_admin_task(sid, wid):
            async with semaphore:
                await run_admin_session(sid, ctxs[wid % MAX_CONCURRENT])
                await tick_progress()

        all_tasks = (
            [run_user_task(i, i)                 for i in range(1, NUM_SESSIONS + 1)] +
            [run_admin_task(NUM_SESSIONS + i, i) for i in range(1, NUM_ADMIN_SESSIONS + 1)]
        )
        random.shuffle(all_tasks)
        await asyncio.gather(*all_tasks)

        # ── Cleanup ──
        for cx in contexts:
            await cx.close()
        for bw in browsers:
            await bw.close()

    print("\n" + "=" * 90)
    print(f"  ✅ Done! {total} sessions completed.")
    print(f"  CSV: {CSV_FILE}  |  Also logged to proxy_logs.db")
    print("=" * 90)


if __name__ == "__main__":
    asyncio.run(main())