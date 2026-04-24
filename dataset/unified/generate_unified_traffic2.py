"""
GATE80 — Unified Labeled Traffic Generator v2
dataset/unified/generate_unified_traffic.py

Generates labeled sessions with realistic behavioral noise to produce
meaningful ML classification metrics rather than trivially perfect ones.

Key design change from v1:
  Attack sessions now include probabilistic evasion behaviors that blend
  malicious patterns with legitimate-looking actions. Normal sessions
  include probabilistic noise that mimics real user mistakes and habits.
  This creates feature overlap forcing the model to learn probabilistic
  decision boundaries rather than perfect cuts.

Noise design grounded in:
  - Palo Alto Networks (2024): "Well-resourced attackers blend traffic into
    routine authentication flows — detection requires context, not just counts"
  - TCM Security (2025): "AI-driven attacks randomize timing and emulate
    human-like behavior patterns — fewer floods, more quiet infiltrations"
  - NIST SP 800-63B: Users regularly mistype passwords (grounds failed login
    noise in normal sessions)
  - Akamai Bot Manager: think_time CV distinguishes human (>0.5) from bot
    (<0.2) — noise targets this boundary

Normal session noise (probabilistic, not rule-based):
  12% chance: one failed login at start (forgot password — NIST SP 800-63B)
  8%  chance: rapid financial burst — 3-5 wallet ops in quick succession
              (power_user/transactor only — legitimate batch payments)
  10% chance: high endpoint diversity — 6-10 endpoints in one session
              (power users checking everything)
  Think time variance increased — CV 0.35-0.55 to reflect natural pacing

Attack session noise per type:
  brute_force:
    30% chance: browse 1-3 normal endpoints between attempt bursts
    Bimodal think time: 60% fast (50-200ms), 40% slow (800-2500ms)
    Occasional longer pause after every 5 attempts

  credential_stuffing:
    40% chance: 2-4 normal endpoint visits before starting attempts
    Variable inter-attempt timing clusters
    5% chance per attempt: fake "slow-down" pause of 2-5 seconds

  account_takeover:
    After login: 1-3 browsing actions before financial drain (profile,
    balance check) — mimics attacker assessing account before draining
    Mix lower-amount transactions — avoiding threshold detection
    30% chance: leave 10-30% of balance (realistic partial drain)
    Occasional human-paced pauses of 2-8 seconds

  scanning:
    60% probes / 40% legitimate requests mixed throughout
    Variable probe speed — not uniform timing

  financial_fraud:
    Start with 2-4 normal-paced actions (view balance first)
    Occasionally mix topups between withdrawals
    Variable think times — not always machine-speed

Session counts for test run (2,000 total):
  Normal  : 1,700 (1,615 user + 85 admin)
  Abnormal:   300 (90 BF + 75 CS + 60 ATO + 45 SC + 30 FF)

Run:
    python dataset/unified/generate_unified_traffic.py
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
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

NUM_REGISTER_USERS = 50    # PRODUCTION: 500
MAX_CONCURRENT     = 5     # PRODUCTION: 10

RUN_ID   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"dataset/unified/output/gate80_requests2_log_{RUN_ID}.csv"

SOURCE_TOOL = "playwright"
ADMIN_CREDS = {"username": "admin", "password": "admin123"}

# ── Session counts — TEST RUN (2,000 total) ───────────────────────────────────
# PRODUCTION: NORMAL_USER_SESSIONS=8075, NORMAL_ADMIN_SESSIONS=425,
#             brute_force=450, credential_stuffing=375, account_takeover=300,
#             scanning=225, financial_fraud=150
NORMAL_USER_SESSIONS  = 1615
NORMAL_ADMIN_SESSIONS =   85
ABNORMAL_COUNTS = {
    "brute_force":         90,
    "credential_stuffing": 75,
    "account_takeover":    60,
    "scanning":            45,
    "financial_fraud":     30,
}

SAUDI_CITIES = [
    "Jeddah","Riyadh","Mecca","Medina",
    "Dammam","Khobar","Tabuk","Abha","Taif","Buraidah"
]
CLIENT_TYPES = ["web","ios","android"]

fake = Faker()

# ─────────────────────────────────────────────────────────────────────────────
# PERSONAS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PersonaConfig:
    name: str
    think_min: float
    think_max: float
    actions_min: int
    actions_max: int
    w_health: int; w_hello: int; w_auth_me: int
    w_wallet_view: int; w_topup: int; w_withdraw: int
    w_transfer: int; w_pay_bill: int
    w_view_profile: int; w_update_profile: int
    w_payments: int; w_bank_accounts: int

PERSONAS: Dict[str, PersonaConfig] = {
    "casual": PersonaConfig(
        name="casual", think_min=3.0, think_max=14.0,
        actions_min=2, actions_max=6,
        w_health=5, w_hello=5, w_auth_me=20, w_wallet_view=20,
        w_topup=5, w_withdraw=5, w_transfer=5, w_pay_bill=5,
        w_view_profile=15, w_update_profile=5, w_payments=5, w_bank_accounts=5,
    ),
    "power_user": PersonaConfig(
        name="power_user", think_min=0.5, think_max=3.0,
        actions_min=7, actions_max=15,
        w_health=2, w_hello=2, w_auth_me=8, w_wallet_view=15,
        w_topup=15, w_withdraw=12, w_transfer=15, w_pay_bill=12,
        w_view_profile=8, w_update_profile=3, w_payments=5, w_bank_accounts=3,
    ),
    "confused": PersonaConfig(
        name="confused", think_min=8.0, think_max=30.0,
        actions_min=1, actions_max=3,
        w_health=10, w_hello=10, w_auth_me=30, w_wallet_view=10,
        w_topup=5, w_withdraw=5, w_transfer=5, w_pay_bill=5,
        w_view_profile=15, w_update_profile=0, w_payments=5, w_bank_accounts=0,
    ),
    "transactor": PersonaConfig(
        name="transactor", think_min=1.0, think_max=5.0,
        actions_min=4, actions_max=9,
        w_health=2, w_hello=2, w_auth_me=8, w_wallet_view=12,
        w_topup=12, w_withdraw=10, w_transfer=25, w_pay_bill=15,
        w_view_profile=5, w_update_profile=3, w_payments=4, w_bank_accounts=2,
    ),
}

PERSONA_NAMES   = list(PERSONAS.keys())
PERSONA_WEIGHTS = [40, 20, 10, 30]

ACTION_NAMES = [
    "health","hello","auth_me","wallet_view","topup","withdraw",
    "transfer","pay_bill","view_profile","update_profile","payments","bank_accounts",
]

MISTAKE_WEIGHTS = {
    "wrong_password":30,"overdraft":20,"double_submit":15,"transfer_to_self":10,
    "transfer_nonexistent":8,"wrong_email_format":6,"signout_no_token":5,
    "zero_negative_amount":4,"bad_data_format":2,
}
MISTAKE_TYPES  = list(MISTAKE_WEIGHTS.keys())
MISTAKE_VALUES = list(MISTAKE_WEIGHTS.values())
MISTAKE_SESSION_RATE = 0.08
PRE_LOGIN_MISTAKES  = {"wrong_password","wrong_email_format","signout_no_token"}
POST_LOGIN_MISTAKES = {
    "overdraft","double_submit","transfer_to_self",
    "transfer_nonexistent","zero_negative_amount","bad_data_format"
}

# ─────────────────────────────────────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────────────────────────────────────
CSV_COLUMNS = [
    "timestamp","session_id","persona","email","user_id",
    "action","method","path","status_code","is_failed_login",
    "response_time_ms","think_time_ms","body_size",
    "has_auth_token","endpoint_category","response_length",
    "geo_location","client_type","user_agent","source_tool",
    "label","session_type",
]

csv_lock = asyncio.Lock()


def init_csv():
    os.makedirs("dataset/unified/output", exist_ok=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(CSV_COLUMNS)


async def log_row(row: dict):
    async with csv_lock:
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([row.get(col,"") for col in CSV_COLUMNS])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def endpoint_category(path: str) -> str:
    if "/admin" in path: return "admin"
    if any(x in path for x in ["/auth/sign-in","/auth/sign-up",
                                "/auth/sign-out","/auth/me"]): return "auth"
    if "/wallet" in path: return "wallet"
    if "/bank-accounts" in path or "/payments" in path: return "account"
    if path.startswith("/users/"): return "account"
    if path in ["/health","/hello"]: return "system"
    return "other"


def make_row(session_id, persona, email, user_id, action,
             method, path, status_code, label=0, session_type="normal",
             is_failed_login=False, response_time_ms=0, think_time_ms=0,
             body_size=0, has_auth_token=False, response_length=0,
             geo_location="", client_type="web", user_agent="") -> dict:
    return {
        "timestamp": now_iso(), "session_id": session_id,
        "persona": persona, "email": email, "user_id": user_id,
        "action": action, "method": method, "path": path,
        "status_code": status_code, "is_failed_login": is_failed_login,
        "response_time_ms": response_time_ms, "think_time_ms": think_time_ms,
        "body_size": body_size, "has_auth_token": has_auth_token,
        "endpoint_category": endpoint_category(path),
        "response_length": response_length, "geo_location": geo_location,
        "client_type": client_type, "user_agent": user_agent,
        "source_tool": SOURCE_TOOL, "label": label, "session_type": session_type,
    }


def clog(sid, tag, action, status, rt_ms=None):
    ts = datetime.now().strftime("%H:%M:%S")
    rt = f"{rt_ms}ms" if rt_ms is not None else ""
    print(f"[{ts}] {sid[:8]} | {tag:<22} | {action:<48} | {status} {rt}")


# ─────────────────────────────────────────────────────────────────────────────
# USER POOL
# ─────────────────────────────────────────────────────────────────────────────
registered_users  = []
registration_lock = asyncio.Lock()
session_counter   = 0
counter_lock      = asyncio.Lock()
total_sessions    = NORMAL_USER_SESSIONS + NORMAL_ADMIN_SESSIONS + sum(ABNORMAL_COUNTS.values())


async def tick_progress():
    global session_counter
    async with counter_lock:
        session_counter += 1
        count = session_counter
    if count % 100 == 0 or count == total_sessions:
        pct = count / total_sessions * 100
        print(f"\n  Progress: {count}/{total_sessions} ({pct:.1f}%)\n")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────────────────────────────────────
async def api_post(ctx, path, payload=None, token=None, token_type="user",
                   client_type="web", user_agent="") -> Tuple:
    headers = {"Content-Type":"application/json","User-Agent":user_agent,
               "X-Client-Type":client_type}
    if token:
        headers["X-User-Token" if token_type=="user" else "X-Admin-Token"] = token
    body_str  = json.dumps(payload) if payload else ""
    body_size = len(body_str.encode("utf-8"))
    try:
        t = time.time()
        r = await ctx.post(f"{BASE_URL}{path}",
                           data=body_str if payload else None, headers=headers)
        rt_ms = int((time.time()-t)*1000)
        return r, rt_ms, body_size, len(await r.body())
    except Exception:
        return None, 0, body_size, 0


async def api_get(ctx, path, token=None, token_type="user",
                  client_type="web", user_agent="") -> Tuple:
    headers = {"User-Agent":user_agent,"X-Client-Type":client_type}
    if token:
        headers["X-User-Token" if token_type=="user" else "X-Admin-Token"] = token
    url = (f"{BASE_URL_ROOT}{path}" if path in ["/health","/hello"]
           else f"{BASE_URL}{path}")
    try:
        t = time.time()
        r = await ctx.get(url, headers=headers)
        rt_ms = int((time.time()-t)*1000)
        return r, rt_ms, len(await r.body())
    except Exception:
        return None, 0, 0


async def api_put(ctx, path, payload=None, token=None,
                  client_type="web", user_agent="") -> Tuple:
    headers = {"Content-Type":"application/json","User-Agent":user_agent,
               "X-Client-Type":client_type}
    if token:
        headers["X-User-Token"] = token
    body_str  = json.dumps(payload) if payload else ""
    body_size = len(body_str.encode("utf-8"))
    try:
        t = time.time()
        r = await ctx.put(f"{BASE_URL}{path}",
                          data=body_str if payload else None, headers=headers)
        rt_ms = int((time.time()-t)*1000)
        return r, rt_ms, body_size, len(await r.body())
    except Exception:
        return None, 0, body_size, 0


# ─────────────────────────────────────────────────────────────────────────────
# THINK TIME HELPERS
# ─────────────────────────────────────────────────────────────────────────────
async def think(persona: PersonaConfig) -> int:
    """
    Human think time with realistic variability.
    Uses triangular distribution skewed toward min to reflect
    purposeful users who know what they want but occasionally pause.
    CV target: 0.35-0.55 for natural human pacing.
    """
    # Occasionally add a longer pause (distraction, reading, etc.)
    if random.random() < 0.15:
        delay = random.uniform(persona.think_max, persona.think_max * 2.5)
    else:
        delay = random.triangular(persona.think_min, persona.think_max,
                                  persona.think_min + (persona.think_max - persona.think_min) * 0.3)
    await asyncio.sleep(delay)
    return int(delay * 1000)


async def think_ms(min_ms: float, max_ms: float) -> int:
    delay = random.uniform(min_ms/1000, max_ms/1000)
    await asyncio.sleep(delay)
    return int(delay * 1000)


async def think_bimodal(fast_min=50, fast_max=250,
                        slow_min=800, slow_max=2500,
                        fast_prob=0.65) -> int:
    """
    Bimodal think time distribution for evasive attackers.
    Most attempts are fast (automated), occasionally slows down
    to avoid rate limiting detection. Source: Palo Alto Networks (2024)
    — attackers blend login timing to mimic user interaction.
    """
    if random.random() < fast_prob:
        delay = random.uniform(fast_min/1000, fast_max/1000)
    else:
        delay = random.uniform(slow_min/1000, slow_max/1000)
    await asyncio.sleep(delay)
    return int(delay * 1000)


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRATION + WALLET FUNDING
# ─────────────────────────────────────────────────────────────────────────────
async def register_and_fund(ctx) -> Optional[dict]:
    email    = fake.unique.email()
    password = fake.password(length=random.randint(8,14), special_chars=False)
    city     = random.choice(SAUDI_CITIES)
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    payload = {
        "full_name": fake.name(), "email": email, "password": password,
        "phone": f"+9665{random.randint(10000000,99999999)}", "city": city,
    }
    r, _, _, _ = await api_post(ctx, "/auth/sign-up", payload,
                                client_type=ct, user_agent=ua)
    if not r or r.status != 201:
        print(f"[WARN] Registration failed: {r.status if r else 'NO RESPONSE'} for {email}")
        return None

    body    = await r.json()
    user_id = body.get("user_id")

    r2, _, _, _ = await api_post(ctx, "/auth/sign-in",
                                 {"email":email,"password":password},
                                 client_type=ct, user_agent=ua)
    if not r2 or r2.status != 200:
        print(f"[WARN] Sign-in after registration failed: {r2.status if r2 else 'NO RESPONSE'}")
        return None

    body2 = await r2.json()
    token = body2.get("token")

    fund_amount = round(random.triangular(500, 2000, 800), 2)
    await api_post(ctx, f"/users/{user_id}/wallet/topup",
                   {"amount": fund_amount}, token=token,
                   client_type=ct, user_agent=ua)
    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)

    user = {"email":email,"password":password,"user_id":user_id,
            "geo_location":city,"client_type":ct,"user_agent":ua}
    async with registration_lock:
        registered_users.append(user)
    return user


async def get_random_user() -> dict:
    async with registration_lock:
        pool = list(registered_users)
    if not pool:
        raise RuntimeError("User pool is empty")
    return dict(random.choice(pool))


# ─────────────────────────────────────────────────────────────────────────────
# MISTAKE HELPERS (normal sessions)
# ─────────────────────────────────────────────────────────────────────────────
def pick_mistake() -> str:
    return random.choices(MISTAKE_TYPES, weights=MISTAKE_VALUES, k=1)[0]


def typo_password(pwd: str) -> str:
    base  = pwd if len(pwd) >= 8 else pwd + "x"*(8-len(pwd))
    chars = list(base)
    mutation = random.choice(["swap","insert_digit","wrong_case","replace"])
    if mutation == "swap" and len(chars) >= 2:
        i = random.randint(0, len(chars)-2)
        chars[i], chars[i+1] = chars[i+1], chars[i]
    elif mutation == "insert_digit":
        chars.insert(random.randint(0,len(chars)), str(random.randint(0,9)))
    elif mutation == "wrong_case":
        chars[0] = chars[0].upper() if chars[0].islower() else chars[0].lower()
    elif mutation == "replace":
        idx = random.randint(0, len(chars)-1)
        chars[idx] = random.choice("abcdefghijklmnopqrstuvwxyz")
    result = "".join(chars)
    return result if len(result) >= 8 else result+"pad12345"


def wrong_email(email: str) -> str:
    mutation = random.choice(["remove_at","double_dot","truncate"])
    if mutation == "remove_at":   return email.replace("@","")
    elif mutation == "double_dot": return email.replace(".","..",1)
    return email[:max(3,len(email)-4)]


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


async def execute_action(ctx, action_name, sid, uid, token, email,
                         persona, geo, ct, ua, label, session_type) -> None:

    async def log(method, path, status, rt, r_len, body_size=0,
                  failed_login=False, has_token=True, tt=0):
        await log_row(make_row(
            sid, persona.name, email, uid, action_name,
            method, path, status, label=label, session_type=session_type,
            is_failed_login=failed_login, response_time_ms=rt, think_time_ms=tt,
            body_size=body_size, has_auth_token=has_token,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

    if action_name == "health":
        r, rt, r_len = await api_get(ctx, "/health", client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", "/health", r.status if r else "ERR", rt, r_len,
                  has_token=False, tt=tt)
    elif action_name == "hello":
        r, rt, r_len = await api_get(ctx, "/hello", client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", "/hello", r.status if r else "ERR", rt, r_len,
                  has_token=False, tt=tt)
    elif action_name == "auth_me":
        r, rt, r_len = await api_get(ctx, "/auth/me", token=token,
                                     client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", "/auth/me", r.status if r else "ERR", rt, r_len, tt=tt)
    elif action_name == "wallet_view":
        path = f"/users/{uid}/wallet"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", path, r.status if r else "ERR", rt, r_len, tt=tt)
    elif action_name == "topup":
        path   = f"/users/{uid}/wallet/topup"
        amount = round(random.uniform(10,500), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                          token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("POST", path, r.status if r else "ERR", rt, r_len,
                  body_size=bs, tt=tt)
    elif action_name == "withdraw":
        path   = f"/users/{uid}/wallet/withdraw"
        amount = round(random.uniform(5,100), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                          token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("POST", path, r.status if r else "ERR", rt, r_len,
                  body_size=bs, tt=tt)
    elif action_name == "transfer":
        async with registration_lock:
            targets = [u["user_id"] for u in registered_users if u.get("user_id")]
        if not targets:
            targets = ["u_1001","u_1002","u_1003"]
        target = random.choice([t for t in targets if t != uid] or targets)
        path   = f"/users/{uid}/wallet/transfer/{target}"
        amount = round(random.uniform(5,80), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                          token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("POST", path, r.status if r else "ERR", rt, r_len,
                  body_size=bs, tt=tt)
    elif action_name == "pay_bill":
        path   = f"/users/{uid}/wallet/pay-bill"
        amount = round(random.uniform(20,200), 2)
        r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                          token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("POST", path, r.status if r else "ERR", rt, r_len,
                  body_size=bs, tt=tt)
    elif action_name == "view_profile":
        path = f"/users/{uid}"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", path, r.status if r else "ERR", rt, r_len, tt=tt)
    elif action_name == "update_profile":
        path = f"/users/{uid}"
        r, rt, bs, r_len = await api_put(ctx, path,
                                         {"city":random.choice(SAUDI_CITIES)},
                                         token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("PUT", path, r.status if r else "ERR", rt, r_len,
                  body_size=bs, tt=tt)
    elif action_name == "payments":
        path = f"/users/{uid}/payments"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", path, r.status if r else "ERR", rt, r_len, tt=tt)
    elif action_name == "bank_accounts":
        path = f"/users/{uid}/bank-accounts"
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("GET", path, r.status if r else "ERR", rt, r_len, tt=tt)


# ─────────────────────────────────────────────────────────────────────────────
# MISTAKE INJECTION (normal sessions)
# ─────────────────────────────────────────────────────────────────────────────
async def inject_mistake(ctx, sid, uid, token, email, password,
                         persona, geo, ct, ua, mtype,
                         label=0, session_type="normal") -> None:

    async def log(action, method, path, status, rt, r_len,
                  body_size=0, failed_login=False, has_token=False, tt=0):
        await log_row(make_row(
            sid, persona.name, email, uid or "unknown", action,
            method, path, status, label=label, session_type=session_type,
            is_failed_login=failed_login, response_time_ms=rt, think_time_ms=tt,
            body_size=body_size, has_auth_token=has_token,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))

    if mtype == "wrong_password":
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email":email,"password":typo_password(password)},
            client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("failed_login","POST","/auth/sign-in",
                  r.status if r else "ERR", rt, r_len,
                  body_size=bs, failed_login=True, tt=tt)

    elif mtype == "overdraft" and uid and token:
        path = f"/users/{uid}/wallet/withdraw"
        r, rt, bs, r_len = await api_post(ctx, path, {"amount":999999},
                                          token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("withdraw_overdraft","POST",path,
                  r.status if r else "ERR", rt, r_len,
                  body_size=bs, has_token=True, tt=tt)

    elif mtype == "double_submit" and uid and token:
        path   = f"/users/{uid}/wallet/topup"
        amount = round(random.uniform(10,100), 2)
        for i in range(2):
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)
            action = "topup" if i == 0 else "topup_double_submit"
            await log(action,"POST",path,r.status if r else "ERR",rt,r_len,
                      body_size=bs, has_token=True)
            if i == 0:
                await asyncio.sleep(random.uniform(0, 0.5))
        await think(persona)

    elif mtype == "transfer_to_self" and uid and token:
        path = f"/users/{uid}/wallet/transfer/{uid}"
        r, rt, bs, r_len = await api_post(ctx, path, {"amount":50},
                                          token=token, client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("transfer_to_self","POST",path,
                  r.status if r else "ERR",rt,r_len,
                  body_size=bs, has_token=True, tt=tt)

    elif mtype == "wrong_email_format":
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email":wrong_email(email),"password":password},
            client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("failed_login_bad_email","POST","/auth/sign-in",
                  r.status if r else "ERR",rt,r_len,
                  body_size=bs, failed_login=True, tt=tt)

    elif mtype == "signout_no_token":
        r, rt, bs, r_len = await api_post(ctx, "/auth/sign-out",
                                          client_type=ct, user_agent=ua)
        tt = await think(persona)
        await log("signout_no_token","POST","/auth/sign-out",
                  r.status if r else "ERR",rt,r_len, body_size=bs, tt=tt)


# ─────────────────────────────────────────────────────────────────────────────
# QUICK ATTACKER BROWSE — legitimizing actions mixed into attack sessions
# Used by all attack types to blend in with normal traffic.
# Source: TCM Security (2025) — "AI attacks randomize timing and emulate
# human-like behavior to avoid detection"
# ─────────────────────────────────────────────────────────────────────────────
async def attacker_browse(ctx, sid, uid, token, email,
                          geo, ct, ua, session_type,
                          n_actions=None) -> None:
    """1-3 legitimate-looking requests mixed into attack session."""
    n = n_actions or random.randint(1, 3)
    browse_paths = [
        (f"/users/{uid}/wallet", "GET"),
        (f"/users/{uid}", "GET"),
        (f"/users/{uid}/payments", "GET"),
        ("/auth/me", "GET"),
    ]
    choices = random.sample(browse_paths, min(n, len(browse_paths)))
    for path, method in choices:
        r, rt, r_len = await api_get(ctx, path, token=token,
                                     client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think_ms(500, 2500)  # human-paced browsing
        await log_row(make_row(
            sid, "attacker", email, uid, "browse_cover",
            method, path, status, label=1, session_type=session_type,
            response_time_ms=rt, think_time_ms=tt,
            has_auth_token=True, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))


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

    # ── NOISE: 12% chance of failed login at start (forgot password)
    # Grounded in NIST SP 800-63B — users regularly mistype credentials.
    # Creates failed_login_count=1 overlap with low-count attack signals.
    if random.random() < 0.12:
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email": email, "password": typo_password(password)},
            client_type=ct, user_agent=ua)
        await log_row(make_row(
            sid, persona_name, email, "unknown", "failed_login",
            "POST", "/auth/sign-in", r.status if r else "ERR",
            label=0, session_type="normal",
            is_failed_login=True, response_time_ms=rt, body_size=bs,
            response_length=r_len, geo_location=geo,
            client_type=ct, user_agent=ua,
        ))
        await asyncio.sleep(random.uniform(1.5, 4.0))  # pause after failed login

    mistake = pick_mistake() if random.random() < MISTAKE_SESSION_RATE else None
    if mistake in PRE_LOGIN_MISTAKES:
        await inject_mistake(ctx, sid, None, None, email, password,
                             persona, geo, ct, ua, mistake)
        mistake = None

    r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in",
                                      {"email":email,"password":password},
                                      client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        await log_row(make_row(sid, persona_name, email, "unknown", "sign_in",
                               "POST", "/auth/sign-in", r.status if r else "ERR",
                               label=0, session_type="normal",
                               response_time_ms=rt, body_size=bs,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")
    tt      = await think(persona)

    await log_row(make_row(sid, persona_name, email, user_id, "sign_in",
                           "POST", "/auth/sign-in", 200, label=0, session_type="normal",
                           response_time_ms=rt, think_time_ms=tt, body_size=bs,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))

    if mistake in POST_LOGIN_MISTAKES:
        await inject_mistake(ctx, sid, user_id, token, email, password,
                             persona, geo, ct, ua, mistake)

    n_actions = random.randint(persona.actions_min, persona.actions_max)

    # ── NOISE: 8% chance of rapid financial burst for transactor/power_user
    # Reflects legitimate batch payments — users paying multiple bills at once.
    # Creates high wallet_action_ratio overlap with fraud sessions.
    if persona_name in ("transactor","power_user") and random.random() < 0.08:
        burst_ops = ["topup","transfer","pay_bill","withdraw"]
        n_burst   = random.randint(3, 5)
        for _ in range(n_burst):
            action = random.choice(burst_ops)
            await execute_action(ctx, action, sid, user_id, token, email,
                                 persona, geo, ct, ua, label=0, session_type="normal")
            # Short delay within burst — human doing multiple things quickly
            await asyncio.sleep(random.uniform(0.2, 1.0))

    # ── NOISE: 10% chance of high endpoint diversity in one session
    # Power users checking balance, profile, payments, bank accounts all at once.
    # Creates unique_endpoints overlap with scanning sessions.
    if random.random() < 0.10:
        diversity_actions = ["wallet_view","view_profile","payments",
                             "bank_accounts","auth_me"]
        random.shuffle(diversity_actions)
        for act in diversity_actions[:random.randint(3,5)]:
            await execute_action(ctx, act, sid, user_id, token, email,
                                 persona, geo, ct, ua, label=0, session_type="normal")

    # Normal action loop
    for _ in range(n_actions):
        await execute_action(ctx, pick_action(persona), sid, user_id,
                             token, email, persona, geo, ct, ua,
                             label=0, session_type="normal")

    r, rt, _, r_len = await api_post(ctx, "/auth/sign-out", token=token,
                                     client_type=ct, user_agent=ua)
    await log_row(make_row(sid, persona_name, email, user_id, "sign_out",
                           "POST", "/auth/sign-out", r.status if r else "ERR",
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
    tt          = int(random.uniform(600, 2500))
    await asyncio.sleep(tt/1000)

    await log_row(make_row(sid, "admin", "admin", "admin_1", "admin_sign_in",
                           "POST", "/admin/auth/sign-in", 200, label=0, session_type="normal",
                           response_time_ms=rt, think_time_ms=tt, body_size=bs,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))

    session_length = random.choices([5,10,20,35], weights=[30,30,25,15], k=1)[0]
    admin_paths    = ["/admin/users","/admin/wallets",
                      "/admin/transactions","/admin/overview/financial"]
    admin_weights  = [30,25,25,20]

    for _ in range(session_length):
        path = random.choices(admin_paths, weights=admin_weights, k=1)[0]
        r, rt, r_len = await api_get(ctx, path, token=admin_token,
                                     token_type="admin", client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"
        tt = int(random.triangular(400, 3000, 800))
        await asyncio.sleep(tt/1000)
        action = f"admin_{path.split('/')[-1]}"
        await log_row(make_row(sid, "admin", "admin", "admin_1", action,
                               "GET", path, status, label=0, session_type="normal",
                               response_time_ms=rt, think_time_ms=tt, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

    r, rt, _, r_len = await api_post(ctx, "/admin/auth/sign-out",
                                     token=admin_token, token_type="admin",
                                     client_type=ct, user_agent=ua)
    await log_row(make_row(sid, "admin", "admin", "admin_1", "admin_sign_out",
                           "POST", "/admin/auth/sign-out", r.status if r else "ERR",
                           label=0, session_type="normal",
                           response_time_ms=rt, has_auth_token=True,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))


# ── ATTACK: BRUTE FORCE ───────────────────────────────────────────────────────
# Source: OWASP API2:2023 + Palo Alto (2024) — attackers increasingly blend
# login timing to mimic user interaction. Detection requires context not volume.
#
# Noise added:
#   30% chance: browse 1-3 normal endpoints between attempt bursts
#   Bimodal think time: 65% fast (50-250ms), 35% slow (800-2500ms)
#   Longer pause after every 5 attempts (evading rate limiting)
async def run_brute_force(ctx) -> None:
    sid   = str(uuid.uuid4())
    user  = await get_random_user()
    email = user["email"]
    geo   = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct    = random.choice(CLIENT_TYPES)
    ua    = fake.user_agent()

    n_attempts = random.randint(10, 30)
    clog(sid, "BRUTE_FORCE", f"hammering {email} x{n_attempts}", "→")

    # 30% chance: do some normal browsing BEFORE starting
    # Attacker appears to be a normal user at session start
    pre_browse = random.random() < 0.30

    # Need a token for pre-browse — attempt login with correct creds first
    # then fail subsequent ones (mimics attacker who got partial access)
    token = None
    user_id = None
    if pre_browse:
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email": email, "password": user["password"]},
            client_type=ct, user_agent=ua)
        if r and r.status == 200:
            body    = await r.json()
            token   = body.get("token")
            user_id = body.get("user_id")
            await log_row(make_row(
                sid, "attacker", email, user_id, "sign_in",
                "POST", "/auth/sign-in", 200,
                label=1, session_type="brute_force",
                response_time_ms=rt, body_size=bs, response_length=r_len,
                geo_location=geo, client_type=ct, user_agent=ua,
            ))
            # Browse 1-2 endpoints looking normal
            await attacker_browse(ctx, sid, user_id, token, email,
                                  geo, ct, ua, "brute_force",
                                  n_actions=random.randint(1,2))
            # Sign out — then begin brute force as if session expired/new attacker
            await api_post(ctx, "/auth/sign-out", token=token,
                           client_type=ct, user_agent=ua)
            token = None

    for i in range(n_attempts):
        bad_password = typo_password(
            fake.password(length=random.randint(8,14), special_chars=False)
        )
        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email":email,"password":bad_password},
            client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"

        # Bimodal think time — mostly fast with occasional slow
        tt = await think_bimodal(fast_min=50, fast_max=250,
                                 slow_min=800, slow_max=2500, fast_prob=0.65)

        await log_row(make_row(
            sid, "attacker", email, "unknown", "failed_login",
            "POST", "/auth/sign-in", status,
            label=1, session_type="brute_force",
            is_failed_login=True, response_time_ms=rt, think_time_ms=tt,
            body_size=bs, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))

        # Every 5 attempts: longer strategic pause to avoid rate limiting
        if (i+1) % 5 == 0 and i < n_attempts-1:
            await asyncio.sleep(random.uniform(2.0, 5.0))

        if i % 5 == 0:
            clog(sid, "BRUTE_FORCE", f"attempt {i+1}/{n_attempts}", status, rt)


# ── ATTACK: CREDENTIAL STUFFING ───────────────────────────────────────────────
# Source: OWASP API2:2023 + Akamai 2023 + TCM Security (2025)
# Modern stuffing mimics human behavior with randomized timing.
#
# Noise added:
#   40% chance: 2-4 normal endpoint visits before starting attempts
#   Variable timing with occasional slow-downs
#   5% per attempt: strategic pause of 2-5 seconds
async def run_credential_stuffing(ctx) -> None:
    sid = str(uuid.uuid4())
    geo = random.choice(SAUDI_CITIES)
    ct  = random.choice(CLIENT_TYPES)
    ua  = fake.user_agent()

    n_attempts = random.randint(15, 40)
    clog(sid, "CRED_STUFFING", f"trying {n_attempts} credential pairs", "→")

    # 40% chance: visit public endpoints first to appear as normal traffic
    # Attacker profiling the API before attacking
    if random.random() < 0.40:
        pub_paths = ["/health", "/hello"]
        for path in random.sample(pub_paths, random.randint(1,2)):
            r, rt, r_len = await api_get(ctx, path, client_type=ct, user_agent=ua)
            tt = await think_ms(800, 3000)
            await log_row(make_row(
                sid, "attacker", "unknown", "unknown", "recon_browse",
                "GET", path, r.status if r else "ERR",
                label=1, session_type="credential_stuffing",
                response_time_ms=rt, think_time_ms=tt,
                response_length=r_len, geo_location=geo,
                client_type=ct, user_agent=ua,
            ))

    for i in range(n_attempts):
        fake_email    = fake.unique.email()
        fake_password = fake.password(length=random.randint(8,14), special_chars=False)

        r, rt, bs, r_len = await api_post(
            ctx, "/auth/sign-in",
            {"email":fake_email,"password":fake_password},
            client_type=ct, user_agent=ua)
        status = r.status if r else "ERR"

        # Variable timing — clusters of fast attempts with occasional slow-down
        tt = await think_bimodal(fast_min=30, fast_max=200,
                                 slow_min=1000, slow_max=4000, fast_prob=0.70)

        await log_row(make_row(
            sid, "attacker", fake_email, "unknown", "credential_stuffing",
            "POST", "/auth/sign-in", status,
            label=1, session_type="credential_stuffing",
            is_failed_login=True, response_time_ms=rt, think_time_ms=tt,
            body_size=bs, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))

        # 5% chance: strategic pause to evade rate detection
        if random.random() < 0.05:
            await asyncio.sleep(random.uniform(2.0, 5.0))

        if i % 8 == 0:
            clog(sid, "CRED_STUFFING", f"attempt {i+1}/{n_attempts}", status, rt)


# ── ATTACK: ACCOUNT TAKEOVER ─────────────────────────────────────────────────
# Source: Imperva 2024 + 2026 threat report — attackers operate within
# legitimate channels, blending malicious activity with authorized operations.
#
# Noise added:
#   1-3 normal browsing actions after login before financial drain
#   Mix lower-amount transactions to avoid threshold detection
#   30% chance: partial drain (leave 10-30% balance)
#   Human-paced pauses of 2-8 seconds between some operations
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
        {"email":email,"password":password},
        client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")

    await log_row(make_row(
        sid, "attacker", email, user_id, "sign_in_ato",
        "POST", "/auth/sign-in", 200, label=1, session_type="account_takeover",
        response_time_ms=rt, body_size=bs, response_length=r_len,
        geo_location=geo, client_type=ct, user_agent=ua,
    ))

    # NOISE: 1-3 legitimate browsing actions after login
    # Attacker assessing account before draining — appears as normal user
    n_cover = random.randint(1, 3)
    await attacker_browse(ctx, sid, user_id, token, email,
                          geo, ct, ua, "account_takeover", n_actions=n_cover)

    async with registration_lock:
        targets = [u["user_id"] for u in registered_users
                   if u.get("user_id") and u["user_id"] != user_id]
    if not targets:
        targets = ["u_1001","u_1002","u_1003"]

    n_ops = random.randint(8, 15)
    # 30% chance: partial drain — leave some balance (realistic attacker behavior)
    partial_drain = random.random() < 0.30
    ops_to_do = n_ops if not partial_drain else random.randint(3, n_ops-2)

    for i in range(ops_to_do):
        action = random.choices(["withdraw","transfer","pay_bill"],
                                weights=[40,40,20], k=1)[0]

        # Mix amount sizes — smaller amounts blend with normal transactions
        if random.random() < 0.3:
            amount = round(random.uniform(10, 80), 2)   # small, normal-looking
        else:
            amount = round(random.uniform(80, 300), 2)  # larger drain amounts

        if action == "withdraw":
            path = f"/users/{user_id}/wallet/withdraw"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)
        elif action == "transfer":
            target = random.choice(targets)
            path   = f"/users/{user_id}/wallet/transfer/{target}"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)
        else:
            path = f"/users/{user_id}/wallet/pay-bill"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)

        status = r.status if r else "ERR"

        # Occasional human-paced pause between operations
        if random.random() < 0.20:
            tt = await think_ms(2000, 8000)
        else:
            tt = await think_ms(80, 400)

        await log_row(make_row(
            sid, "attacker", email, user_id, f"{action}_ato",
            "POST", path, status, label=1, session_type="account_takeover",
            response_time_ms=rt, think_time_ms=tt, body_size=bs,
            has_auth_token=True, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))

        if i % 4 == 0:
            clog(sid, "ACCOUNT_TAKEOVER", f"{action} attempt {i+1}", status, rt)

    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)


# ── ATTACK: ENDPOINT SCANNING ─────────────────────────────────────────────────
# Source: OWASP API7:2023 + Salt Security 2023
#
# Noise added:
#   60% probes / 40% legitimate requests mixed throughout session
#   Variable probe speed — not uniform timing
async def run_scanning(ctx) -> None:
    sid  = str(uuid.uuid4())
    user = await get_random_user()
    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    clog(sid, "SCANNING", "probing API surface", "→")

    r, rt, bs, r_len = await api_post(
        ctx, "/auth/sign-in",
        {"email":email,"password":password},
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
        response_time_ms=rt, body_size=bs, response_length=r_len,
        geo_location=geo, client_type=ct, user_agent=ua,
    ))

    probe_targets = [
        ("/admin/users","GET",False),("/admin/wallets","GET",False),
        ("/admin/transactions","GET",False),("/admin/overview/financial","GET",False),
        ("/config","GET",False),("/api/v1/config","GET",False),
        ("/system/metrics","GET",False),("/admin/keys","GET",False),
        ("/admin/logs","GET",False),("/admin/export","GET",False),
        ("/debug/users","GET",False),("/.env","GET",False),("/backup","GET",False),
        ("/users/u_1001/wallet","GET",True),
        ("/users/u_1002/wallet","GET",True),
        ("/users/u_1003/wallet","GET",True),
    ]
    if user_id:
        probe_targets += [
            (f"/users/{user_id}/wallet","GET",True),
            (f"/users/{user_id}/payments","GET",True),
            (f"/users/{user_id}/bank-accounts","GET",True),
            ("/auth/me","GET",True),
        ]

    # Legitimate actions to mix in (40% of requests)
    legit_paths = [
        (f"/users/{user_id}/wallet","GET"),
        (f"/users/{user_id}","GET"),
        ("/auth/me","GET"),
    ] if user_id else []

    random.shuffle(probe_targets)
    n_probes = random.randint(12, len(probe_targets))
    probes   = probe_targets[:n_probes]

    for i, (path, method, use_token) in enumerate(probes):
        # NOISE: 40% chance insert a legitimate request before this probe
        if legit_paths and random.random() < 0.40:
            lpath, lmethod = random.choice(legit_paths)
            r, rt, r_len = await api_get(ctx, lpath, token=token,
                                         client_type=ct, user_agent=ua)
            tt = await think_ms(300, 1500)
            await log_row(make_row(
                sid, "attacker", email, user_id or "unknown", "legit_cover",
                lmethod, lpath, r.status if r else "ERR",
                label=1, session_type="scanning",
                response_time_ms=rt, think_time_ms=tt, has_auth_token=bool(token),
                response_length=r_len, geo_location=geo,
                client_type=ct, user_agent=ua,
            ))

        use_tok = token if use_token else None
        r, rt, r_len = await api_get(ctx, path, token=use_tok,
                                     client_type=ct, user_agent=ua)
        bs = 0
        status = r.status if r else "ERR"

        # Variable probe speed — not uniform
        tt = await think_bimodal(fast_min=80, fast_max=300,
                                 slow_min=500, slow_max=2000, fast_prob=0.60)

        await log_row(make_row(
            sid, "attacker", email, user_id or "unknown", "probe",
            method, path, status, label=1, session_type="scanning",
            response_time_ms=rt, think_time_ms=tt, body_size=bs,
            has_auth_token=bool(use_tok), response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
        ))

        if i % 5 == 0:
            clog(sid, "SCANNING", f"probe {i+1}/{n_probes} {path}", status, rt)

    if token:
        await api_post(ctx, "/auth/sign-out", token=token,
                       client_type=ct, user_agent=ua)


# ── ATTACK: FINANCIAL FRAUD ───────────────────────────────────────────────────
# Source: Traceable 2023 + Imperva 2024
# Modern fraud blends rapid operations with occasional human-paced pauses.
#
# Noise added:
#   2-4 normal-paced actions at session start (view balance first)
#   Occasionally mix topups between withdrawals
#   Variable think times — not always machine-speed
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
        {"email":email,"password":password},
        client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")

    await log_row(make_row(
        sid, "attacker", email, user_id, "sign_in_fraud",
        "POST", "/auth/sign-in", 200, label=1, session_type="financial_fraud",
        response_time_ms=rt, body_size=bs, response_length=r_len,
        geo_location=geo, client_type=ct, user_agent=ua,
    ))

    # NOISE: 2-4 normal-paced actions first (view balance, check profile)
    # Fraudster assessing available funds before starting rapid operations
    n_cover = random.randint(2, 4)
    await attacker_browse(ctx, sid, user_id, token, email,
                          geo, ct, ua, "financial_fraud", n_actions=n_cover)

    async with registration_lock:
        targets = [u["user_id"] for u in registered_users
                   if u.get("user_id") and u["user_id"] != user_id]
    if not targets:
        targets = ["u_1001","u_1002","u_1003"]

    n_ops = random.randint(10, 20)

    for i in range(n_ops):
        action = random.choices(
            ["topup","transfer","withdraw","pay_bill"],
            weights=[20,40,25,15], k=1
        )[0]
        amount = round(random.uniform(10,150), 2)

        if action == "topup":
            path = f"/users/{user_id}/wallet/topup"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)
        elif action == "transfer":
            target = random.choice(targets)
            path   = f"/users/{user_id}/wallet/transfer/{target}"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)
        elif action == "withdraw":
            path = f"/users/{user_id}/wallet/withdraw"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)
        else:
            path = f"/users/{user_id}/wallet/pay-bill"
            r, rt, bs, r_len = await api_post(ctx, path, {"amount":amount},
                                              token=token, client_type=ct, user_agent=ua)

        status = r.status if r else "ERR"

        # Variable think times — mostly fast but occasionally human-paced
        # to evade simple rate-based detection
        if random.random() < 0.15:
            tt = await think_ms(800, 3000)   # occasional human pause
        else:
            tt = await think_ms(30, 200)     # fast automated pace

        await log_row(make_row(
            sid, "attacker", email, user_id, f"{action}_fraud",
            "POST", path, status, label=1, session_type="financial_fraud",
            response_time_ms=rt, think_time_ms=tt, body_size=bs,
            has_auth_token=True, response_length=r_len,
            geo_location=geo, client_type=ct, user_agent=ua,
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

    print("="*90)
    print("  GATE80 Unified Labeled Traffic Generator v2 — Realistic Behavioral Noise")
    print(f"  Normal     : {NORMAL_USER_SESSIONS} user + {NORMAL_ADMIN_SESSIONS} admin = {NORMAL_USER_SESSIONS+NORMAL_ADMIN_SESSIONS}")
    print(f"  Abnormal   : {sum(ABNORMAL_COUNTS.values())} sessions across {len(ABNORMAL_COUNTS)} attack types")
    for atype, count in ABNORMAL_COUNTS.items():
        print(f"               {atype:<25} {count} sessions")
    print(f"  Total      : {total_sessions}")
    print(f"  Output     : {CSV_FILE}")
    print("="*90)

    async with async_playwright() as playwright:

        print(f"\n[SETUP] Registering and funding {NUM_REGISTER_USERS} users...")
        sb = await playwright.chromium.launch()
        sc = await sb.new_context()
        for i in range(NUM_REGISTER_USERS):
            await register_and_fund(sc.request)
            if (i+1) % 20 == 0:
                print(f"  {i+1}/{NUM_REGISTER_USERS} registered...")
            await asyncio.sleep(0.2)
        await sc.close()
        await sb.close()

        if not registered_users:
            print("[ERROR] No users registered. Check proxy is running.")
            return
        print(f"[SETUP] ✅ {len(registered_users)} users ready\n")

        browsers, contexts, ctxs = [], [], []
        for _ in range(MAX_CONCURRENT):
            bw = await playwright.chromium.launch()
            cx = await bw.new_context()
            browsers.append(bw)
            contexts.append(cx)
            ctxs.append(cx.request)

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        def make_task(coro_fn, worker_idx):
            async def _task():
                async with semaphore:
                    await coro_fn(ctxs[worker_idx % MAX_CONCURRENT])
                    await tick_progress()
            return _task()

        all_tasks = []

        for i in range(NORMAL_USER_SESSIONS):
            all_tasks.append(make_task(run_normal_user_session, i))
        for i in range(NORMAL_ADMIN_SESSIONS):
            all_tasks.append(make_task(run_normal_admin_session, i))

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

        random.shuffle(all_tasks)

        print(f"[RUN] Generating {len(all_tasks)} sessions...\n")
        await asyncio.gather(*all_tasks)

        for cx in contexts:
            await cx.close()
        for bw in browsers:
            await bw.close()

    print("\n"+"="*90)
    print(f"  ✅ Done! {total_sessions} sessions generated.")
    print(f"  CSV     : {CSV_FILE}")
    print(f"  Columns : 22 (including label + session_type)")
    print(f"\n  Label distribution:")
    print(f"    label=0 (normal)   : {NORMAL_USER_SESSIONS+NORMAL_ADMIN_SESSIONS}")
    print(f"    label=1 (abnormal) : {sum(ABNORMAL_COUNTS.values())}")
    print("="*90)


if __name__ == "__main__":
    asyncio.run(main())