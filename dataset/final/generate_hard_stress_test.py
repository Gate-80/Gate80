"""
GATE80 — Hard Stress Test Generator
dataset/final/generate_hard_stress_test.py

Generates a rigorous held-out test set with multi-dimensional feature
overlap designed to stress-test model generalization beyond timing alone.

Unlike the standard stress test (timing overlap only), this generator
creates sessions where MULTIPLE features simultaneously overlap with
normal — forcing the model to use joint feature distributions rather
than any single discriminating feature.

Attack overlap design:

  Credential attack — low failed_login_ratio variant (30% of sessions)
    Attacker succeeds after 2–3 attempts then browses normally.
    failed_login_ratio drops to 0.10–0.25, overlapping confused normal users.
    Source: Alsaleh et al. TDSC 2012, p. 128 — ATT threshold for known
    machine is 30 failures; attacker who knows account stops early after
    success. DOI: 10.1109/TDSC.2011.24

  Financial fraud — low velocity variant (40% of sessions)
    Fraudster makes only 2–4 financial operations spread over 20+ minutes.
    wallet_action_ratio drops to 0.15–0.30, overlapping power_user normal.
    Source: Mubarok et al. IEEE ICIC 2025 — attackers deliberately stay
    below transaction velocity thresholds to evade rule-based detection.

  Endpoint scanning — distributed variant (40% of sessions)
    Scanner hits only 3–5 endpoints per session with normal timing.
    unique_endpoints and admin_action_count both in normal range.
    Source: OWASP ATH v1.3 OAT-018 — systematic enumeration can be
    distributed across multiple short sessions.

  Account creation — slow variant (50% of sessions)
    Only 1–2 registrations per session with human timing between them.
    total_requests and requests_per_minute both in normal range.
    Source: Cola et al. IEEE Access 2023 — 24.5% of fake accounts created
    slowly over days to avoid burst detection.
    DOI: 10.1109/ACCESS.2023.3282580

  Normal sessions — elevated suspicion variants (20% of sessions)
    Power users with high request rate + occasional login mistakes.
    Confused users with elevated wallet_action_ratio from repeated attempts.
    Source: Balla et al. ICT 2011; NIST SP 800-63B §5.2.3

Session composition: 100 sessions (87 normal, 13 abnormal)
  Same ratios as training — only behavioral overlap increases.

Run:
    GATE80_DETECTION_DISABLED=1 uvicorn proxy.main:app --reload --port 8080
    python3 -m dataset.final.generate_hard_stress_test
"""

from __future__ import annotations

import asyncio
import csv
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from faker import Faker
from playwright.async_api import async_playwright

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
BASE_URL      = "http://127.0.0.1:8080/api/v1"
BASE_URL_ROOT = "http://127.0.0.1:8080"
MAX_CONCURRENT = 10

RUN_ID   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"dataset/final/output/hard_stress_test_{RUN_ID}.csv"

# ── Session counts ─────────────────────────────────────────────────────────
N_NORMAL     = 87
N_CREDENTIAL = 5
N_FRAUD      = 4
N_SCANNING   = 3
N_ACCOUNT    = 1
TOTAL        = N_NORMAL + N_CREDENTIAL + N_FRAUD + N_SCANNING + N_ACCOUNT

N_NORMAL_USERS = 20
N_ATTACK_USERS = 13

# ── Multi-dimensional overlap rates ───────────────────────────────────────
# Fraction of each attack type that uses a low-signal variant
# designed to overlap with normal sessions on multiple features
CRED_LOW_RATIO_RATE   = 0.30  # succeed early → low failed_login_ratio
FRAUD_LOW_VELOCITY    = 0.40  # few slow ops → low wallet_action_ratio
SCAN_DISTRIBUTED      = 0.40  # few endpoints → low unique_endpoints
ACCOUNT_SLOW          = 0.50  # 1–2 regs → low total_requests
NORMAL_SUSPICIOUS     = 0.20  # elevated metrics in normal sessions

SAUDI_CITIES = [
    "Jeddah", "Riyadh", "Mecca", "Medina", "Dammam",
    "Khobar", "Tabuk", "Abha", "Taif", "Buraidah",
]
INTERNATIONAL_CITIES = [
    "London", "Dubai", "Cairo", "New York", "Kuala Lumpur", "Istanbul",
]
CLIENT_TYPES = ["web", "ios", "android"]

fake = Faker()

# ─────────────────────────────────────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────────────────────────────────────
CSV_COLUMNS = [
    "timestamp", "session_id", "user_id", "email",
    "geo_location", "client_type", "method", "path",
    "status_code", "response_time_ms", "think_time_ms",
    "label", "attack_type",
]

csv_lock = asyncio.Lock()


def init_csv():
    Path("dataset/final/output").mkdir(parents=True, exist_ok=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(CSV_COLUMNS)


async def log_req(
    session_id, user_id, email, geo, client_type,
    method, path, status_code,
    response_time_ms, think_time_ms,
    label, attack_type,
) -> None:
    async with csv_lock:
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                datetime.now(timezone.utc).isoformat(),
                session_id, user_id, email, geo, client_type,
                method, path, status_code,
                response_time_ms, think_time_ms,
                label, attack_type,
            ])


# ─────────────────────────────────────────────────────────────────────────────
# Geography
# ─────────────────────────────────────────────────────────────────────────────
def pick_geo() -> str:
    return (
        random.choice(SAUDI_CITIES)
        if random.random() < 0.90
        else random.choice(INTERNATIONAL_CITIES)
    )


def pick_client() -> str:
    return random.choice(CLIENT_TYPES)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────
async def api_post(ctx, path, payload=None, token=None,
                   token_type="user", client_type="web") -> Tuple:
    headers = {"Content-Type": "application/json",
               "X-Client-Type": client_type}
    if token:
        headers["X-User-Token" if token_type == "user"
                else "X-Admin-Token"] = token
    body_str = json.dumps(payload) if payload else ""
    try:
        t = time.time()
        r = await ctx.post(
            f"{BASE_URL}{path}",
            data=body_str if payload else None,
            headers=headers,
        )
        return r, int((time.time() - t) * 1000)
    except Exception:
        return None, 0


async def api_get(ctx, path, token=None,
                  token_type="user", client_type="web") -> Tuple:
    headers = {"X-Client-Type": client_type}
    if token:
        headers["X-User-Token" if token_type == "user"
                else "X-Admin-Token"] = token
    url = (f"{BASE_URL_ROOT}{path}"
           if path in ["/health", "/hello"]
           else f"{BASE_URL}{path}")
    try:
        t = time.time()
        r = await ctx.get(url, headers=headers)
        return r, int((time.time() - t) * 1000)
    except Exception:
        return None, 0


async def api_put(ctx, path, payload=None,
                  token=None, client_type="web") -> Tuple:
    headers = {"Content-Type": "application/json",
               "X-Client-Type": client_type}
    if token:
        headers["X-User-Token"] = token
    body_str = json.dumps(payload) if payload else ""
    try:
        t = time.time()
        r = await ctx.put(
            f"{BASE_URL}{path}",
            data=body_str if payload else None,
            headers=headers,
        )
        return r, int((time.time() - t) * 1000)
    except Exception:
        return None, 0


# ─────────────────────────────────────────────────────────────────────────────
# Think time helpers
# ─────────────────────────────────────────────────────────────────────────────
async def think_human_bimodal() -> int:
    """
    Bimodal human think time.
    Source: Oikonomou & Mirkovic ICC 2009, Fig. 1
    DOI: 10.1109/ICC.2009.5199191
    """
    ms = (
        random.uniform(1_000, 12_000)
        if random.random() < 0.60
        else random.uniform(15_000, 60_100)
    )
    await asyncio.sleep(ms / 1000)
    return int(ms)


async def think_bot() -> int:
    """
    Bot timing: 17–100 ms
    Source: Oikonomou & Mirkovic ICC 2009, p. 3
    """
    ms = random.uniform(17, 100)
    await asyncio.sleep(ms / 1000)
    return int(ms)


async def think_ms(min_ms: float, max_ms: float) -> int:
    ms = random.uniform(min_ms, max_ms)
    await asyncio.sleep(ms / 1000)
    return int(ms)


# ─────────────────────────────────────────────────────────────────────────────
# Personas
# ─────────────────────────────────────────────────────────────────────────────
PERSONAS = {
    "casual": {
        "actions_min": 2, "actions_max": 6,
        "weights": {
            "wallet_view": 20, "topup": 5, "withdraw": 5,
            "transfer": 5, "pay_bill": 5, "view_profile": 15,
            "update_profile": 5, "payments": 5,
            "bank_accounts": 5, "auth_me": 20,
        },
    },
    "power_user": {
        "actions_min": 7, "actions_max": 15,
        "weights": {
            "wallet_view": 15, "topup": 15, "withdraw": 12,
            "transfer": 15, "pay_bill": 12, "view_profile": 8,
            "update_profile": 3, "payments": 5,
            "bank_accounts": 3, "auth_me": 8,
        },
    },
    "confused": {
        "actions_min": 1, "actions_max": 3,
        "weights": {
            "wallet_view": 10, "topup": 5, "withdraw": 5,
            "transfer": 5, "pay_bill": 5, "view_profile": 15,
            "update_profile": 0, "payments": 5,
            "bank_accounts": 0, "auth_me": 30,
        },
    },
    "transactor": {
        "actions_min": 4, "actions_max": 9,
        "weights": {
            "wallet_view": 12, "topup": 12, "withdraw": 10,
            "transfer": 25, "pay_bill": 15, "view_profile": 5,
            "update_profile": 3, "payments": 4,
            "bank_accounts": 2, "auth_me": 8,
        },
    },
}

PERSONA_NAMES   = list(PERSONAS.keys())
PERSONA_WEIGHTS = [40, 20, 10, 30]


def pick_persona() -> dict:
    return PERSONAS[
        random.choices(PERSONA_NAMES, weights=PERSONA_WEIGHTS, k=1)[0]
    ]


def pick_action(persona: dict) -> str:
    w = persona["weights"]
    return random.choices(list(w.keys()), weights=list(w.values()), k=1)[0]


# ─────────────────────────────────────────────────────────────────────────────
# User pools
# ─────────────────────────────────────────────────────────────────────────────
normal_pool: List[dict] = []
attack_pool: List[dict] = []
pool_lock = asyncio.Lock()


async def register_and_fund(ctx, pool: List[dict]) -> Optional[dict]:
    """
    Wallet funding: triangular(200, 3000, 800) SAR
    [CALIBRATED] — see docs/references.md §gaps
    """
    email    = fake.unique.email()
    password = fake.password(length=random.randint(8, 14), special_chars=False)
    city     = pick_geo()
    ct       = pick_client()

    r, _ = await api_post(ctx, "/auth/sign-up", {
        "full_name": fake.name(),
        "email":     email,
        "password":  password,
        "phone":     f"+9665{random.randint(10_000_000, 99_999_999)}",
        "city":      city,
    }, client_type=ct)

    if not r or r.status != 201:
        return None

    body    = await r.json()
    user_id = body.get("user_id")

    r2, _ = await api_post(ctx, "/auth/sign-in",
                           {"email": email, "password": password},
                           client_type=ct)
    if not r2 or r2.status != 200:
        return None

    token = (await r2.json()).get("token")
    fund  = round(random.triangular(200, 3000, 800), 2)
    await api_post(ctx, f"/users/{user_id}/wallet/topup",
                   {"amount": fund}, token=token, client_type=ct)
    await api_post(ctx, "/auth/sign-out", token=token, client_type=ct)

    user = {"email": email, "password": password,
            "user_id": user_id, "geo_location": city, "client_type": ct}
    async with pool_lock:
        pool.append(user)
    return user


async def get_normal_user() -> dict:
    async with pool_lock:
        return dict(random.choice(normal_pool))


async def get_attack_user() -> Optional[dict]:
    async with pool_lock:
        return attack_pool.pop(0) if attack_pool else None


# ─────────────────────────────────────────────────────────────────────────────
# Progress
# ─────────────────────────────────────────────────────────────────────────────
_counter      = 0
_counter_lock = asyncio.Lock()


async def tick():
    global _counter
    async with _counter_lock:
        _counter += 1
        c = _counter
    if c % 20 == 0 or c == TOTAL:
        print(f"  ▶ {c}/{TOTAL} sessions ({c/TOTAL*100:.1f}%)")


def _typo(pwd: str) -> str:
    base  = pwd if len(pwd) >= 8 else pwd + "x" * (8 - len(pwd))
    chars = list(base)
    mut   = random.choice(["swap", "insert", "case", "replace"])
    if mut == "swap" and len(chars) >= 2:
        i = random.randint(0, len(chars) - 2)
        chars[i], chars[i+1] = chars[i+1], chars[i]
    elif mut == "insert":
        chars.insert(random.randint(0, len(chars)), str(random.randint(0, 9)))
    elif mut == "case":
        chars[0] = chars[0].swapcase()
    elif mut == "replace":
        chars[random.randint(0, len(chars)-1)] = random.choice(
            "abcdefghijklmnopqrstuvwxyz"
        )
    result = "".join(chars)
    return result if len(result) >= 8 else result + "pad12345"


# ─────────────────────────────────────────────────────────────────────────────
# Normal session runners
# ─────────────────────────────────────────────────────────────────────────────

async def run_normal_session(ctx) -> None:
    """
    Normal session. 20% are suspicious-looking power users with elevated
    request rates and occasional login mistakes — overlapping with attack
    sessions on requests_per_minute and failed_login_ratio.
    Source: Balla et al. ICT 2011; NIST SP 800-63B §5.2.3
    """
    sid     = str(uuid.uuid4())
    user    = await get_normal_user()
    email   = user["email"]
    pw      = user["password"]
    geo     = user["geo_location"]
    ct      = user["client_type"]
    uid     = user["user_id"]

    # 20% suspicious-looking normal sessions
    # Elevated mistake rate + power user actions
    # Source: Balla 2011; NIST 800-63B §5.2.3
    is_suspicious_normal = random.random() < NORMAL_SUSPICIOUS
    persona = (
        PERSONAS["power_user"]
        if is_suspicious_normal
        else pick_persona()
    )
    mistake_rate = 0.20 if is_suspicious_normal else 0.08

    await asyncio.sleep(random.uniform(0, 2))

    # Login mistakes
    if random.random() < mistake_rate:
        r, rt = await api_post(
            ctx, "/auth/sign-in",
            {"email": email, "password": _typo(pw)},
            client_type=ct,
        )
        tt = await think_human_bimodal()
        await log_req(sid, uid, email, geo, ct, "POST",
                      "/auth/sign-in", r.status if r else "ERR",
                      rt, tt, 0, "normal")

    r, rt = await api_post(ctx, "/auth/sign-in",
                           {"email": email, "password": pw},
                           client_type=ct)
    if not r or r.status != 200:
        await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-in",
                      r.status if r else "ERR", rt, 0, 0, "normal")
        return

    body  = await r.json()
    token = body.get("token")
    uid   = body.get("user_id", uid)
    tt    = await think_human_bimodal()
    await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-in",
                  200, rt, tt, 0, "normal")

    n = random.randint(persona["actions_min"], persona["actions_max"])
    for _ in range(n):
        action = pick_action(persona)
        tt     = await think_human_bimodal()
        await _normal_action(ctx, sid, uid, token, email, geo, ct, action, tt)

    r, rt = await api_post(ctx, "/auth/sign-out", token=token, client_type=ct)
    await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-out",
                  r.status if r else "ERR", rt, 0, 0, "normal")


async def _normal_action(ctx, sid, uid, token, email,
                         geo, ct, action, tt) -> None:

    async def log(method, path, r, rt):
        await log_req(sid, uid, email, geo, ct, method, path,
                      r.status if r else "ERR", rt, tt, 0, "normal")

    if action == "wallet_view":
        path = f"/users/{uid}/wallet"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "topup":
        path = f"/users/{uid}/wallet/topup"
        r, rt = await api_post(ctx, path,
            {"amount": round(random.uniform(10, 500), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "withdraw":
        path = f"/users/{uid}/wallet/withdraw"
        r, rt = await api_post(ctx, path,
            {"amount": round(random.uniform(5, 100), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "transfer":
        async with pool_lock:
            targets = [u["user_id"] for u in normal_pool
                       if u["user_id"] != uid]
        target = random.choice(targets) if targets else "u_1001"
        path   = f"/users/{uid}/wallet/transfer/{target}"
        r, rt  = await api_post(ctx, path,
            {"amount": round(random.uniform(5, 80), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "pay_bill":
        path = f"/users/{uid}/wallet/pay-bill"
        r, rt = await api_post(ctx, path,
            {"amount": round(random.uniform(20, 200), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "view_profile":
        path = f"/users/{uid}"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "update_profile":
        path = f"/users/{uid}"
        r, rt = await api_put(ctx, path, {"city": pick_geo()},
                              token=token, client_type=ct)
        await log("PUT", path, r, rt)
    elif action == "payments":
        path = f"/users/{uid}/payments"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "bank_accounts":
        path = f"/users/{uid}/bank-accounts"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "auth_me":
        r, rt = await api_get(ctx, "/auth/me", token=token, client_type=ct)
        await log("GET", "/auth/me", r, rt)


# ─────────────────────────────────────────────────────────────────────────────
# Attack session runners — multi-dimensional overlap variants
# ─────────────────────────────────────────────────────────────────────────────

async def run_credential_attack(ctx) -> None:
    """
    Two variants:

    Standard (70%): Many failed attempts, high failed_login_ratio.
    Bot or stealth timing. Clear signal.

    Low-ratio (30%): Attacker succeeds after 2–3 attempts then browses
    normally. failed_login_ratio drops to 0.10–0.25. Timing is human.
    Model must rely on session context and request sequence.
    Source: Alsaleh et al. TDSC 2012, p. 128 — ATT known machine threshold
    is 30 failures; sophisticated attacker stops early after success.
    DOI: 10.1109/TDSC.2011.24
    """
    sid  = str(uuid.uuid4())
    user = await get_attack_user()
    if not user:
        return
    email    = user["email"]
    password = user["password"]
    geo      = user["geo_location"]
    ct       = user["client_type"]
    uid      = user["user_id"]

    is_low_ratio = random.random() < CRED_LOW_RATIO_RATE

    if is_low_ratio:
        # 2–3 failed attempts then successful login and normal browsing
        # failed_login_ratio ≈ 0.10–0.25 — overlaps confused normal user
        # Source: Alsaleh et al. TDSC 2012, p. 128
        n_fails = random.randint(2, 3)
        for _ in range(n_fails):
            bad_pw = fake.password(length=random.randint(8, 14), special_chars=False)
            r, rt  = await api_post(
                ctx, "/auth/sign-in",
                {"email": email, "password": bad_pw},
                client_type=ct,
            )
            tt = await think_human_bimodal()
            await log_req(sid, uid, email, geo, ct,
                          "POST", "/auth/sign-in",
                          r.status if r else "ERR", rt, tt,
                          1, "credential_attack")

        # Successful login
        r, rt = await api_post(
            ctx, "/auth/sign-in",
            {"email": email, "password": password},
            client_type=ct,
        )
        if not r or r.status != 200:
            return

        body  = await r.json()
        token = body.get("token")
        uid   = body.get("user_id", uid)
        tt    = await think_human_bimodal()
        await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-in",
                      200, rt, tt, 1, "credential_attack")

        # Normal-looking browsing after successful login
        # Overlaps with casual normal user sessions
        persona = PERSONAS["casual"]
        n = random.randint(3, 6)
        for _ in range(n):
            action = pick_action(persona)
            tt     = await think_human_bimodal()
            await _attack_action(ctx, sid, uid, token, email, geo, ct,
                                 action, tt, "credential_attack")

        await api_post(ctx, "/auth/sign-out", token=token, client_type=ct)

    else:
        # Standard: many failed attempts, high error ratio
        # All timing stealth (human bimodal throughout)
        n = random.randint(10, 30)
        for _ in range(n):
            bad_pw = fake.password(length=random.randint(8, 14), special_chars=False)
            r, rt  = await api_post(
                ctx, "/auth/sign-in",
                {"email": email, "password": bad_pw},
                client_type=ct,
            )
            status = r.status if r else "ERR"
            tt = await think_human_bimodal()
            await log_req(sid, uid, email, geo, ct,
                          "POST", "/auth/sign-in", status, rt, tt,
                          1, "credential_attack")


async def run_financial_fraud(ctx) -> None:
    """
    Two variants:

    Standard (60%): Many rapid financial operations. High wallet_action_ratio.
    Mixed timing. Clear signal.

    Low-velocity (40%): Only 2–4 financial operations spread over 20+ minutes.
    wallet_action_ratio drops to 0.15–0.30, overlapping power_user normal.
    Timing is fully human bimodal.
    Model must rely on transfer targets and operation sequence.
    Source: Mubarok et al. IEEE ICIC 2025 — attackers stay below velocity
    thresholds to evade rule-based detection.
    """
    sid  = str(uuid.uuid4())
    user = await get_attack_user()
    if not user:
        return
    email    = user["email"]
    password = user["password"]
    geo      = user["geo_location"]
    ct       = user["client_type"]
    uid      = user["user_id"]

    r, rt = await api_post(ctx, "/auth/sign-in",
                           {"email": email, "password": password},
                           client_type=ct)
    if not r or r.status != 200:
        await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-in",
                      r.status if r else "ERR", rt, 0, 1, "financial_fraud")
        return

    body  = await r.json()
    token = body.get("token")
    uid   = body.get("user_id", uid)
    await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-in",
                  200, rt, 0, 1, "financial_fraud")

    async with pool_lock:
        targets = [u["user_id"] for u in normal_pool if u["user_id"] != uid]
    if not targets:
        targets = ["u_1001", "u_1002", "u_1003"]

    is_low_velocity = random.random() < FRAUD_LOW_VELOCITY

    if is_low_velocity:
        # 2–4 operations with human timing between them
        # wallet_action_ratio ≈ 0.15–0.30 — overlaps power_user normal
        # Source: Mubarok et al. ICIC 2025
        n = random.randint(2, 4)

        # Pad with normal-looking browsing actions between fraud ops
        persona = PERSONAS["power_user"]
        total_actions = random.randint(8, 12)
        fraud_positions = sorted(random.sample(range(total_actions), n))

        for i in range(total_actions):
            if i in fraud_positions:
                # Fraud operation
                action = random.choices(
                    ["transfer", "withdraw"],
                    weights=[60, 40], k=1
                )[0]
                amount = round(random.uniform(10, 150), 2)
                if action == "transfer":
                    path = f"/users/{uid}/wallet/transfer/{random.choice(targets)}"
                else:
                    path = f"/users/{uid}/wallet/withdraw"
                r, rt = await api_post(ctx, path, {"amount": amount},
                                       token=token, client_type=ct)
                tt = await think_human_bimodal()
                await log_req(sid, uid, email, geo, ct, "POST", path,
                              r.status if r else "ERR", rt, tt,
                              1, "financial_fraud")
            else:
                # Normal-looking filler action
                action = pick_action(persona)
                tt     = await think_human_bimodal()
                await _attack_action(ctx, sid, uid, token, email, geo, ct,
                                     action, tt, "financial_fraud")
    else:
        # Standard: rapid financial operations
        n = random.randint(8, 15)
        for _ in range(n):
            action = random.choices(
                ["transfer", "withdraw", "topup", "pay_bill"],
                weights=[40, 30, 15, 15], k=1
            )[0]
            amount = round(random.uniform(10, 150), 2)
            if action == "transfer":
                path = f"/users/{uid}/wallet/transfer/{random.choice(targets)}"
            elif action == "withdraw":
                path = f"/users/{uid}/wallet/withdraw"
            elif action == "topup":
                path = f"/users/{uid}/wallet/topup"
            else:
                path = f"/users/{uid}/wallet/pay-bill"
            r, rt = await api_post(ctx, path, {"amount": amount},
                                   token=token, client_type=ct)
            tt = await think_human_bimodal()
            await log_req(sid, uid, email, geo, ct, "POST", path,
                          r.status if r else "ERR", rt, tt,
                          1, "financial_fraud")

    await api_post(ctx, "/auth/sign-out", token=token, client_type=ct)


async def run_endpoint_scanning(ctx) -> None:
    """
    Two variants:

    Standard (60%): Many endpoints probed, admin paths hit, high 4xx ratio.
    Clear signal.

    Distributed (40%): Only 3–5 endpoints probed with human timing.
    unique_endpoints and admin_action_count both in normal range.
    http_4xx_ratio still elevated but fewer requests means less signal.
    Model must rely on which specific paths are probed.
    Source: OWASP ATH v1.3 OAT-018 — enumeration can be distributed
    across multiple short sessions over time.
    """
    sid  = str(uuid.uuid4())
    user = await get_attack_user()
    if not user:
        return
    email    = user["email"]
    password = user["password"]
    geo      = user["geo_location"]
    ct       = user["client_type"]
    uid      = user["user_id"]

    is_distributed = random.random() < SCAN_DISTRIBUTED

    r, rt = await api_post(ctx, "/auth/sign-in",
                           {"email": email, "password": password},
                           client_type=ct)
    token = None
    if r and r.status == 200:
        body  = await r.json()
        token = body.get("token")
        uid   = body.get("user_id", uid)

    await log_req(sid, uid, email, geo, ct, "POST", "/auth/sign-in",
                  r.status if r else "ERR", rt, 0, 1, "endpoint_scanning")

    all_probes = [
        ("/admin/users",              "GET", False),
        ("/admin/wallets",            "GET", False),
        ("/admin/transactions",       "GET", False),
        ("/admin/overview/financial", "GET", False),
        ("/admin/keys",               "GET", False),
        ("/admin/logs",               "GET", False),
        ("/admin/export",             "GET", False),
        ("/config",                   "GET", False),
        ("/system/metrics",           "GET", False),
        ("/.env",                     "GET", False),
        ("/backup",                   "GET", False),
        ("/debug/users",              "GET", False),
        ("/api/v1/config",            "GET", False),
        ("/users/u_1001/wallet",      "GET", True),
        ("/users/u_1002/wallet",      "GET", True),
        ("/users/u_1003/wallet",      "GET", True),
    ]
    if token:
        all_probes += [
            (f"/users/{uid}/wallet",        "GET", True),
            (f"/users/{uid}/payments",      "GET", True),
            (f"/users/{uid}/bank-accounts", "GET", True),
            ("/auth/me",                    "GET", True),
        ]

    random.shuffle(all_probes)

    if is_distributed:
        # Only 3–5 probes — unique_endpoints in normal range
        # Still probes suspicious paths but low volume per session
        # Source: OWASP ATH v1.3 OAT-018
        selected = all_probes[:random.randint(3, 5)]
    else:
        # Full scan: 12+ probes
        selected = all_probes[:random.randint(12, len(all_probes))]

    for path, method, use_token in selected:
        tok = token if use_token else None
        if method == "GET":
            r, rt = await api_get(ctx, path, token=tok, client_type=ct)
        else:
            r, rt = await api_post(ctx, path, None, token=tok, client_type=ct)

        status = r.status if r else "ERR"
        # All scanning sessions use human timing in this hard test
        tt = await think_human_bimodal()
        await log_req(sid, uid, email, geo, ct, method, path,
                      status, rt, tt, 1, "endpoint_scanning")

    if token:
        await api_post(ctx, "/auth/sign-out", token=token, client_type=ct)


async def run_account_creation(ctx) -> None:
    """
    Two variants:

    Standard (50%): 3–8 rapid registrations. Clear signal.

    Slow (50%): Only 1–2 registrations with long human pauses between.
    total_requests and requests_per_minute both in normal range.
    Model must rely on sign-up path concentration.
    Source: Cola et al. IEEE Access 2023 — 24.5% of fake accounts created
    slowly to avoid burst detection.
    DOI: 10.1109/ACCESS.2023.3282580
    """
    sid = str(uuid.uuid4())
    geo = pick_geo()
    ct  = pick_client()

    is_slow = random.random() < ACCOUNT_SLOW

    if is_slow:
        # 1–2 registrations with human timing
        # total_requests ≈ 1–2, requests_per_minute in normal range
        # Source: Cola et al. IEEE Access 2023
        n = random.randint(1, 2)
        for _ in range(n):
            email = fake.unique.email()
            pw    = fake.password(length=random.randint(8, 14), special_chars=False)
            r, rt = await api_post(ctx, "/auth/sign-up", {
                "full_name": fake.name(),
                "email":     email,
                "password":  pw,
                "phone":     f"+9665{random.randint(10_000_000, 99_999_999)}",
                "city":      pick_geo(),
            }, client_type=ct)
            status = r.status if r else "ERR"
            tt = await think_human_bimodal()
            await log_req(sid, "unknown", email, geo, ct,
                          "POST", "/auth/sign-up", status, rt, tt,
                          1, "account_creation")
    else:
        # Standard: 3–8 rapid registrations
        n = random.randint(3, 8)
        for _ in range(n):
            email = fake.unique.email()
            pw    = fake.password(length=random.randint(8, 14), special_chars=False)
            r, rt = await api_post(ctx, "/auth/sign-up", {
                "full_name": fake.name(),
                "email":     email,
                "password":  pw,
                "phone":     f"+9665{random.randint(10_000_000, 99_999_999)}",
                "city":      pick_geo(),
            }, client_type=ct)
            status = r.status if r else "ERR"
            tt = await think_human_bimodal()
            await log_req(sid, "unknown", email, geo, ct,
                          "POST", "/auth/sign-up", status, rt, tt,
                          1, "account_creation")


# ─────────────────────────────────────────────────────────────────────────────
# Attack action helper — same as normal but different label
# ─────────────────────────────────────────────────────────────────────────────
async def _attack_action(ctx, sid, uid, token, email,
                         geo, ct, action, tt, attack_type) -> None:

    async def log(method, path, r, rt):
        await log_req(sid, uid, email, geo, ct, method, path,
                      r.status if r else "ERR", rt, tt, 1, attack_type)

    if action == "wallet_view":
        path = f"/users/{uid}/wallet"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "topup":
        path = f"/users/{uid}/wallet/topup"
        r, rt = await api_post(ctx, path,
            {"amount": round(random.uniform(10, 500), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "withdraw":
        path = f"/users/{uid}/wallet/withdraw"
        r, rt = await api_post(ctx, path,
            {"amount": round(random.uniform(5, 100), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "transfer":
        async with pool_lock:
            targets = [u["user_id"] for u in normal_pool
                       if u["user_id"] != uid]
        target = random.choice(targets) if targets else "u_1001"
        path   = f"/users/{uid}/wallet/transfer/{target}"
        r, rt  = await api_post(ctx, path,
            {"amount": round(random.uniform(5, 80), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "pay_bill":
        path = f"/users/{uid}/wallet/pay-bill"
        r, rt = await api_post(ctx, path,
            {"amount": round(random.uniform(20, 200), 2)},
            token=token, client_type=ct)
        await log("POST", path, r, rt)
    elif action == "view_profile":
        path = f"/users/{uid}"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "auth_me":
        r, rt = await api_get(ctx, "/auth/me", token=token, client_type=ct)
        await log("GET", "/auth/me", r, rt)
    elif action == "payments":
        path = f"/users/{uid}/payments"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)
    elif action == "bank_accounts":
        path = f"/users/{uid}/bank-accounts"
        r, rt = await api_get(ctx, path, token=token, client_type=ct)
        await log("GET", path, r, rt)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
async def main():
    init_csv()

    print("=" * 80)
    print("  GATE80 Hard Stress Test Generator")
    print(f"  Total          : {TOTAL} sessions")
    print(f"  Normal         : {N_NORMAL} — 20% suspicious-looking variants")
    print(f"  Credential     : {N_CREDENTIAL} — 30% low failed_login_ratio variant")
    print(f"  Fraud          : {N_FRAUD} — 40% low velocity variant")
    print(f"  Scanning       : {N_SCANNING} — 40% distributed (3–5 endpoints)")
    print(f"  Account        : {N_ACCOUNT} — 50% slow (1–2 registrations)")
    print(f"  All attack timing: human bimodal throughout")
    print(f"  Output         : {CSV_FILE}")
    print("=" * 80)

    async with async_playwright() as pw:

        rb = await pw.chromium.launch()
        rc = await rb.new_context()

        print(f"\n[SETUP] Registering {N_NORMAL_USERS} normal users...")
        for i in range(N_NORMAL_USERS):
            await register_and_fund(rc.request, normal_pool)
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/{N_NORMAL_USERS}")
            await asyncio.sleep(0.2)

        print(f"\n[SETUP] Registering {N_ATTACK_USERS} attack users...")
        for i in range(N_ATTACK_USERS):
            await register_and_fund(rc.request, attack_pool)
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/{N_ATTACK_USERS}")
            await asyncio.sleep(0.2)

        await rc.close()
        await rb.close()
        print(f"\n[SETUP] ✅ {len(normal_pool)} normal + "
              f"{len(attack_pool)} attack users ready\n")

        print(f"[SETUP] Launching {MAX_CONCURRENT} workers...")
        browsers, ctxs = [], []
        for _ in range(MAX_CONCURRENT):
            bw = await pw.chromium.launch()
            cx = await bw.new_context()
            browsers.append(bw)
            ctxs.append(cx.request)
        print("[SETUP] ✅ Workers ready\n")

        sem = asyncio.Semaphore(MAX_CONCURRENT)

        def task(fn, idx):
            async def _():
                async with sem:
                    await fn(ctxs[idx % MAX_CONCURRENT])
                    await tick()
            return _()

        all_tasks = []
        i = 0
        for _ in range(N_NORMAL):
            all_tasks.append(task(run_normal_session, i));    i += 1
        for _ in range(N_CREDENTIAL):
            all_tasks.append(task(run_credential_attack, i)); i += 1
        for _ in range(N_FRAUD):
            all_tasks.append(task(run_financial_fraud, i));   i += 1
        for _ in range(N_SCANNING):
            all_tasks.append(task(run_endpoint_scanning, i)); i += 1
        for _ in range(N_ACCOUNT):
            all_tasks.append(task(run_account_creation, i));  i += 1

        random.shuffle(all_tasks)
        print(f"[RUN] Starting {len(all_tasks)} sessions...\n")
        await asyncio.gather(*all_tasks)

        for bw in browsers:
            await bw.close()

    print("\n" + "=" * 80)
    print(f"  ✅ Done! Output: {CSV_FILE}")
    print(f"  Next: python3 -m dataset.final.aggregate_sessions {CSV_FILE}")
    print(f"  Then: python3 -m dataset.final.evaluate <sessions_csv>")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())