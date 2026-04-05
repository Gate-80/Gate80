"""
GATE80 — Targeted Top-up Generator
dataset/unified/generate_topup.py

Generates only the missing attack sessions to complete the 10k dataset.
Appends rows to the existing gate80_requests_log.csv.

Missing sessions:
  account_takeover  : 176 (target 300, got 124)
  financial_fraud   :  99 (target 150, got  51)

Fix:
  Dedicated 200-user pool used ONLY by these two attack types.
  Higher wallet funding (3000-5000 SAR) to prevent balance exhaustion.
  Lower concurrency to avoid SQLite write contention.
  Always sign out after each session to free the token.
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from faker import Faker
from playwright.async_api import async_playwright

BASE_URL      = "http://127.0.0.1:8080/api/v1"
NUM_DEDICATED_USERS = 200
MAX_CONCURRENT = 5
OUTPUT_FILE = "dataset/output/gate80_requests_log.csv"
SOURCE_TOOL = "playwright"

TOPUP_COUNTS = {
    "account_takeover": 176,
    "financial_fraud":  99,
}

SAUDI_CITIES = ["Jeddah","Riyadh","Mecca","Medina","Dammam","Khobar","Tabuk","Abha","Taif","Buraidah"]
CLIENT_TYPES = ["web", "ios", "android"]

fake = Faker()

CSV_COLUMNS = [
    "timestamp","session_id","persona","email","user_id",
    "action","method","path","status_code","is_failed_login",
    "response_time_ms","think_time_ms","body_size",
    "has_auth_token","endpoint_category","response_length",
    "geo_location","client_type","user_agent","source_tool",
    "label","session_type",
]

csv_lock = asyncio.Lock()
reg_lock = asyncio.Lock()
dedicated_users = []

session_counter = 0
counter_lock    = asyncio.Lock()
total_sessions  = sum(TOPUP_COUNTS.values())


def endpoint_category(path):
    if "/admin" in path: return "admin"
    if any(x in path for x in ["/auth/sign-in","/auth/sign-up","/auth/sign-out","/auth/me"]): return "auth"
    if "/wallet" in path: return "wallet"
    if "/bank-accounts" in path or "/payments" in path: return "account"
    if path.startswith("/users/"): return "account"
    if path in ["/health","/hello"]: return "system"
    return "other"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


async def log_row(row):
    async with csv_lock:
        with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([row.get(col, "") for col in CSV_COLUMNS])


def make_row(session_id, persona, email, user_id, action, method, path,
             status_code, label=1, session_type="account_takeover",
             is_failed_login=False, response_time_ms=0, think_time_ms=0,
             body_size=0, has_auth_token=False, response_length=0,
             geo_location="", client_type="web", user_agent=""):
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
    print(f"[{ts}] {sid[:8]} | {tag:<22} | {action:<45} | {status} {rt}")


async def tick():
    global session_counter
    async with counter_lock:
        session_counter += 1
        count = session_counter
    if count % 50 == 0 or count == total_sessions:
        pct = count / total_sessions * 100
        print(f"\n  Progress: {count}/{total_sessions} ({pct:.1f}%)\n")


async def api_post(ctx, path, payload=None, token=None, token_type="user",
                   client_type="web", user_agent=""):
    headers = {"Content-Type": "application/json", "User-Agent": user_agent,
               "X-Client-Type": client_type}
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


async def think_ms(min_ms, max_ms):
    delay = random.uniform(min_ms / 1000, max_ms / 1000)
    await asyncio.sleep(delay)
    return int(delay * 1000)


async def register_dedicated_user(ctx):
    email    = fake.unique.email()
    password = fake.password(length=random.randint(8, 14), special_chars=False)
    city     = random.choice(SAUDI_CITIES)
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    r, _, _, _ = await api_post(ctx, "/auth/sign-up", {
        "full_name": fake.name(), "email": email, "password": password,
        "phone": f"+9665{random.randint(10000000,99999999)}", "city": city,
    }, client_type=ct, user_agent=ua)

    if not r or r.status != 201:
        return None

    body    = await r.json()
    user_id = body.get("user_id")

    r2, _, _, _ = await api_post(ctx, "/auth/sign-in",
                                 {"email": email, "password": password},
                                 client_type=ct, user_agent=ua)
    if not r2 or r2.status != 200:
        return None

    token = (await r2.json()).get("token")

    # Higher funding so financial fraud doesn't exhaust balance
    fund = round(random.triangular(3000, 5000, 3500), 2)
    await api_post(ctx, f"/users/{user_id}/wallet/topup", {"amount": fund},
                   token=token, client_type=ct, user_agent=ua)
    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)

    user = {"email": email, "password": password, "user_id": user_id,
            "geo_location": city, "client_type": ct, "user_agent": ua}
    async with reg_lock:
        dedicated_users.append(user)
    return user


async def get_user():
    async with reg_lock:
        pool = list(dedicated_users)
    if not pool:
        raise RuntimeError("Dedicated pool empty")
    return dict(random.choice(pool))


async def run_account_takeover(ctx):
    sid      = str(uuid.uuid4())
    user     = await get_user()
    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    clog(sid, "ACCOUNT_TAKEOVER", f"logging in as {email}", "->")

    r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in",
                                      {"email": email, "password": password},
                                      client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")

    await log_row(make_row(sid, "attacker", email, user_id, "sign_in_ato",
                           "POST", "/auth/sign-in", 200,
                           label=1, session_type="account_takeover",
                           response_time_ms=rt, body_size=bs,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))

    async with reg_lock:
        targets = [u["user_id"] for u in dedicated_users
                   if u.get("user_id") and u["user_id"] != user_id]
    if not targets:
        targets = ["u_1001", "u_1002", "u_1003"]

    for i in range(random.randint(8, 15)):
        action = random.choices(["withdraw","transfer","pay_bill"],
                                weights=[40,40,20], k=1)[0]
        if action == "withdraw":
            path = f"/users/{user_id}/wallet/withdraw"
            amount = round(random.uniform(50, 300), 2)
        elif action == "transfer":
            path = f"/users/{user_id}/wallet/transfer/{random.choice(targets)}"
            amount = round(random.uniform(50, 300), 2)
        else:
            path = f"/users/{user_id}/wallet/pay-bill"
            amount = round(random.uniform(30, 200), 2)

        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                          token=token, client_type=ct,
                                          user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think_ms(80, 400)

        await log_row(make_row(sid, "attacker", email, user_id, f"{action}_ato",
                               "POST", path, status,
                               label=1, session_type="account_takeover",
                               response_time_ms=rt, think_time_ms=tt,
                               body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

        if i % 4 == 0:
            clog(sid, "ACCOUNT_TAKEOVER", f"{action} attempt {i+1}", status, rt)

    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)


async def run_financial_fraud(ctx):
    sid      = str(uuid.uuid4())
    user     = await get_user()
    email    = user["email"]
    password = user["password"]
    geo      = user.get("geo_location", random.choice(SAUDI_CITIES))
    ct       = random.choice(CLIENT_TYPES)
    ua       = fake.user_agent()

    clog(sid, "FINANCIAL_FRAUD", f"logging in as {email}", "->")

    r, rt, bs, r_len = await api_post(ctx, "/auth/sign-in",
                                      {"email": email, "password": password},
                                      client_type=ct, user_agent=ua)
    if not r or r.status != 200:
        return

    body    = await r.json()
    token   = body.get("token")
    user_id = body.get("user_id")

    await log_row(make_row(sid, "attacker", email, user_id, "sign_in_fraud",
                           "POST", "/auth/sign-in", 200,
                           label=1, session_type="financial_fraud",
                           response_time_ms=rt, body_size=bs,
                           response_length=r_len, geo_location=geo,
                           client_type=ct, user_agent=ua))

    async with reg_lock:
        targets = [u["user_id"] for u in dedicated_users
                   if u.get("user_id") and u["user_id"] != user_id]
    if not targets:
        targets = ["u_1001", "u_1002", "u_1003"]

    for i in range(random.randint(10, 20)):
        action = random.choices(["topup","transfer","withdraw","pay_bill"],
                                weights=[20,40,25,15], k=1)[0]
        amount = round(random.uniform(10, 150), 2)

        if action == "topup":
            path = f"/users/{user_id}/wallet/topup"
        elif action == "transfer":
            path = f"/users/{user_id}/wallet/transfer/{random.choice(targets)}"
        elif action == "withdraw":
            path = f"/users/{user_id}/wallet/withdraw"
        else:
            path = f"/users/{user_id}/wallet/pay-bill"

        r, rt, bs, r_len = await api_post(ctx, path, {"amount": amount},
                                          token=token, client_type=ct,
                                          user_agent=ua)
        status = r.status if r else "ERR"
        tt = await think_ms(30, 180)

        await log_row(make_row(sid, "attacker", email, user_id, f"{action}_fraud",
                               "POST", path, status,
                               label=1, session_type="financial_fraud",
                               response_time_ms=rt, think_time_ms=tt,
                               body_size=bs, has_auth_token=True,
                               response_length=r_len, geo_location=geo,
                               client_type=ct, user_agent=ua))

        if i % 5 == 0:
            clog(sid, "FINANCIAL_FRAUD", f"{action} x{i+1}", status, rt)

    await api_post(ctx, "/auth/sign-out", token=token,
                   client_type=ct, user_agent=ua)


async def main():
    if not os.path.exists(OUTPUT_FILE):
        print(f"[ERROR] File not found: {OUTPUT_FILE}")
        return

    print("=" * 70)
    print("  GATE80 Targeted Top-up Generator")
    print(f"  Appending to: {OUTPUT_FILE}")
    for atype, count in TOPUP_COUNTS.items():
        print(f"  {atype:<25} {count} sessions")
    print(f"  Total: {total_sessions}")
    print("=" * 70)

    async with async_playwright() as playwright:

        print(f"\n[SETUP] Registering {NUM_DEDICATED_USERS} dedicated users...")
        sb = await playwright.chromium.launch()
        sc = await sb.new_context()
        for i in range(NUM_DEDICATED_USERS):
            await register_dedicated_user(sc.request)
            if (i + 1) % 50 == 0:
                print(f"  {i+1}/{NUM_DEDICATED_USERS} registered...")
            await asyncio.sleep(0.2)
        await sc.close()
        await sb.close()

        if not dedicated_users:
            print("[ERROR] Registration failed. Check proxy is running.")
            return

        print(f"[SETUP] {len(dedicated_users)} dedicated users ready\n")

        browsers, contexts, ctxs = [], [], []
        for _ in range(MAX_CONCURRENT):
            bw = await playwright.chromium.launch()
            cx = await bw.new_context()
            browsers.append(bw)
            contexts.append(cx)
            ctxs.append(cx.request)

        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        def make_task(fn, idx):
            async def _t():
                async with semaphore:
                    await fn(ctxs[idx % MAX_CONCURRENT])
                    await tick()
            return _t()

        runners = {
            "account_takeover": run_account_takeover,
            "financial_fraud":  run_financial_fraud,
        }
        tasks = []
        idx = 0
        for atype, count in TOPUP_COUNTS.items():
            for _ in range(count):
                tasks.append(make_task(runners[atype], idx))
                idx += 1

        random.shuffle(tasks)
        print(f"[RUN] Generating {len(tasks)} sessions...\n")
        await asyncio.gather(*tasks)

        for cx in contexts:
            await cx.close()
        for bw in browsers:
            await bw.close()

    print("\n" + "=" * 70)
    print(f"  Done! {total_sessions} sessions appended.")
    print(f"  Re-run: python dataset/unified/feature_engineering.py")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())