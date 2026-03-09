# Step 3 script

"""
RASD - Step 3: Extract Behavioral Features for Abnormal Sessions
Week 4/5 - Feature Engineering

Takes:
  - traffic_log.csv
  - TrafficLog_abnormal_sessions.csv

Produces:
  - abnormal_sessions.csv

Features computed per session:
  --- Session metrics ---
  1.  total_requests
  2.  session_duration_sec
  3.  requests_per_minute

  --- Error signals ---
  4.  failed_login_count
  5.  error_ratio
  6.  error_4xx_count
  7.  error_5xx_count

  --- Endpoint behavior ---
  8.  unique_endpoints
  9.  endpoint_entropy
  10. has_admin_access
  11. admin_action_count

  --- Financial behavior ---
  12. wallet_action_count
  13. wallet_action_ratio
  14. transfer_count
  15. topup_count
  16. withdraw_count
  17. pay_bill_count
  18. financial_error_count

  --- Timing behavior ---
  19. avg_think_time_ms
  20. std_think_time_ms
  21. avg_response_time_ms
  22. min_think_time_ms

  --- Identity ---
  23. persona
  24. geo_location
  25. client_type
  26. user_id
  27. email

Run:
    python abnormal_feature_engineering.py
"""

import csv
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
TRAFFIC_LOG_FILE  = "dataset/output/traffic_log.csv"
SESSIONS_FILE     = "dataset/output/TrafficLog_abnormal_sessions.csv"
OUTPUT_FILE       = "dataset/output/abnormal_sessions.csv"

WALLET_ACTIONS = {
    "wallet_view", "topup", "withdraw", "transfer", "pay_bill",
    "withdraw_overdraft", "topup_double_submit", "transfer_to_self",
    "transfer_nonexistent", "topup_bad_format",
    "topup_bad_amount", "withdraw_bad_amount", "pay-bill_bad_amount",
}

FINANCIAL_ERROR_ACTIONS = {
    "withdraw_overdraft", "topup_bad_format", "topup_bad_amount",
    "withdraw_bad_amount", "pay-bill_bad_amount",
}

ADMIN_ACTIONS = {
    "admin_sign_in", "admin_sign_out", "admin_users",
    "admin_wallets", "admin_transactions", "admin_financial",
    "admin_get",
}

FAILED_LOGIN_ACTIONS = {
    "failed_login", "failed_login_bad_email",
}

OUTPUT_COLUMNS = [
    "session_id", "user_id", "email", "persona", "geo_location", "client_type",
    # session metrics
    "total_requests", "session_duration_sec", "requests_per_minute",
    # error signals
    "failed_login_count", "error_ratio", "error_4xx_count", "error_5xx_count",
    # endpoint behavior
    "unique_endpoints", "endpoint_entropy", "has_admin_access", "admin_action_count",
    # financial behavior
    "wallet_action_count", "wallet_action_ratio", "transfer_count",
    "topup_count", "withdraw_count", "pay_bill_count", "financial_error_count",
    # timing
    "avg_think_time_ms", "std_think_time_ms", "avg_response_time_ms", "min_think_time_ms",
]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def parse_ts(ts_str: str) -> datetime:
    """Parse ISO timestamp to datetime — handles both Z and +00:00 formats."""
    ts_str = ts_str.strip()
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.fromisoformat(ts_str[:26]).replace(tzinfo=timezone.utc)


def shannon_entropy(counts: list) -> float:
    """Shannon entropy of a distribution — measures endpoint diversity."""
    total = sum(counts)
    if total == 0:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    return -sum(p * math.log2(p) for p in probs)


def safe_mean(vals: list) -> float:
    return round(sum(vals) / len(vals), 2) if vals else 0.0


def safe_std(vals: list) -> float:
    if len(vals) < 2:
        return 0.0
    mean = sum(vals) / len(vals)
    variance = sum((v - mean) ** 2 for v in vals) / len(vals)
    return round(math.sqrt(variance), 2)


# ─────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────
print(f"[1/4] Loading {TRAFFIC_LOG_FILE}...")
with open(TRAFFIC_LOG_FILE, newline="", encoding="utf-8") as f:
    raw_rows = list(csv.DictReader(f))
print(f"      {len(raw_rows)} request rows loaded.")

print(f"[2/4] Loading {SESSIONS_FILE}...")
with open(SESSIONS_FILE, newline="", encoding="utf-8") as f:
    session_meta = {r["session_id"]: r for r in csv.DictReader(f)}
print(f"      {len(session_meta)} abnormal session objects loaded.")

# ─────────────────────────────────────────────
# GROUP REQUESTS BY SESSION
# ─────────────────────────────────────────────
print("[3/4] Grouping requests by session and computing features...")
sessions_requests = defaultdict(list)
for row in raw_rows:
    sessions_requests[row["session_id"]].append(row)

# ─────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────
output_rows = []

for session_id, requests in sessions_requests.items():

    # Sort by timestamp
    try:
        requests.sort(key=lambda r: parse_ts(r["timestamp"]))
    except Exception:
        pass

    # ── Identity (from session meta or first request) ──
    meta        = session_meta.get(session_id, {})
    first       = requests[0]
    persona     = meta.get("persona",     first.get("persona", ""))
    geo         = meta.get("geo_location",first.get("geo_location", ""))
    client_type = meta.get("client_type", first.get("client_type", ""))
    user_id     = meta.get("user_id",     first.get("user_id", ""))
    email       = meta.get("email",       first.get("email", ""))

    # ── Session metrics ──
    total_requests = len(requests)

    try:
        t_start = parse_ts(requests[0]["timestamp"])
        t_end   = parse_ts(requests[-1]["timestamp"])
        duration_sec = max((t_end - t_start).total_seconds(), 0.0)
    except Exception:
        duration_sec = 0.0

    requests_per_minute = round(
        (total_requests / duration_sec * 60) if duration_sec > 0 else 0.0, 2
    )

    # ── Error signals ──
    failed_login_count = sum(
        1 for r in requests if r["action"] in FAILED_LOGIN_ACTIONS
        or r.get("is_failed_login", "").lower() == "true"
    )

    status_codes  = [r["status_code"] for r in requests]
    non_200_count = sum(1 for s in status_codes if s != "200")
    error_ratio   = round(non_200_count / total_requests, 4) if total_requests > 0 else 0.0
    error_4xx     = sum(1 for s in status_codes if s.startswith("4"))
    error_5xx     = sum(1 for s in status_codes if s.startswith("5"))

    # ── Endpoint behavior ──
    paths            = [r["path"] for r in requests]
    unique_endpoints = len(set(paths))
    path_counts      = list(Counter(paths).values())
    endpoint_entropy = round(shannon_entropy(path_counts), 4)

    has_admin_access   = int(any(r["endpoint_category"] == "admin" for r in requests))
    admin_action_count = sum(
        1 for r in requests
        if r["action"] in ADMIN_ACTIONS or r["endpoint_category"] == "admin"
    )

    # ── Financial behavior ──
    actions = [r["action"] for r in requests]

    wallet_action_count   = sum(1 for a in actions if a in WALLET_ACTIONS)
    wallet_action_ratio   = round(wallet_action_count / total_requests, 4) if total_requests > 0 else 0.0
    transfer_count        = sum(1 for a in actions if a in {"transfer", "transfer_to_self", "transfer_nonexistent"})
    topup_count           = sum(1 for a in actions if a in {"topup", "topup_double_submit", "topup_bad_format", "topup_bad_amount"})
    withdraw_count        = sum(1 for a in actions if a in {"withdraw", "withdraw_overdraft", "withdraw_bad_amount"})
    pay_bill_count        = sum(1 for a in actions if a in {"pay_bill", "pay-bill_bad_amount"})
    financial_error_count = sum(1 for a in actions if a in FINANCIAL_ERROR_ACTIONS)

    # ── Timing behavior ──
    think_times = [
        int(r["think_time_ms"]) for r in requests
        if r["think_time_ms"].strip().isdigit() and int(r["think_time_ms"]) > 0
    ]
    response_times = [
        int(r["response_time_ms"]) for r in requests
        if r["response_time_ms"].strip().isdigit()
    ]

    avg_think_time_ms    = safe_mean(think_times)
    std_think_time_ms    = safe_std(think_times)
    avg_response_time_ms = min(safe_mean(response_times), 500.0)
    min_think_time_ms    = min(think_times) if think_times else 0

    # Skip incomplete sessions
    if total_requests <= 1:
        continue

    # ── Assemble row ──
    output_rows.append({
        "session_id":            session_id,
        "user_id":               user_id,
        "email":                 email,
        "persona":               persona,
        "geo_location":          geo,
        "client_type":           client_type,
        "total_requests":        total_requests,
        "session_duration_sec":  round(duration_sec, 2),
        "requests_per_minute":   requests_per_minute,
        "failed_login_count":    failed_login_count,
        "error_ratio":           error_ratio,
        "error_4xx_count":       error_4xx,
        "error_5xx_count":       error_5xx,
        "unique_endpoints":      unique_endpoints,
        "endpoint_entropy":      endpoint_entropy,
        "has_admin_access":      has_admin_access,
        "admin_action_count":    admin_action_count,
        "wallet_action_count":   wallet_action_count,
        "wallet_action_ratio":   wallet_action_ratio,
        "transfer_count":        transfer_count,
        "topup_count":           topup_count,
        "withdraw_count":        withdraw_count,
        "pay_bill_count":        pay_bill_count,
        "financial_error_count": financial_error_count,
        "avg_think_time_ms":     avg_think_time_ms,
        "std_think_time_ms":     std_think_time_ms,
        "avg_response_time_ms":  avg_response_time_ms,
        "min_think_time_ms":     min_think_time_ms,
    })

# ─────────────────────────────────────────────
# WRITE OUTPUT
# ─────────────────────────────────────────────
print(f"[4/4] Writing {OUTPUT_FILE}...")
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
    writer.writeheader()
    writer.writerows(output_rows)

print(f"\n✅ Done! {len(output_rows)} abnormal session rows written to {OUTPUT_FILE}")
print(f"   Columns: {len(OUTPUT_COLUMNS)}")
print(f"\nQuick summary:")
print(f"  Sessions       : {len(output_rows)}")
print(f"  Avg requests   : {safe_mean([r['total_requests'] for r in output_rows]):.1f}")
print(f"  Avg duration   : {safe_mean([r['session_duration_sec'] for r in output_rows]):.1f}s")
print(f"  Avg think time : {safe_mean([r['avg_think_time_ms'] for r in output_rows]):.0f}ms")
print(f"  Sessions with failed logins : {sum(1 for r in output_rows if r['failed_login_count'] > 0)}")
print(f"  Sessions with admin access  : {sum(1 for r in output_rows if r['has_admin_access'] == 1)}")
print(f"  Sessions with financial errs: {sum(1 for r in output_rows if r['financial_error_count'] > 0)}")