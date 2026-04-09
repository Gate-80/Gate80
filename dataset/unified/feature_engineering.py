"""
GATE80 — Unified Feature Engineering
dataset/unified/feature_engineering.py

Transforms request-level traffic log into session-level behavioral features
for supervised ML anomaly detection.

Input:  dataset/unified/output/unified_traffic_log_<RUN_ID>.csv
Output: dataset/unified/output/gate80_dataset.csv

Feature design is grounded in how real API security tools detect threats:
  - Cloudflare API Gateway: session-based rate profiling, endpoint distribution
  - Akamai API Security: credential abuse signals, behavioral fingerprinting
  - Salt Security Q1 2023: authentication sequence analysis, enumeration detection
  - Shannon entropy: endpoint diversity measure (Bereziński et al., 2015;
    Hsiao & Lee, 2026 — Springer MISNC 2025)
  - Think time CV: coefficient of variation separates human (high CV) from
    bot/automated sessions (CV ≈ 0), used in behavioral bot detection systems

Feature groups (27 features + 2 labels):

  ── Volume & Rate ──────────────────────────────────────────────────────────
  total_requests        Total HTTP requests in session
  session_duration_sec  Time from first to last request (seconds)
  requests_per_minute   Request rate — high values indicate automation

  ── Authentication Signals ─────────────────────────────────────────────────
  failed_login_count    Failed login attempts (brute force / stuffing signal)
  login_attempts        Total sign-in attempts
  failed_login_ratio    failed_login_count / login_attempts (0–1)
                        → 1.0 = pure attack, 0.0 = no auth issues
  login_success         1 if any login succeeded (ATO signal when combined
                        with high wallet_action_count)

  ── Error Signals ──────────────────────────────────────────────────────────
  error_ratio           Non-200 responses / total_requests
  error_4xx_count       Client-side errors (auth failures, not found, etc.)
  error_5xx_count       Server errors (usually SQLite contention noise)
  http_4xx_ratio        error_4xx_count / total_requests
  http_5xx_ratio        error_5xx_count / total_requests

  ── Endpoint Behavior ──────────────────────────────────────────────────────
  unique_endpoints      Distinct paths hit — scanning has very high values
  endpoint_entropy      Shannon entropy of endpoint distribution
                        Low = concentrated on few paths (brute force)
                        High = diverse paths (scanning / normal)
  has_admin_access      1 if any admin endpoint was accessed
  admin_action_count    Number of admin endpoint requests
  admin_ratio           admin_action_count / total_requests

  ── Financial Behavior ─────────────────────────────────────────────────────
  wallet_action_count   Wallet operations (topup, withdraw, transfer, pay-bill)
  wallet_action_ratio   wallet_action_count / total_requests
                        High = fraud / ATO, low = brute force / scanning
  transfer_count        Transfer operations
  topup_count           Topup operations
  withdraw_count        Withdrawal operations
  pay_bill_count        Bill payment operations
  financial_error_count Wallet ops returning 400 (insufficient balance etc.)
                        Normal users hit this occasionally; ATO hits it often
                        after draining balance

  ── Timing Behavior ────────────────────────────────────────────────────────
  avg_think_time_ms     Mean inter-request delay
  std_think_time_ms     Standard deviation of think time
  min_think_time_ms     Minimum think time (near-zero = bot signal)
  max_think_time_ms     Maximum think time
  think_time_cv         Coefficient of Variation (std / mean) of think time
                        Humans: CV > 0.5 (irregular, purposeful pacing)
                        Bots:   CV ≈ 0.0–0.2 (machine-consistent timing)
                        Key bot detection signal used by Akamai Bot Manager
  avg_response_time_ms  Mean server response time

  ── Ground Truth ───────────────────────────────────────────────────────────
  label                 0 = normal, 1 = abnormal (binary, for model training)
  session_type          normal / brute_force / credential_stuffing /
                        account_takeover / scanning / financial_fraud
                        (internal diversity label, not used by model)

Run:
    python dataset/unified/feature_engineering.py \
        --input dataset/unified/output/unified_traffic_log_<RUN_ID>.csv
    
    Or without args to use the most recent file automatically.
"""

import argparse
import csv
import glob
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# Action name registry
# Maps all possible action names from the generator to semantic categories.
# Covers both normal persona actions and all 5 attack type action names.
# ─────────────────────────────────────────────────────────────────────────────

# Actions that represent a failed authentication attempt
FAILED_LOGIN_ACTIONS = {
    # Normal session mistake actions
    "failed_login",
    "failed_login_bad_email",
    # Attack-specific actions
    "credential_stuffing",   # credential stuffing attack attempts
}

# Actions that represent a successful sign-in attempt
SIGNIN_ACTIONS = {
    "sign_in",
    "sign_in_ato",      # account takeover successful login
    "sign_in_fraud",    # financial fraud successful login
    "sign_in_scan",     # scanning after successful login
}

# All wallet/financial operations — normal and attack variants
WALLET_ACTIONS = {
    # Normal persona actions
    "wallet_view",
    "topup",
    "withdraw",
    "transfer",
    "pay_bill",
    # Normal session mistake variants
    "withdraw_overdraft",
    "topup_double_submit",
    "transfer_to_self",
    "transfer_nonexistent",
    # Account takeover financial operations
    "withdraw_ato",
    "transfer_ato",
    "pay_bill_ato",
    # Financial fraud operations
    "withdraw_fraud",
    "transfer_fraud",
    "topup_fraud",
    "pay_bill_fraud",
}

# Transfer-specific actions
TRANSFER_ACTIONS = {
    "transfer", "transfer_to_self", "transfer_nonexistent",
    "transfer_ato", "transfer_fraud",
}

# Topup-specific actions
TOPUP_ACTIONS = {
    "topup", "topup_double_submit", "topup_fraud",
}

# Withdraw-specific actions
WITHDRAW_ACTIONS = {
    "withdraw", "withdraw_overdraft", "withdraw_ato", "withdraw_fraud",
}

# Pay-bill-specific actions
PAYBILL_ACTIONS = {
    "pay_bill", "pay_bill_ato", "pay_bill_fraud",
}

# Admin endpoint actions
ADMIN_ACTIONS = {
    "admin_sign_in", "admin_sign_out",
    "admin_users", "admin_wallets", "admin_transactions",
    "admin_financial", "admin_financial",
    "admin_overview",
}

# ─────────────────────────────────────────────────────────────────────────────
# Output schema — 29 columns
# ─────────────────────────────────────────────────────────────────────────────
OUTPUT_COLUMNS = [
    # Identity
    "session_id", "user_id", "email", "persona",
    "geo_location", "client_type",
    # Volume & rate
    "total_requests", "session_duration_sec", "requests_per_minute",
    # Authentication signals
    "failed_login_count", "login_attempts",
    "failed_login_ratio", "login_success",
    # Error signals
    "error_ratio", "error_4xx_count", "error_5xx_count",
    "http_4xx_ratio", "http_5xx_ratio",
    # Endpoint behavior
    "unique_endpoints", "endpoint_entropy",
    "has_admin_access", "admin_action_count", "admin_ratio",
    # Financial behavior
    "wallet_action_count", "wallet_action_ratio",
    "transfer_count", "topup_count", "withdraw_count",
    "pay_bill_count", "financial_error_count",
    # Timing behavior
    "avg_think_time_ms", "std_think_time_ms",
    "min_think_time_ms", "max_think_time_ms",
    "think_time_cv", "avg_response_time_ms",
    # Ground truth labels
    "label", "session_type",
]


# ─────────────────────────────────────────────────────────────────────────────
# Math helpers
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(counts: list) -> float:
    """
    Shannon entropy of a path distribution.
    Quantifies endpoint diversity within a session.
    Reference: Bereziński et al. (2015) — Entropy 17(4):2367–2408
               Hsiao & Lee (2026) — Springer MISNC 2025
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    return round(-sum(p * math.log2(p) for p in probs), 4)


def safe_mean(vals: list) -> float:
    return round(sum(vals) / len(vals), 2) if vals else 0.0


def safe_std(vals: list) -> float:
    if len(vals) < 2:
        return 0.0
    mean = sum(vals) / len(vals)
    variance = sum((v - mean) ** 2 for v in vals) / len(vals)
    return round(math.sqrt(variance), 2)


def coefficient_of_variation(vals: list) -> float:
    """
    CV = std / mean — measures timing regularity.
    Human sessions: CV > 0.5 (irregular, purposeful)
    Bot sessions:   CV ≈ 0.0–0.2 (machine-consistent)
    Used in Akamai Bot Manager and Cloudflare Bot Score behavioral models.
    """
    if len(vals) < 2:
        return 0.0
    mean = sum(vals) / len(vals)
    if mean == 0:
        return 0.0
    std = safe_std(vals)
    return round(std / mean, 4)


def parse_ts(ts_str: str) -> datetime:
    ts_str = ts_str.strip()
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.fromisoformat(ts_str[:26]).replace(tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GATE80 — Feature Engineering for unified traffic log"
    )
    parser.add_argument(
        "--input", type=str, default=None,
        help="Path to unified_traffic_log CSV. Auto-detects latest if omitted."
    )
    parser.add_argument(
        "--output", type=str,
        default="dataset/unified/output/gate80_dataset.csv",
        help="Output path for session-level feature dataset."
    )
    args = parser.parse_args()

    # Auto-detect latest log if not specified
    input_file = args.input
    if not input_file:
        pattern = "dataset/unified/output/unified_traffic_log_*.csv"
        files = sorted(glob.glob(pattern))
        if not files:
            print(f"[ERROR] No files found matching: {pattern}")
            sys.exit(1)
        input_file = files[-1]
        print(f"[AUTO] Using latest log: {input_file}")

    output_file = args.output
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"\n[1/3] Loading {input_file}...")
    with open(input_file, newline="", encoding="utf-8") as f:
        raw_rows = list(csv.DictReader(f))

    print(f"      {len(raw_rows):,} request rows loaded.")

    # Validate required columns
    required = {"session_id", "label", "session_type", "action",
                "status_code", "timestamp", "think_time_ms",
                "response_time_ms", "path", "endpoint_category",
                "is_failed_login"}
    missing = required - set(raw_rows[0].keys())
    if missing:
        print(f"[ERROR] Missing columns in input: {missing}")
        sys.exit(1)

    # ── Group by session ──────────────────────────────────────────────────────
    print("[2/3] Grouping requests by session_id...")
    sessions: dict[str, list] = defaultdict(list)
    for row in raw_rows:
        sessions[row["session_id"]].append(row)

    print(f"      {len(sessions):,} unique sessions found.")

    # ── Feature extraction ────────────────────────────────────────────────────
    print("[3/3] Extracting features...")
    output_rows = []
    skipped = 0

    for session_id, requests in sessions.items():

        # Sort by timestamp
        try:
            requests.sort(key=lambda r: parse_ts(r["timestamp"]))
        except Exception:
            pass

        # Skip only completely empty sessions — no behavioral signal at all
        # Note: we keep single-request sessions because some attack sessions
        # (e.g. failed sign-in attempts) are valid single-action sessions
        # that contribute meaningful features (failed_login_count, error_ratio)
        if len(requests) == 0:
            skipped += 1
            continue

        first = requests[0]

        # ── Identity ────────────────────────────────────────────────────────
        persona     = first.get("persona", "")
        geo         = first.get("geo_location", "")
        client_type = first.get("client_type", "")
        user_id     = first.get("user_id", "")
        email       = first.get("email", "")

        # ── Ground truth — take from first request (consistent within session)
        label        = first.get("label", "0")
        session_type = first.get("session_type", "normal")

        # ── Volume & rate ────────────────────────────────────────────────────
        total_requests = len(requests)

        try:
            t_start = parse_ts(requests[0]["timestamp"])
            t_end   = parse_ts(requests[-1]["timestamp"])
            duration_sec = max((t_end - t_start).total_seconds(), 0.0)
        except Exception:
            duration_sec = 0.0

        requests_per_minute = round(
            (total_requests / duration_sec * 60)
            if duration_sec > 0 else 0.0, 2
        )

        # ── Authentication signals ───────────────────────────────────────────
        actions = [r["action"] for r in requests]

        failed_login_count = sum(
            1 for r in requests
            if r["action"] in FAILED_LOGIN_ACTIONS
            or r.get("is_failed_login", "").lower() == "true"
        )

        # All sign-in attempts (both successful and failed)
        login_attempts = sum(
            1 for r in requests
            if r["action"] in SIGNIN_ACTIONS
            or r["action"] in FAILED_LOGIN_ACTIONS
            or r.get("is_failed_login", "").lower() == "true"
        )

        failed_login_ratio = round(
            failed_login_count / login_attempts
            if login_attempts > 0 else 0.0, 4
        )

        # Login success: any sign-in action that returned 200
        login_success = int(any(
            r["action"] in SIGNIN_ACTIONS and r["status_code"] == "200"
            for r in requests
        ))

        # ── Error signals ────────────────────────────────────────────────────
        status_codes = [r["status_code"] for r in requests]

        non_200_count = sum(1 for s in status_codes if s != "200")
        error_ratio   = round(
            non_200_count / total_requests, 4
        ) if total_requests > 0 else 0.0

        error_4xx = sum(1 for s in status_codes if s.startswith("4"))
        error_5xx = sum(1 for s in status_codes if s.startswith("5"))

        http_4xx_ratio = round(error_4xx / total_requests, 4)
        http_5xx_ratio = round(error_5xx / total_requests, 4)

        # ── Endpoint behavior ────────────────────────────────────────────────
        paths            = [r["path"] for r in requests]
        unique_endpoints = len(set(paths))
        path_counts      = list(Counter(paths).values())
        endpoint_entropy = shannon_entropy(path_counts)

        has_admin_access = int(
            any(r["endpoint_category"] == "admin" for r in requests)
        )
        admin_action_count = sum(
            1 for r in requests
            if r["action"] in ADMIN_ACTIONS
            or r["endpoint_category"] == "admin"
        )
        admin_ratio = round(
            admin_action_count / total_requests, 4
        )

        # ── Financial behavior ───────────────────────────────────────────────
        wallet_action_count = sum(
            1 for a in actions if a in WALLET_ACTIONS
        )
        wallet_action_ratio = round(
            wallet_action_count / total_requests, 4
        ) if total_requests > 0 else 0.0

        transfer_count = sum(1 for a in actions if a in TRANSFER_ACTIONS)
        topup_count    = sum(1 for a in actions if a in TOPUP_ACTIONS)
        withdraw_count = sum(1 for a in actions if a in WITHDRAW_ACTIONS)
        pay_bill_count = sum(1 for a in actions if a in PAYBILL_ACTIONS)

        # Financial errors: wallet operations that returned 400
        # (insufficient balance, self-transfer, etc.)
        financial_error_count = sum(
            1 for r in requests
            if r["action"] in WALLET_ACTIONS
            and r["status_code"] == "400"
        )

        # ── Timing behavior ──────────────────────────────────────────────────
        think_times = [
            int(r["think_time_ms"])
            for r in requests
            if r["think_time_ms"].strip().lstrip("-").isdigit()
            and int(r["think_time_ms"]) > 0
        ]
        response_times = [
            int(r["response_time_ms"])
            for r in requests
            if r["response_time_ms"].strip().lstrip("-").isdigit()
            and int(r["response_time_ms"]) >= 0
        ]

        avg_think_time_ms    = safe_mean(think_times)
        std_think_time_ms    = safe_std(think_times)
        min_think_time_ms    = min(think_times) if think_times else 0
        max_think_time_ms    = max(think_times) if think_times else 0
        think_time_cv        = coefficient_of_variation(think_times)
        avg_response_time_ms = safe_mean(response_times)

        # ── Assemble row ─────────────────────────────────────────────────────
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
            "login_attempts":        login_attempts,
            "failed_login_ratio":    failed_login_ratio,
            "login_success":         login_success,
            "error_ratio":           error_ratio,
            "error_4xx_count":       error_4xx,
            "error_5xx_count":       error_5xx,
            "http_4xx_ratio":        http_4xx_ratio,
            "http_5xx_ratio":        http_5xx_ratio,
            "unique_endpoints":      unique_endpoints,
            "endpoint_entropy":      endpoint_entropy,
            "has_admin_access":      has_admin_access,
            "admin_action_count":    admin_action_count,
            "admin_ratio":           admin_ratio,
            "wallet_action_count":   wallet_action_count,
            "wallet_action_ratio":   wallet_action_ratio,
            "transfer_count":        transfer_count,
            "topup_count":           topup_count,
            "withdraw_count":        withdraw_count,
            "pay_bill_count":        pay_bill_count,
            "financial_error_count": financial_error_count,
            "avg_think_time_ms":     avg_think_time_ms,
            "std_think_time_ms":     std_think_time_ms,
            "min_think_time_ms":     min_think_time_ms,
            "max_think_time_ms":     max_think_time_ms,
            "think_time_cv":         think_time_cv,
            "avg_response_time_ms":  avg_response_time_ms,
            "label":                 label,
            "session_type":          session_type,
        })

    # ── Write output ──────────────────────────────────────────────────────────
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(output_rows)

    # ── Summary ───────────────────────────────────────────────────────────────
    normal_rows   = [r for r in output_rows if str(r["label"]) == "0"]
    abnormal_rows = [r for r in output_rows if str(r["label"]) == "1"]

    attack_counts = Counter(r["session_type"] for r in abnormal_rows)

    print(f"\n{'='*70}")
    print(f"  ✅ Done! {len(output_rows):,} sessions written to:")
    print(f"     {output_file}")
    print(f"{'='*70}")
    print(f"\n  Label distribution:")
    print(f"    label=0  normal   : {len(normal_rows):,} "
          f"({len(normal_rows)/len(output_rows)*100:.1f}%)")
    print(f"    label=1  abnormal : {len(abnormal_rows):,} "
          f"({len(abnormal_rows)/len(output_rows)*100:.1f}%)")
    print(f"\n  Abnormal breakdown:")
    for atype, count in sorted(attack_counts.items()):
        print(f"    {atype:<25} {count:>5}")
    print(f"\n  Sessions skipped (≤1 request): {skipped}")
    print(f"  Features: {len(OUTPUT_COLUMNS) - 8} behavioral "
          f"+ 6 identity/label columns = {len(OUTPUT_COLUMNS)} total")

    print(f"\n  Feature sanity check (abnormal vs normal means):")
    def mean_feature(rows, col):
        vals = [float(r[col]) for r in rows if str(r[col]).replace('.','').lstrip('-').isdigit()]
        return safe_mean(vals)

    check_features = [
        "failed_login_count", "failed_login_ratio", "requests_per_minute",
        "wallet_action_ratio", "unique_endpoints", "think_time_cv",
        "admin_action_count",
    ]
    print(f"  {'Feature':<28} {'Normal':>10} {'Abnormal':>10}")
    print(f"  {'-'*50}")
    for feat in check_features:
        n_mean = mean_feature(normal_rows, feat)
        a_mean = mean_feature(abnormal_rows, feat)
        print(f"  {feat:<28} {n_mean:>10.3f} {a_mean:>10.3f}")

    print(f"\n  Next step: run dataset/unified/split_dataset.py")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()