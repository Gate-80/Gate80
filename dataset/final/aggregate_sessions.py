"""
GATE80 — Session Aggregator
dataset/final/aggregate_sessions.py

Reads request-level CSV from generate_requests.py and aggregates
each session into 28 session-level features matching
detection/model.py FEATURE_NAMES exactly.

Input columns:
    timestamp, session_id, user_id, email, geo_location, client_type,
    method, path, status_code, response_time_ms, think_time_ms,
    label, attack_type

Usage:
    python3 -m dataset.final.aggregate_sessions dataset/final/output/requests_YYYYMMDD_HHMMSS.csv

Output:
    dataset/final/output/sessions_{RUN_ID}.csv       — all sessions unified
    dataset/final/output/baseline_sessions.csv       — normal only (IF training)
    dataset/final/output/abnormal_sessions.csv       — attacks only (evaluation)
"""

import math
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# Feature names — must match detection/model.py FEATURE_NAMES exactly
# ─────────────────────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "total_requests",
    "session_duration_sec",
    "requests_per_minute",
    "requests_per_second",
    "error_ratio",
    "error_count",
    "http_4xx_ratio",
    "http_5xx_ratio",
    "failed_login_count",
    "login_attempts",
    "failed_login_ratio",
    "unique_endpoints",
    "endpoint_entropy",
    "admin_action_count",
    "admin_ratio",
    "has_admin_access",
    "wallet_action_ratio",
    "transfer_count",
    "topup_count",
    "withdraw_count",
    "pay_bill_count",
    "financial_error_count",
    "avg_think_time_ms",
    "std_think_time_ms",
    "min_think_time_ms",
    "max_think_time_ms",
    "think_time_cv",
    "avg_response_time_ms",
]


# ─────────────────────────────────────────────────────────────────────────────
# Path helpers — derived from path column
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_path(path: str) -> str:
    """
    Collapse dynamic segments so /users/u_1234/wallet and
    /users/u_5678/wallet count as the same endpoint.
    """
    import re
    path = str(path)
    path = re.sub(r"/[a-zA-Z]{1,4}_\d{4,}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    return path.rstrip("/") or "/"


def _is_login(path: str) -> bool:
    return "sign-in" in path or "sign-up" in path

def _is_admin(path: str) -> bool:
    return "/admin" in path

def _is_wallet(path: str) -> bool:
    return "/wallet" in path

def _is_transfer(path: str) -> bool:
    return "transfer" in path

def _is_topup(path: str) -> bool:
    return "topup" in path

def _is_withdraw(path: str) -> bool:
    return "withdraw" in path

def _is_pay_bill(path: str) -> bool:
    return "pay-bill" in path


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(series: pd.Series) -> float:
    """
    Shannon entropy of endpoint distribution.
    Sequence probability < 0.05 separates 98.06% of bots from humans.
    Source: Oikonomou & Mirkovic IEEE ICC 2009, p. 4
      DOI: 10.1109/ICC.2009.5199191
    """
    counts = series.value_counts()
    total  = counts.sum()
    if total == 0:
        return 0.0
    probs = counts / total
    return float(-np.sum(probs * np.log2(probs + 1e-10)))


# ─────────────────────────────────────────────────────────────────────────────
# Per-session aggregation
# ─────────────────────────────────────────────────────────────────────────────

def aggregate_session(grp: pd.DataFrame) -> dict:

    n = len(grp)

    # ── Session duration from timestamps ──────────────────────────────────────
    try:
        ts = pd.to_datetime(grp["timestamp"], utc=True)
        duration_sec = max((ts.max() - ts.min()).total_seconds(), 1.0)
    except Exception:
        # Fallback: sum of think times
        duration_sec = max(grp["think_time_ms"].sum() / 1000.0, 1.0)

    # ── Request rates ─────────────────────────────────────────────────────────
    rpm = (n / duration_sec) * 60.0
    rps =  n / duration_sec

    # ── Status codes ──────────────────────────────────────────────────────────
    status = pd.to_numeric(grp["status_code"], errors="coerce").fillna(0)
    count_4xx   = int(((status >= 400) & (status < 500)).sum())
    count_5xx   = int((status >= 500).sum())
    error_count = int((status >= 400).sum())

    # error_ratio: ~4% for normal, >20% for scanners
    # Source: Balla et al. ICT 2011, p. 429
    # DOI: 10.1109/CTS.2011.5898963
    error_ratio    = error_count / n
    http_4xx_ratio = count_4xx / n
    http_5xx_ratio = count_5xx / n

    # ── Login signals ─────────────────────────────────────────────────────────
    # Detect from path column
    login_mask  = grp["path"].apply(_is_login)
    login_attempts     = int(login_mask.sum())
    failed_login_count = int(
        (login_mask & (status >= 400)).sum()
    )
    # failed_login_ratio
    # Normal human: < 0.5  Attack: > 0.80
    # Source: NIST SP 800-63B §5.2.3
    #         Alsaleh et al. TDSC 2012, p. 128 DOI: 10.1109/TDSC.2011.24
    failed_login_ratio = (
        failed_login_count / login_attempts
        if login_attempts > 0 else 0.0
    )

    # ── Endpoint behavior ─────────────────────────────────────────────────────
    norm_paths  = grp["path"].apply(_normalise_path)
    unique_ep   = int(norm_paths.nunique())

    # endpoint_entropy
    # Source: Oikonomou & Mirkovic ICC 2009, p. 4
    ep_entropy  = _shannon_entropy(norm_paths)

    # admin signals
    # Source: OWASP ATH v1.3 OAT-014
    admin_mask       = grp["path"].apply(_is_admin)
    admin_count      = int(admin_mask.sum())
    admin_ratio      = admin_count / n
    has_admin_access = float(
        int((admin_mask & (status < 400)).any())
    )

    # ── Wallet / financial ────────────────────────────────────────────────────
    # wallet_action_ratio: [CALIBRATED] — no published threshold
    # Directional: OWASP ATH v1.3 OAT-012
    # See docs/references.md §gaps
    wallet_mask   = grp["path"].apply(_is_wallet)
    wallet_count  = int(wallet_mask.sum())
    wallet_ratio  = wallet_count / n

    transfer_count = int(grp["path"].apply(_is_transfer).sum())
    topup_count    = int(grp["path"].apply(_is_topup).sum())
    withdraw_count = int(grp["path"].apply(_is_withdraw).sum())
    pay_bill_count = int(grp["path"].apply(_is_pay_bill).sum())

    # financial_error_count: errors on wallet endpoints specifically
    financial_error_count = int(
        (wallet_mask & (status >= 400)).sum()
    )

    # ── Timing ────────────────────────────────────────────────────────────────
    # Exclude zero think times (first request of session has no prior gap)
    think_raw  = grp["think_time_ms"].values.astype(float)
    think_vals = think_raw[think_raw > 0]

    # avg_think_time_ms
    # Bot: 17–100 ms   Human: 6,300–60,100 ms
    # Source: Oikonomou & Mirkovic ICC 2009, Fig. 1
    # DOI: 10.1109/ICC.2009.5199191
    avg_think = float(np.mean(think_vals))   if len(think_vals) > 0 else 0.0
    std_think = float(np.std(think_vals))    if len(think_vals) > 1 else 0.0
    min_think = float(np.min(think_vals))    if len(think_vals) > 0 else 0.0
    max_think = float(np.max(think_vals))    if len(think_vals) > 0 else 0.0

    # think_time_cv = std / mean
    # Bot CV < 0.3 (near-periodic)   Human CV > 1.5 (dispersed)
    # Source: Derived from Oikonomou & Mirkovic ICC 2009
    cv_think = (std_think / avg_think) if avg_think > 0 else 0.0

    # ── Response time ─────────────────────────────────────────────────────────
    resp_vals = grp["response_time_ms"].values.astype(float)
    avg_resp  = float(np.mean(resp_vals)) if len(resp_vals) > 0 else 0.0

    # ── Metadata ──────────────────────────────────────────────────────────────
    label       = int(grp["label"].max())
    attack_type = grp["attack_type"].iloc[0]
    session_id  = grp["session_id"].iloc[0]
    user_id     = grp["user_id"].iloc[0]
    email       = grp["email"].iloc[0]
    geo         = grp["geo_location"].iloc[0]
    ct          = grp["client_type"].iloc[0]

    return {
        "session_id":           session_id,
        "user_id":              user_id,
        "email":                email,
        "geo_location":         geo,
        "client_type":          ct,
        # 28 features
        "total_requests":       n,
        "session_duration_sec": round(duration_sec, 4),
        "requests_per_minute":  round(rpm, 4),
        "requests_per_second":  round(rps, 4),
        "error_ratio":          round(error_ratio, 4),
        "error_count":          error_count,
        "http_4xx_ratio":       round(http_4xx_ratio, 4),
        "http_5xx_ratio":       round(http_5xx_ratio, 4),
        "failed_login_count":   failed_login_count,
        "login_attempts":       login_attempts,
        "failed_login_ratio":   round(failed_login_ratio, 4),
        "unique_endpoints":     unique_ep,
        "endpoint_entropy":     round(ep_entropy, 4),
        "admin_action_count":   admin_count,
        "admin_ratio":          round(admin_ratio, 4),
        "has_admin_access":     has_admin_access,
        "wallet_action_ratio":  round(wallet_ratio, 4),
        "transfer_count":       transfer_count,
        "topup_count":          topup_count,
        "withdraw_count":       withdraw_count,
        "pay_bill_count":       pay_bill_count,
        "financial_error_count": financial_error_count,
        "avg_think_time_ms":    round(avg_think, 4),
        "std_think_time_ms":    round(std_think, 4),
        "min_think_time_ms":    round(min_think, 4),
        "max_think_time_ms":    round(max_think, 4),
        "think_time_cv":        round(cv_think, 4),
        "avg_response_time_ms": round(avg_resp, 4),
        # Labels
        "label":                label,
        "attack_type":          attack_type,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m dataset.final.aggregate_sessions <requests_csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        sys.exit(1)

    print(f"Reading {input_path} ...")
    df = pd.read_csv(input_path)
    print(f"  {len(df):,} requests | {df['session_id'].nunique():,} sessions")

    # ── Aggregate ─────────────────────────────────────────────────────────────
    print("Aggregating sessions...")
    records = [
        aggregate_session(grp)
        for _, grp in df.groupby("session_id")
    ]
    sessions = pd.DataFrame(records)

    # ── Column order ──────────────────────────────────────────────────────────
    meta     = ["session_id", "user_id", "email", "geo_location", "client_type"]
    col_order = meta + FEATURE_NAMES + ["label", "attack_type"]
    sessions  = sessions[col_order]

    # ── Output ────────────────────────────────────────────────────────────────
    out_dir  = Path("dataset/final/output")
    out_dir.mkdir(parents=True, exist_ok=True)

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unified  = out_dir / f"sessions_{ts}.csv"
    baseline = out_dir / "baseline_sessions.csv"
    abnormal = out_dir / "abnormal_sessions.csv"

    sessions.to_csv(unified, index=False)

    # Normal only — no label/attack_type — for Isolation Forest training
    normal_df = sessions[sessions["label"] == 0][meta + FEATURE_NAMES]
    normal_df.to_csv(baseline, index=False)

    # Attacks only — for evaluation
    attack_df = sessions[sessions["label"] == 1]
    attack_df.to_csv(abnormal, index=False)

    # ── Report ────────────────────────────────────────────────────────────────
    total = len(sessions)
    n_cnt = len(normal_df)
    a_cnt = len(attack_df)

    print()
    print(f"✅ sessions_{ts}.csv      → {total} sessions")
    print(f"✅ baseline_sessions.csv  → {n_cnt} normal sessions")
    print(f"✅ abnormal_sessions.csv  → {a_cnt} attack sessions")
    print()
    print("Label split:")
    print(f"  Normal   : {n_cnt:>5}  ({n_cnt/total*100:.1f}%)")
    print(f"  Abnormal : {a_cnt:>5}  ({a_cnt/total*100:.1f}%)")
    print()
    print("Attack type breakdown:")
    for atype, cnt in sessions["attack_type"].value_counts().items():
        print(f"  {atype:<25}: {cnt:>4}  ({cnt/total*100:.1f}%)")
    print()

    # ── Sanity check ──────────────────────────────────────────────────────────
    print("Feature sanity check — mean by label:")
    key_features = [
        "avg_think_time_ms", "think_time_cv",
        "failed_login_ratio", "error_ratio",
        "http_4xx_ratio", "admin_action_count",
        "wallet_action_ratio", "requests_per_minute",
    ]
    print(sessions.groupby("label")[key_features].mean().round(3).to_string())
    print()
    print(f"Next: python3 -m dataset.final.train {unified}")


if __name__ == "__main__":
    main()