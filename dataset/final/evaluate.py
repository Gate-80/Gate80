"""
GATE80 — Stress Test Evaluator
dataset/final/evaluate.py

Evaluates the trained model against the stress test dataset
without retraining. Loads existing model/scaler and scores
stress test sessions.

Usage:
    python3 -m dataset.final.evaluate dataset/final/output/sessions_YYYYMMDD_HHMMSS.csv
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

FEATURE_NAMES = [
    "total_requests", "session_duration_sec",
    "requests_per_minute", "requests_per_second",
    "error_ratio", "error_count",
    "http_4xx_ratio", "http_5xx_ratio",
    "failed_login_count", "login_attempts", "failed_login_ratio",
    "unique_endpoints", "endpoint_entropy",
    "admin_action_count", "admin_ratio", "has_admin_access",
    "wallet_action_ratio", "transfer_count", "topup_count",
    "withdraw_count", "pay_bill_count", "financial_error_count",
    "avg_think_time_ms", "std_think_time_ms",
    "min_think_time_ms", "max_think_time_ms", "think_time_cv",
    "avg_response_time_ms",
]

ATTACK_TYPES = [
    "credential_attack", "financial_fraud",
    "endpoint_scanning", "account_creation",
]

MODEL_DIR = Path("model")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m dataset.final.evaluate <stress_test_sessions_csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        sys.exit(1)

    # ── Load model — do not retrain ───────────────────────────────────────────
    print("Loading trained model...")
    rf     = joblib.load(MODEL_DIR / "random_forest.pkl")
    iso    = joblib.load(MODEL_DIR / "isolation_forest.pkl")
    scaler = joblib.load(MODEL_DIR / "scaler.pkl")
    print("  ✅ random_forest.pkl, isolation_forest.pkl, scaler.pkl loaded")

    # ── Load stress test sessions ─────────────────────────────────────────────
    print(f"\nLoading stress test: {input_path}")
    df = pd.read_csv(input_path)
    print(f"  {len(df)} sessions | "
          f"{df['label'].sum()} abnormal | "
          f"{(df['label']==0).sum()} normal")

    X = df[FEATURE_NAMES].copy()
    y = df["label"].values
    X_scaled = scaler.transform(X)

    # ── Random Forest evaluation ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  RANDOM FOREST — Stress Test Evaluation")
    print("=" * 60)

    rf_preds = rf.predict(X_scaled)
    rf_f1    = f1_score(y, rf_preds, zero_division=0)
    rf_pre   = precision_score(y, rf_preds, zero_division=0)
    rf_rec   = recall_score(y, rf_preds, zero_division=0)
    fpr      = float((rf_preds[y == 0] == 1).mean())

    print(f"\n  Precision : {rf_pre:.4f}  ({rf_pre*100:.1f}%)")
    print(f"  Recall    : {rf_rec:.4f}  ({rf_rec*100:.1f}%)")
    print(f"  F1        : {rf_f1:.4f}  ({rf_f1*100:.1f}%)")
    print(f"  FPR       : {fpr:.4f}  ({fpr*100:.1f}%)")

    cm = confusion_matrix(y, rf_preds)
    print(f"\n  Confusion matrix:")
    print(f"    {'':20} Pred Normal  Pred Abnormal")
    print(f"    {'Actual Normal':<20} {cm[0][0]:>11}  {cm[0][1]:>13}")
    print(f"    {'Actual Abnormal':<20} {cm[1][0]:>11}  {cm[1][1]:>13}")

    # ── Per-attack-type ───────────────────────────────────────────────────────
    print(f"\n  Per-attack-type (RF):")
    df["pred"] = rf_preds
    for atype in ATTACK_TYPES:
        mask = df["attack_type"] == atype
        if mask.sum() == 0:
            continue
        sub_true = df.loc[mask, "label"].values
        sub_pred = df.loc[mask, "pred"].values
        p = precision_score(sub_true, sub_pred, zero_division=0)
        r = recall_score(sub_true, sub_pred, zero_division=0)
        f = f1_score(sub_true, sub_pred, zero_division=0)
        print(f"  {atype:<25} P={p:.3f}  R={r:.3f}  F1={f:.3f}  (n={mask.sum()})")

    # ── Isolation Forest evaluation ───────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ISOLATION FOREST — Stress Test Evaluation")
    print("=" * 60)

    iso_preds_raw = iso.predict(X_scaled)
    iso_preds = (iso_preds_raw == -1).astype(int)
    iso_f1  = f1_score(y, iso_preds, zero_division=0)
    iso_pre = precision_score(y, iso_preds, zero_division=0)
    iso_rec = recall_score(y, iso_preds, zero_division=0)

    print(f"\n  Precision : {iso_pre:.4f}  ({iso_pre*100:.1f}%)")
    print(f"  Recall    : {iso_rec:.4f}  ({iso_rec*100:.1f}%)")
    print(f"  F1        : {iso_f1:.4f}  ({iso_f1*100:.1f}%)")

    # ── Save report ───────────────────────────────────────────────────────────
    report = MODEL_DIR / "stress_test_report.txt"
    with open(report, "w") as f:
        f.write("GATE80 Stress Test Evaluation Report\n")
        f.write(f"Input: {input_path}\n")
        f.write(f"Sessions: {len(df)} | "
                f"Normal: {(y==0).sum()} | Abnormal: {y.sum()}\n\n")
        f.write("Random Forest\n")
        f.write(f"  Precision : {rf_pre:.4f}\n")
        f.write(f"  Recall    : {rf_rec:.4f}\n")
        f.write(f"  F1        : {rf_f1:.4f}\n")
        f.write(f"  FPR       : {fpr:.4f}\n\n")
        f.write("Isolation Forest\n")
        f.write(f"  Precision : {iso_pre:.4f}\n")
        f.write(f"  Recall    : {iso_rec:.4f}\n")
        f.write(f"  F1        : {iso_f1:.4f}\n\n")
        f.write("Per-attack-type (RF):\n")
        for atype in ATTACK_TYPES:
            mask = df["attack_type"] == atype
            if mask.sum() == 0:
                continue
            sub_true = df.loc[mask, "label"].values
            sub_pred = df.loc[mask, "pred"].values
            p = precision_score(sub_true, sub_pred, zero_division=0)
            r = recall_score(sub_true, sub_pred, zero_division=0)
            fi = f1_score(sub_true, sub_pred, zero_division=0)
            f.write(f"  {atype:<25} P={p:.3f}  R={r:.3f}  F1={fi:.3f}  "
                    f"(n={mask.sum()})\n")
        f.write("\nFull classification report:\n")
        f.write(classification_report(y, rf_preds,
                target_names=["normal", "abnormal"], zero_division=0))

    print(f"\n  ✅ Report saved → {report}")


if __name__ == "__main__":
    main()