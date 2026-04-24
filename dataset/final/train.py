"""
GATE80 — Model Training Script
dataset/final/train.py

Trains two models:
  1. Isolation Forest  — unsupervised, trains on normal sessions only
  2. Random Forest     — supervised, trains on all sessions (binary labels)

Both models are saved to model/ directory for use by the proxy detector.

Usage:
    python3 -m dataset.final.train dataset/final/output/sessions_YYYYMMDD_HHMMSS.csv

Output:
    model/isolation_forest.pkl
    model/scaler.pkl
    model/random_forest.pkl
    model/training_report.txt
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler

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

ATTACK_TYPES = [
    "normal",
    "credential_attack",
    "financial_fraud",
    "endpoint_scanning",
    "account_creation",
]

MODEL_DIR = Path("model")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m dataset.final.train <sessions_csv>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        sys.exit(1)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("  GATE80 Model Training")
    print(f"  Input  : {input_path}")
    print(f"  Output : {MODEL_DIR}/")
    print("=" * 70)

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"\n[1/6] Loading dataset...")
    df = pd.read_csv(input_path)
    print(f"  {len(df):,} sessions | {df['label'].sum()} abnormal | "
          f"{(df['label']==0).sum()} normal")

    X = df[FEATURE_NAMES].copy()
    y = df["label"].values

    # ── Scale ─────────────────────────────────────────────────────────────────
    print("\n[2/6] Fitting StandardScaler on all sessions...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")
    print("  ✅ scaler.pkl saved")

    # ── Train/test split ──────────────────────────────────────────────────────
    # 80/20 stratified split
    # Stratification ensures attack type proportions preserved in both sets
    print("\n[3/6] Stratified 80/20 train/test split (seed=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )
    print(f"  Train: {len(X_train)} sessions "
          f"({y_train.sum()} abnormal, {(y_train==0).sum()} normal)")
    print(f"  Test : {len(X_test)} sessions "
          f"({y_test.sum()} abnormal, {(y_test==0).sum()} normal)")

    # ── Isolation Forest ──────────────────────────────────────────────────────
    # Trains on normal sessions only — unsupervised baseline
    # contamination=0.05 per Benova & Hudec Sensors 2024
    # DOI: 10.3390/s24010119
    print("\n[4/6] Training Isolation Forest (normal sessions only)...")
    X_train_normal = X_scaled[y == 0]
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.05,   # 5% expected anomaly rate
                              # Source: Benova & Hudec Sensors 2024
                              # DOI: 10.3390/s24010119
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train_normal)
    joblib.dump(iso, MODEL_DIR / "isolation_forest.pkl")
    print("  ✅ isolation_forest.pkl saved")

    # Evaluate IF on test set
    iso_preds_raw = iso.predict(X_test)
    # IsolationForest returns -1 for anomaly, 1 for normal
    iso_preds = (iso_preds_raw == -1).astype(int)
    iso_f1  = f1_score(y_test, iso_preds, zero_division=0)
    iso_pre = precision_score(y_test, iso_preds, zero_division=0)
    iso_rec = recall_score(y_test, iso_preds, zero_division=0)
    print(f"  IF  Precision : {iso_pre:.4f}")
    print(f"  IF  Recall    : {iso_rec:.4f}")
    print(f"  IF  F1        : {iso_f1:.4f}")

    # ── Random Forest ─────────────────────────────────────────────────────────
    # Supervised binary classifier — 0 = normal, 1 = abnormal
    # class_weight='balanced' handles 87/13 imbalance
    # Source for imbalance handling: Doddamani et al. I2CT 2024
    # DOI: 10.1109/I2CT61223.2024.10544197
    print("\n[5/6] Training Random Forest (all sessions, binary labels)...")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",  # handles 87/13 imbalance
                                  # Source: Doddamani et al. I2CT 2024
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, MODEL_DIR / "random_forest.pkl")
    print("  ✅ random_forest.pkl saved")

    # RF predictions
    rf_preds  = rf.predict(X_test)
    rf_proba  = rf.predict_proba(X_test)[:, 1]
    rf_f1     = f1_score(y_test, rf_preds, zero_division=0)
    rf_pre    = precision_score(y_test, rf_preds, zero_division=0)
    rf_rec    = recall_score(y_test, rf_preds, zero_division=0)
    fpr       = float((rf_preds[y_test == 0] == 1).mean())

    print(f"  RF  Precision : {rf_pre:.4f}")
    print(f"  RF  Recall    : {rf_rec:.4f}")
    print(f"  RF  F1        : {rf_f1:.4f}")
    print(f"  RF  FPR       : {fpr:.4f}")

    # ── Per-attack-type breakdown ─────────────────────────────────────────────
    print("\n[6/6] Per-attack-type evaluation...")
    df_test = df.iloc[
        train_test_split(
            np.arange(len(df)), test_size=0.20,
            random_state=42, stratify=y
        )[1]
    ].copy()
    df_test["pred"] = rf_preds

    attack_results = {}
    for atype in ATTACK_TYPES:
        if atype == "normal":
            continue
        mask = df_test["attack_type"] == atype
        if mask.sum() == 0:
            continue
        sub_true = df_test.loc[mask, "label"].values
        sub_pred = df_test.loc[mask, "pred"].values
        attack_results[atype] = {
            "count":     int(mask.sum()),
            "precision": float(precision_score(sub_true, sub_pred, zero_division=0)),
            "recall":    float(recall_score(sub_true, sub_pred, zero_division=0)),
            "f1":        float(f1_score(sub_true, sub_pred, zero_division=0)),
        }
        print(f"  {atype:<25} "
              f"P={attack_results[atype]['precision']:.3f}  "
              f"R={attack_results[atype]['recall']:.3f}  "
              f"F1={attack_results[atype]['f1']:.3f}  "
              f"(n={attack_results[atype]['count']})")

    # ── 5-fold cross-validation ───────────────────────────────────────────────
    print("\n  5-fold stratified cross-validation (RF)...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(
        RandomForestClassifier(
            n_estimators=300, class_weight="balanced",
            random_state=42, n_jobs=-1
        ),
        X_scaled, y, cv=cv, scoring="f1", n_jobs=-1,
    )
    print(f"  CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Feature importance ────────────────────────────────────────────────────
    importances = pd.Series(rf.feature_importances_, index=FEATURE_NAMES)
    importances = importances.sort_values(ascending=False)
    print("\n  Top 10 feature importances (RF):")
    for feat, imp in importances.head(10).items():
        bar = "█" * int(imp * 200)
        print(f"    {feat:<30} {imp:.4f}  {bar}")

    # ── Confusion matrix ──────────────────────────────────────────────────────
    cm = confusion_matrix(y_test, rf_preds)
    print("\n  Confusion matrix (RF):")
    print(f"    {'':20} Pred Normal  Pred Abnormal")
    print(f"    {'Actual Normal':<20} {cm[0][0]:>11}  {cm[0][1]:>13}")
    print(f"    {'Actual Abnormal':<20} {cm[1][0]:>11}  {cm[1][1]:>13}")

    # ── Save training report ──────────────────────────────────────────────────
    ts     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report = MODEL_DIR / "training_report.txt"
    with open(report, "w") as f:
        f.write(f"GATE80 Training Report — {ts}\n")
        f.write(f"Input: {input_path}\n")
        f.write(f"Sessions: {len(df)} total | {(y==0).sum()} normal | {y.sum()} abnormal\n\n")
        f.write(f"Isolation Forest\n")
        f.write(f"  Precision : {iso_pre:.4f}\n")
        f.write(f"  Recall    : {iso_rec:.4f}\n")
        f.write(f"  F1        : {iso_f1:.4f}\n\n")
        f.write(f"Random Forest\n")
        f.write(f"  Precision : {rf_pre:.4f}\n")
        f.write(f"  Recall    : {rf_rec:.4f}\n")
        f.write(f"  F1        : {rf_f1:.4f}\n")
        f.write(f"  FPR       : {fpr:.4f}\n\n")
        f.write(f"5-Fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n\n")
        f.write("Per-attack-type:\n")
        for atype, res in attack_results.items():
            f.write(f"  {atype:<25} "
                    f"P={res['precision']:.3f}  "
                    f"R={res['recall']:.3f}  "
                    f"F1={res['f1']:.3f}\n")
        f.write("\nTop 10 features:\n")
        for feat, imp in importances.head(10).items():
            f.write(f"  {feat:<30} {imp:.4f}\n")
        f.write("\nConfusion Matrix:\n")
        f.write(f"  TN={cm[0][0]}  FP={cm[0][1]}  FN={cm[1][0]}  TP={cm[1][1]}\n")
        f.write("\nFull classification report (RF):\n")
        f.write(classification_report(y_test, rf_preds,
                target_names=["normal", "abnormal"], zero_division=0))

    print(f"\n  ✅ training_report.txt saved → {report}")
    print("\n" + "=" * 70)
    print("  Models saved:")
    print(f"    model/scaler.pkl")
    print(f"    model/isolation_forest.pkl")
    print(f"    model/random_forest.pkl")
    print(f"    model/training_report.txt")
    print("=" * 70)


if __name__ == "__main__":
    main()