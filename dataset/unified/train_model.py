"""
GATE80 - Model Training
dataset/unified/train_model.py

Trains two models on gate80_train.csv:

1. Random Forest (primary - supervised)
   - Uses labels during training
   - class_weight='balanced' handles 86.6/13.4 imbalance
   - Reference: ScienceDirect anomaly detection paper (2023)
     RF achieved F2=97.68%, AUC=98.47% on UNSW-NB15

2. Isolation Forest (comparison - unsupervised)
   - Does NOT use labels during training
   - Trained on normal sessions only (label=0) to learn normal behavior
   - Evaluated against true labels at test time
   - Represents the baseline approach used before labeled data was available

Both models saved to model/unified/

Run:
    python dataset/unified/train_model.py
"""

import csv
import os
import pickle
import json
from collections import Counter

# Feature columns used for training
# Excludes identity columns and label columns
FEATURE_COLUMNS = [
    # Volume & rate
    "total_requests", "session_duration_sec", "requests_per_minute",
    # Authentication signals
    "failed_login_count", "login_attempts", "failed_login_ratio", "login_success",
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
]

TRAIN_FILE  = "dataset/unified/output/gate80_train.csv"
OUTPUT_DIR  = "model/unified"
RF_PATH     = f"{OUTPUT_DIR}/random_forest.pkl"
IF_PATH     = f"{OUTPUT_DIR}/isolation_forest.pkl"
META_PATH   = f"{OUTPUT_DIR}/model_meta.json"


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def to_float(rows, feature_cols):
    X, y = [], []
    for row in rows:
        try:
            features = [float(row[col]) for col in feature_cols]
            label    = int(row["label"])
            X.append(features)
            y.append(label)
        except (ValueError, KeyError):
            continue
    return X, y


def main():
    # ── Imports ───────────────────────────────────────────────────────────────
    try:
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        print("[ERROR] scikit-learn not installed.")
        print("        Run: pip install scikit-learn")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Load training data ────────────────────────────────────────────────────
    print(f"[1/5] Loading {TRAIN_FILE}...")
    if not os.path.exists(TRAIN_FILE):
        print(f"[ERROR] File not found: {TRAIN_FILE}")
        return

    train_rows = load_csv(TRAIN_FILE)
    print(f"      {len(train_rows):,} sessions loaded.")

    X_train, y_train = to_float(train_rows, FEATURE_COLUMNS)
    print(f"      {len(X_train):,} valid rows after parsing.")

    label_counts = Counter(y_train)
    print(f"      label=0 normal   : {label_counts[0]:,}")
    print(f"      label=1 abnormal : {label_counts[1]:,}")

    # ── Scale features ────────────────────────────────────────────────────────
    # StandardScaler normalizes features to zero mean and unit variance.
    # Required for Isolation Forest. Random Forest doesn't need it but
    # using the same scaled features keeps evaluation consistent.
    print("\n[2/5] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # Save scaler
    scaler_path = f"{OUTPUT_DIR}/scaler.pkl"
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    print(f"      Scaler saved to {scaler_path}")

    # ── Train Random Forest ───────────────────────────────────────────────────
    # n_estimators=200: more trees = more stable predictions
    # class_weight='balanced': automatically weights minority class higher
    #   weight for label=1 = (n_samples / (2 * n_abnormal))
    #   weight for label=0 = (n_samples / (2 * n_normal))
    # max_depth=None: trees grow until pure leaves (can tune later)
    # min_samples_leaf=2: prevents overfitting on very small leaf nodes
    # random_state=42: reproducibility
    print("\n[3/5] Training Random Forest (supervised)...")
    print("      n_estimators=200, class_weight='balanced', random_state=42")

    rf = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,  # use all CPU cores
    )
    rf.fit(X_train_scaled, y_train)

    with open(RF_PATH, "wb") as f:
        pickle.dump(rf, f)
    print(f"      Random Forest saved to {RF_PATH}")

    # Feature importance from RF
    importances = list(zip(FEATURE_COLUMNS, rf.feature_importances_))
    importances.sort(key=lambda x: x[1], reverse=True)
    print("\n      Top 10 features by importance:")
    for feat, imp in importances[:10]:
        bar = "█" * int(imp * 200)
        print(f"        {feat:<30} {imp:.4f} {bar}")

    # ── Train Isolation Forest ────────────────────────────────────────────────
    # Trained ONLY on normal sessions (label=0) to learn normal behavior.
    # contamination='auto': IF internally estimates contamination.
    # At evaluation time, IF predictions are compared to true labels.
    # This is the correct unsupervised evaluation methodology --
    # training on normal only, then detecting deviations at test time.
    print("\n[4/5] Training Isolation Forest (unsupervised, normal sessions only)...")

    normal_rows = [row for row in train_rows if row.get("label") == "0"]
    X_normal, _ = to_float(normal_rows, FEATURE_COLUMNS)
    X_normal_scaled = scaler.transform(X_normal)

    print(f"      Training on {len(X_normal):,} normal sessions only.")
    print("      n_estimators=200, contamination='auto', random_state=42")

    iso = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_normal_scaled)

    with open(IF_PATH, "wb") as f:
        pickle.dump(iso, f)
    print(f"      Isolation Forest saved to {IF_PATH}")

    # ── Save metadata ─────────────────────────────────────────────────────────
    print("\n[5/5] Saving metadata...")
    meta = {
        "feature_columns": FEATURE_COLUMNS,
        "n_features": len(FEATURE_COLUMNS),
        "train_sessions": len(X_train),
        "train_normal": label_counts[0],
        "train_abnormal": label_counts[1],
        "random_forest": {
            "path": RF_PATH,
            "n_estimators": 200,
            "class_weight": "balanced",
            "min_samples_leaf": 2,
            "random_state": 42,
        },
        "isolation_forest": {
            "path": IF_PATH,
            "n_estimators": 200,
            "contamination": "auto",
            "trained_on": "normal_sessions_only",
            "random_state": 42,
        },
        "scaler": {
            "path": scaler_path,
            "type": "StandardScaler",
        },
        "feature_importance": [
            {"feature": feat, "importance": round(float(imp), 6)}
            for feat, imp in importances
        ],
    }

    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"      Metadata saved to {META_PATH}")

    print(f"\n{'='*60}")
    print(f"  Training complete.")
    print(f"  Models saved to: {OUTPUT_DIR}/")
    print(f"    random_forest.pkl")
    print(f"    isolation_forest.pkl")
    print(f"    scaler.pkl")
    print(f"    model_meta.json")
    print(f"\n  Next step: python dataset/unified/evaluate.py")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()