"""
GATE80 - Model Evaluation
dataset/unified/evaluate.py

Evaluates both trained models against gate80_test.csv using true labels.
Also runs 5-fold stratified cross-validation on training data for honest
performance estimation.

Models evaluated:
  1. Random Forest  (supervised)   - primary model
  2. Isolation Forest (unsupervised) - comparison baseline

Metrics reported:
  - Accuracy, Precision, Recall, F1, F2, ROC-AUC
  - Confusion Matrix
  - Per-attack-type detection rates (Random Forest)
  - 5-fold cross-validation scores (Random Forest)

Run:
    python dataset/unified/evaluate.py
"""

import csv
import json
import os
import pickle
from collections import Counter, defaultdict

FEATURE_COLUMNS = [
    "total_requests", "session_duration_sec", "requests_per_minute",
    "failed_login_count", "login_attempts", "failed_login_ratio", "login_success",
    "error_ratio", "error_4xx_count", "error_5xx_count",
    "http_4xx_ratio", "http_5xx_ratio",
    "unique_endpoints", "endpoint_entropy",
    "has_admin_access", "admin_action_count", "admin_ratio",
    "wallet_action_count", "wallet_action_ratio",
    "transfer_count", "topup_count", "withdraw_count",
    "pay_bill_count", "financial_error_count",
    "avg_think_time_ms", "std_think_time_ms",
    "min_think_time_ms", "max_think_time_ms",
    "think_time_cv", "avg_response_time_ms",
]

TRAIN_FILE   = "dataset/unified/output/gate80_train.csv"
TEST_FILE    = "dataset/unified/output/gate80_test.csv"
RF_PATH      = "model/unified/random_forest.pkl"
IF_PATH      = "model/unified/isolation_forest.pkl"
SCALER_PATH  = "model/unified/scaler.pkl"
RESULTS_PATH = "model/unified/evaluation_results.json"


def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def to_float(rows, feature_cols):
    X, y, meta = [], [], []
    for row in rows:
        try:
            features = [float(row[col]) for col in feature_cols]
            label    = int(row["label"])
            X.append(features)
            y.append(label)
            meta.append({
                "session_type": row.get("session_type", ""),
                "session_id":   row.get("session_id", ""),
            })
        except (ValueError, KeyError):
            continue
    return X, y, meta


def confusion_matrix_vals(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return tp, tn, fp, fn


def compute_metrics(y_true, y_pred, y_scores=None):
    tp, tn, fp, fn = confusion_matrix_vals(y_true, y_pred)
    total = len(y_true)

    accuracy  = round((tp + tn) / total, 4) if total > 0 else 0
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0
    recall    = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0
    f1        = round(2 * precision * recall / (precision + recall), 4) \
                if (precision + recall) > 0 else 0
    f2        = round((1 + 4) * precision * recall / (4 * precision + recall), 4) \
                if (4 * precision + recall) > 0 else 0
    auc = compute_auc(y_true, y_scores) if y_scores is not None else 0.0

    return {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "f2": f2,
        "auc": round(auc, 4),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": total,
    }


def compute_auc(y_true, y_scores):
    paired = sorted(zip(y_scores, y_true), key=lambda x: -x[0])
    n_pos  = sum(y_true)
    n_neg  = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    tp, auc = 0, 0.0
    for _, label in paired:
        if label == 1:
            tp += 1
        else:
            auc += tp
    return auc / (n_pos * n_neg)


def print_metrics(name, m):
    print(f"\n  {'─'*55}")
    print(f"  {name}")
    print(f"  {'─'*55}")
    print(f"  Accuracy  : {m['accuracy']:.4f}  ({m['accuracy']*100:.2f}%)")
    print(f"  Precision : {m['precision']:.4f}")
    print(f"  Recall    : {m['recall']:.4f}")
    print(f"  F1 Score  : {m['f1']:.4f}")
    print(f"  F2 Score  : {m['f2']:.4f}  (recall-weighted)")
    print(f"  ROC-AUC   : {m['auc']:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted")
    print(f"                  Normal  Abnormal")
    print(f"  Actual Normal  : {m['tn']:>6}  {m['fp']:>8}")
    print(f"  Actual Abnormal: {m['fn']:>6}  {m['tp']:>8}")
    print(f"\n  TP={m['tp']}  TN={m['tn']}  FP={m['fp']}  FN={m['fn']}")


def run_cross_validation(rf_params, X, y, k=5):
    """
    Stratified K-fold cross-validation on training data.
    Stratified means each fold preserves the class ratio.
    Returns mean and std of each metric across K folds.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    # Group indices by label for stratified splitting
    indices_by_label = defaultdict(list)
    for i, label in enumerate(y):
        indices_by_label[label].append(i)

    # Create K stratified folds
    folds = [[] for _ in range(k)]
    for label, indices in indices_by_label.items():
        # Distribute indices of this label across folds
        for i, idx in enumerate(indices):
            folds[i % k].append(idx)

    fold_metrics = []

    for fold_idx in range(k):
        test_idx  = set(folds[fold_idx])
        train_idx = [i for i in range(len(X)) if i not in test_idx]
        test_idx  = list(test_idx)

        X_tr = [X[i] for i in train_idx]
        y_tr = [y[i] for i in train_idx]
        X_te = [X[i] for i in test_idx]
        y_te = [y[i] for i in test_idx]

        # Scale per fold to prevent data leakage
        sc = StandardScaler()
        X_tr_s = sc.fit_transform(X_tr)
        X_te_s = sc.transform(X_te)

        # Train RF with same params
        rf = RandomForestClassifier(**rf_params)
        rf.fit(X_tr_s, y_tr)

        y_pred   = rf.predict(X_te_s)
        y_scores = rf.predict_proba(X_te_s)[:, 1]

        m = compute_metrics(y_te, y_pred, y_scores)
        fold_metrics.append(m)

        print(f"    Fold {fold_idx+1}/{k}: "
              f"F1={m['f1']:.4f}  "
              f"Recall={m['recall']:.4f}  "
              f"Precision={m['precision']:.4f}  "
              f"AUC={m['auc']:.4f}")

    # Average across folds
    avg = {}
    std = {}
    for metric in ["accuracy", "precision", "recall", "f1", "f2", "auc"]:
        vals = [m[metric] for m in fold_metrics]
        avg[metric] = round(sum(vals) / len(vals), 4)
        mean = sum(vals) / len(vals)
        std[metric] = round((sum((v - mean)**2 for v in vals) / len(vals))**0.5, 4)

    return avg, std, fold_metrics


def main():
    try:
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        print("[ERROR] scikit-learn not installed. Run: pip install scikit-learn")
        return

    # ── Load models ───────────────────────────────────────────────────────────
    print("[1/5] Loading models...")
    for path in [RF_PATH, IF_PATH, SCALER_PATH]:
        if not os.path.exists(path):
            print(f"[ERROR] Not found: {path}")
            print("        Run train_model.py first.")
            return

    with open(RF_PATH,     "rb") as f: rf     = pickle.load(f)
    with open(IF_PATH,     "rb") as f: iso    = pickle.load(f)
    with open(SCALER_PATH, "rb") as f: scaler = pickle.load(f)
    print("      Models loaded.")

    # ── Load test data ────────────────────────────────────────────────────────
    print(f"\n[2/5] Loading test data...")
    test_rows = load_csv(TEST_FILE)
    X_test, y_true, meta = to_float(test_rows, FEATURE_COLUMNS)
    X_test_scaled = scaler.transform(X_test)

    label_counts = Counter(y_true)
    print(f"      {len(X_test):,} test sessions")
    print(f"      label=0 normal   : {label_counts[0]:,}")
    print(f"      label=1 abnormal : {label_counts[1]:,}")

    # ── Random Forest held-out test evaluation ────────────────────────────────
    print("\n[3/5] Evaluating Random Forest on held-out test set...")
    rf_pred   = rf.predict(X_test_scaled)
    rf_scores = rf.predict_proba(X_test_scaled)[:, 1]
    rf_metrics = compute_metrics(y_true, rf_pred, rf_scores)
    print_metrics("Random Forest — Held-out Test Set", rf_metrics)

    # Per-attack-type breakdown
    type_results = defaultdict(lambda: {"tp":0,"fp":0,"fn":0,"tn":0,"total":0})
    for i, m in enumerate(meta):
        stype  = m["session_type"]
        actual = y_true[i]
        pred   = int(rf_pred[i])
        type_results[stype]["total"] += 1
        if actual == 1 and pred == 1:   type_results[stype]["tp"] += 1
        elif actual == 1 and pred == 0: type_results[stype]["fn"] += 1
        elif actual == 0 and pred == 1: type_results[stype]["fp"] += 1
        else:                           type_results[stype]["tn"] += 1

    print(f"\n  Per-attack-type detection (Random Forest):")
    print(f"  {'Session Type':<25} {'Total':>6} {'Detected':>9} {'Missed':>7} {'Recall':>8}")
    print(f"  {'─'*58}")
    for stype, r in sorted(type_results.items()):
        if stype == "normal":
            fp_rate = round(r["fp"] / r["total"], 4) if r["total"] > 0 else 0
            print(f"  {stype:<25} {r['total']:>6} {'FP='+str(r['fp']):>9} "
                  f"{'':>7} {'FAR='+str(fp_rate):>8}")
        else:
            recall = round(r["tp"]/(r["tp"]+r["fn"]), 4) \
                     if (r["tp"]+r["fn"]) > 0 else 0
            print(f"  {stype:<25} {r['total']:>6} {r['tp']:>9} "
                  f"{r['fn']:>7} {recall:>8.4f}")

    # ── 5-fold cross-validation ───────────────────────────────────────────────
    print(f"\n[4/5] Running 5-fold stratified cross-validation on training data...")
    print(f"      (This gives a more honest performance estimate than held-out test)")
    print(f"      (If CV scores are significantly lower than test scores,")
    print(f"       it indicates the synthetic data boundary is too clean)\n")

    train_rows = load_csv(TRAIN_FILE)
    X_train, y_train, _ = to_float(train_rows, FEATURE_COLUMNS)

    rf_params = {
        "n_estimators": 200,
        "class_weight": "balanced",
        "min_samples_leaf": 2,
        "random_state": 42,
        "n_jobs": -1,
    }

    cv_avg, cv_std, cv_folds = run_cross_validation(rf_params, X_train, y_train, k=5)

    print(f"\n  Cross-Validation Results (5-fold, stratified):")
    print(f"  {'─'*55}")
    print(f"  {'Metric':<15} {'Mean':>10} {'Std':>10}  {'Held-out Test':>14}")
    print(f"  {'─'*55}")
    for metric in ["accuracy", "precision", "recall", "f1", "f2", "auc"]:
        mean = cv_avg[metric]
        std  = cv_std[metric]
        test = rf_metrics[metric]
        gap  = round(test - mean, 4)
        flag = " ← gap" if abs(gap) > 0.02 else ""
        print(f"  {metric:<15} {mean:>10.4f} {std:>10.4f}  {test:>14.4f}{flag}")

    print(f"\n  Interpretation:")
    overall_gap = round(rf_metrics['f1'] - cv_avg['f1'], 4)
    if overall_gap > 0.05:
        print(f"  F1 gap (test - CV mean) = {overall_gap:.4f}")
        print(f"  This gap reflects the synthetic dataset's clean behavioral")
        print(f"  boundaries. Real-world performance would be closer to CV scores.")
    else:
        print(f"  F1 gap (test - CV mean) = {overall_gap:.4f}")
        print(f"  Small gap — model generalizes consistently across folds.")

    # ── Isolation Forest evaluation ───────────────────────────────────────────
    print(f"\n[5/5] Evaluating Isolation Forest on held-out test set...")
    if_raw    = iso.predict(X_test_scaled)
    if_pred   = [1 if p == -1 else 0 for p in if_raw]
    if_scores = [-s for s in iso.score_samples(X_test_scaled)]
    if_metrics = compute_metrics(y_true, if_pred, if_scores)
    print_metrics("Isolation Forest — Comparison Baseline", if_metrics)

    # ── Side-by-side comparison ───────────────────────────────────────────────
    print(f"\n  {'='*65}")
    print(f"  Final Comparison: Random Forest vs Isolation Forest")
    print(f"  {'='*65}")
    print(f"  {'Metric':<15} {'RF Test':>10} {'RF CV Mean':>12} {'IF Test':>10}")
    print(f"  {'─'*50}")
    for metric in ["accuracy","precision","recall","f1","f2","auc"]:
        rf_t  = rf_metrics[metric]
        rf_cv = cv_avg[metric]
        if_t  = if_metrics[metric]
        print(f"  {metric:<15} {rf_t:>10.4f} {rf_cv:>12.4f} {if_t:>10.4f}")

    print(f"\n  RF CV Mean is the most academically honest performance estimate.")
    print(f"  IF is included as the unsupervised baseline for comparison.")

    # ── Save results ──────────────────────────────────────────────────────────
    results = {
        "test_sessions":    len(X_test),
        "test_normal":      label_counts[0],
        "test_abnormal":    label_counts[1],
        "random_forest": {
            "held_out_test": rf_metrics,
            "cross_validation_5fold": {
                "mean": cv_avg,
                "std":  cv_std,
            },
        },
        "isolation_forest": {
            "held_out_test": if_metrics,
        },
        "per_attack_type_rf": {k: v for k, v in type_results.items()},
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to {RESULTS_PATH}")
    print(f"  {'='*65}\n")


if __name__ == "__main__":
    main()