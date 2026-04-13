import pandas as pd
import numpy as np
import joblib

# -----------------------------
# 1. Load model and scaler
# -----------------------------
model = joblib.load("model/isolation_forest.pkl")
scaler = joblib.load("model/scaler.pkl")

# -----------------------------
# 2. Feature list (must match training exactly)
# -----------------------------
features = [
    "total_requests",
    "session_duration_sec",
    "requests_per_minute",
    "requests_per_second",
    "error_ratio",
    "error_count",
    "unique_endpoints",
    "endpoint_entropy",
    "admin_action_count",
    "wallet_action_ratio",
    "transfer_count",
    "topup_count",
    "withdraw_count",
    "pay_bill_count",
    "avg_think_time_ms",
    "std_think_time_ms",
    "avg_response_time_ms"
]

# -----------------------------
# 3. Helper
# -----------------------------
def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["requests_per_second"] = (
        df["total_requests"] / df["session_duration_sec"].replace(0, np.nan)
    ).fillna(0)
    df["error_count"] = df["error_ratio"] * df["total_requests"]
    return df

# -----------------------------
# 4. Threshold
# -----------------------------
threshold = 0.02

# -----------------------------
# 5. Evaluate on NORMAL dataset
# -----------------------------
df_normal = pd.read_csv("dataset/output/baseline_sessions.csv")
df_normal = add_derived_features(df_normal)

X_normal = df_normal[features].copy()
X_normal_scaled = scaler.transform(X_normal)

normal_scores = model.decision_function(X_normal_scaled)
normal_pred = (normal_scores < threshold).astype(int)   # 1 = anomaly
fpr = normal_pred.mean()

# -----------------------------
# 6. Evaluate on ABNORMAL dataset
# -----------------------------
df_abnormal = pd.read_csv("dataset/abnormal/output/abnormal_sessionsSw.csv")
df_abnormal = add_derived_features(df_abnormal)

X_abnormal = df_abnormal[features].copy()
X_abnormal_scaled = scaler.transform(X_abnormal)



abnormal_scores = model.decision_function(X_abnormal_scaled)
abnormal_pred = (abnormal_scores < threshold).astype(int)   # 1 = anomaly
detection_rate = abnormal_pred.mean()

print()
print("Threshold:", threshold)
print("FPR:", fpr)
print("Detection rate:", detection_rate)

from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

df_abnormal["anomaly_score"] = model.decision_function(X_abnormal_scaled)
df_abnormal["anomaly_label"] = df_abnormal["anomaly_score"].apply(
    lambda s: -1 if s < threshold else 1
)


# -----------------------------
# Proxy ground-truth rules
# -----------------------------
rules = (
    (df_abnormal["requests_per_minute"] > 100) |
    (df_abnormal["error_ratio"] > 0.30) |
    (df_abnormal["admin_action_count"] > 20) |
    (df_abnormal["avg_think_time_ms"] < 100)
)

df_abnormal["label"] = rules.astype(int)   # proxy label: 1 = anomaly, 0 = normal
df_abnormal["pred"] = df_abnormal["anomaly_label"].apply(lambda x: 1 if x == -1 else 0)

# -----------------------------
# Confusion matrix + metrics
# -----------------------------
cm = confusion_matrix(df_abnormal["label"], df_abnormal["pred"])

print("\n=== Proxy-label confusion matrix ===")
print(cm)

cm_df = pd.DataFrame(
    cm,
    index=["Actual Normal", "Actual Anomaly"],
    columns=["Pred Normal", "Pred Anomaly"]
)
print(cm_df)

print("\nProxy Accuracy:", accuracy_score(df_abnormal["label"], df_abnormal["pred"]))
print("Proxy Precision:", precision_score(df_abnormal["label"], df_abnormal["pred"], zero_division=0))
print("Proxy Recall:", recall_score(df_abnormal["label"], df_abnormal["pred"], zero_division=0))
print("Proxy F1 Score:", f1_score(df_abnormal["label"], df_abnormal["pred"], zero_division=0))