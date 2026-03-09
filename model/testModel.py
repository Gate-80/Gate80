import pandas as pd
import joblib

# -----------------------------
# 1. Load saved model and scaler
# -----------------------------
model = joblib.load("model/isolation_forest.pkl")
scaler = joblib.load("model/scaler.pkl")

# -----------------------------
# 2. Load abnormal test dataset
# -----------------------------
df = pd.read_csv("model/abnormal_sessionsSw.csv")

# -----------------------------
# 3. Select same features used in training
# -----------------------------
features = [
    "total_requests",
    "session_duration_sec",
    "requests_per_minute",
    "error_ratio",
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

X = df[features].copy()

# -----------------------------
# 4. Scale using saved scaler
# -----------------------------
X_scaled = scaler.transform(X)

# -----------------------------
# 5. Predict anomalies
# -----------------------------
df["anomaly_score"] = model.decision_function(X_scaled)
df["anomaly_label"] = model.predict(X_scaled)

# convert to clearer format
df["predicted_class"] = df["anomaly_label"].apply(
    lambda x: "anomaly" if x == -1 else "normal"
)

#evaluation step 1
rules = (
    (df["requests_per_minute"] > 100) |
    (df["error_ratio"] > 0.30) |
    (df["admin_action_count"] > 20) |
    (df["avg_think_time_ms"] < 100)
)

df["rule_abnormal"] = rules.astype(int)

flagged = df[df["predicted_class"] == "anomaly"]

precision_proxy = flagged["rule_abnormal"].mean()

print("Total flagged anomalies:", len(flagged))
print("Rule-confirmed anomalies:", flagged["rule_abnormal"].sum())
print("Rule-based abnormal proportion:", precision_proxy)

unconfirmed = flagged[flagged["rule_abnormal"] == 0]
print(unconfirmed[[
    "requests_per_minute",
    "error_ratio",
    "admin_action_count",
    "avg_think_time_ms",
    "anomaly_score"
]].head(20))

# evaluation step 2

print("\nTop 20 most anomalous sessions:")
print(
    flagged.sort_values("anomaly_score")[[
        "session_id",
        "requests_per_minute",
        "error_ratio",
        "admin_action_count",
        "avg_think_time_ms",
        "unique_endpoints",
        "endpoint_entropy",
        "anomaly_score"
    ]].head(20)
)
print("\nBehavior comparison (mean values):")

print(
    df.groupby("predicted_class")[[
        "requests_per_minute",
        "error_ratio",
        "admin_action_count",
        "avg_think_time_ms",
        "unique_endpoints",
        "endpoint_entropy"
    ]].mean()
)

print("\nRandom anomaly sample:")
print(
    flagged.sample(10)[[
        "requests_per_minute",
        "error_ratio",
        "admin_action_count",
        "avg_think_time_ms",
        "anomaly_score"
    ]]
)

# evaluation step 3: create approximate ground-truth labels
df["label"] = rules.astype(int)

# convert model predictions to 0/1
df["pred"] = df["anomaly_label"].apply(lambda x: 1 if x == -1 else 0)

# confusion matrix + metrics
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

cm = confusion_matrix(df["label"], df["pred"])

print("\nConfusion Matrix:")
print(cm)

cm_df = pd.DataFrame(
    cm,
    index=["Actual Normal", "Actual Anomaly"],
    columns=["Pred Normal", "Pred Anomaly"]
)
print(cm_df)

print("\nAccuracy:", accuracy_score(df["label"], df["pred"]))
print("Precision:", precision_score(df["label"], df["pred"]))
print("Recall:", recall_score(df["label"], df["pred"]))
print("F1 Score:", f1_score(df["label"], df["pred"]))