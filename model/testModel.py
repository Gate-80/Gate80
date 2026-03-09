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
df = pd.read_csv("model/abnormal_sessions.csv")

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

# -----------------------------
# 6. Print summary
# -----------------------------
print("\nPrediction distribution:")
print(df["predicted_class"].value_counts())

print("\nTop detected anomalies:")
detected_anomalies = df[df["anomaly_label"] == -1].sort_values("anomaly_score")

print(
    detected_anomalies[
        [
            "session_id",
            "requests_per_minute",
            "error_ratio",
            "admin_action_count",
            "avg_response_time_ms",
            "anomaly_score",
            "predicted_class"
        ]
    ].head(20)
)

# -----------------------------
# 7. Save results
# -----------------------------
df.to_csv("model/abnormal_sessions_results.csv", index=False)
print("\nResults saved to: model/abnormal_sessions_results.csv")