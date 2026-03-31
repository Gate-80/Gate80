import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# -----------------------------
# 1. Load baseline training data
# -----------------------------
df = pd.read_csv("dataset/output/baseline_sessions.csv").copy()

# -----------------------------
# 2. Add derived features
# -----------------------------
df["requests_per_second"] = (
    df["total_requests"] / df["session_duration_sec"].replace(0, np.nan)
).fillna(0)

df["error_count"] = df["error_ratio"] * df["total_requests"]

# -----------------------------
# 3. Feature list
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

X = df[features].copy()

# -----------------------------
# 4. Scale
# -----------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# -----------------------------
# 5. Train model
# -----------------------------
model = IsolationForest(
    n_estimators=500,
    contamination=0.05,
    random_state=42
)

model.fit(X_scaled)

# -----------------------------
# 6. Save artifacts
# -----------------------------
joblib.dump(model, "model/isolation_forest.pkl")
joblib.dump(scaler, "model/scaler.pkl")

# -----------------------------
# 7. Quick inspection
# -----------------------------
df["anomaly_score"] = model.decision_function(X_scaled)
df["anomaly_label"] = model.predict(X_scaled)

print("\nTraining anomaly distribution:")
print(df["anomaly_label"].value_counts())

print("\nMost anomalous baseline sessions:")
print(
    df.sort_values("anomaly_score")[
        [
            "requests_per_minute",
            "error_ratio",
            "admin_action_count",
            "avg_think_time_ms",
            "anomaly_score"
        ]
    ].head(20)
)