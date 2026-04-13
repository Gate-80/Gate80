import joblib
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# 1. Load training data
train_df = pd.read_csv("model/gate80_train_noisier2.csv")

if "label" not in train_df.columns:
    raise ValueError("Training file must contain a 'label' column.")

# 2. Train only on normal rows
train_normal = train_df[train_df["label"] == 0].copy()

print("Full training shape:", train_df.shape)
print("Normal-only training shape:", train_normal.shape)

# 3. Same minimal 7-feature set
features = [
    "session_duration_sec",
    "requests_per_minute",
    "unique_endpoints",
    "endpoint_entropy",
    "avg_think_time_ms",
    "std_think_time_ms",
    "avg_response_time_ms"
]

X_train = train_normal[features].copy()

# 4. Impute + scale
imputer = SimpleImputer(strategy="constant", fill_value=0)
X_train_imputed = imputer.fit_transform(X_train)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_imputed)

# 5. Train IF
model = IsolationForest(
    n_estimators=300,
    contamination=0.08,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled)

# 6. Save
joblib.dump(model, "model/isolation_forest_noisy.pkl")
joblib.dump(imputer, "model/if_noisy_imputer.pkl")
joblib.dump(scaler, "model/if_noisy_scaler.pkl")
joblib.dump(features, "model/if_noisy_features.pkl")

print("\nSaved:")
print("- model/isolation_forest_noisy.pkl")
print("- model/if_noisy_imputer.pkl")
print("- model/if_noisy_scaler.pkl")
print("- model/if_noisy_features.pkl")