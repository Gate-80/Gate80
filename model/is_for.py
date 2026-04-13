import joblib
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# 1. Load training data
train_df = pd.read_csv("model/gate80_train.csv")

if "label" not in train_df.columns:
    raise ValueError("Training file must contain a 'label' column.")

# 2. Keep only normal data for training
train_normal = train_df[train_df["label"] == 0].copy()

print("Full training shape:", train_df.shape)
print("Normal-only training shape:", train_normal.shape)

# 3. Define columns to exclude
drop_cols = {
    "label",
    "session_type",
    "session_id",
    "user_id",
    "email",
    "start_time",
    "end_time",
    "actions_list",
}

numeric_cols = train_normal.select_dtypes(include=["number"]).columns.tolist()
features = [c for c in numeric_cols if c not in drop_cols]

print("\nSelected features:")
for col in features:
    print("-", col)

# 4. Build X
X_train = train_normal[features].copy()

# 5. Impute + scale
imputer = SimpleImputer(strategy="constant", fill_value=0)
X_train_imputed = imputer.fit_transform(X_train)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_imputed)

# 6. Train Isolation Forest
model = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled)

# 7. Save artifacts
joblib.dump(model, "model/isolation_forest.pkl")
joblib.dump(imputer, "model/if_imputer.pkl")
joblib.dump(scaler, "model/if_scaler.pkl")
joblib.dump(features, "model/if_features.pkl")

print("\nSaved:")
print("- model/isolation_forest.pkl")
print("- model/if_imputer.pkl")
print("- model/if_scaler.pkl")
print("- model/if_features.pkl")