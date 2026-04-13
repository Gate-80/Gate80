import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

# load the dataset
train_df=pd.read_csv("model/gate80_train_noisier2.csv")

# check if the data set has a column that says label

if "label" not in train_df.columns:
    raise ValueError("Training file must contain a 'label' column.")

# 2. Define columns to exclude
# -----------------------------
drop_cols = {
    "label",
    "session_type",
    "session_id",
    "user_id",
    "email",
    "start_time",
    "end_time",
    "actions_list"
}

# numeric features only
numeric_cols = train_df.select_dtypes(include=["number"]).columns.tolist()

features = [
    "session_duration_sec",
    "requests_per_minute",
    "unique_endpoints",
    "endpoint_entropy",
    "avg_think_time_ms",
    "std_think_time_ms",
    "avg_response_time_ms"
]
print("Selected features:")
for col in features:
    print("-", col)

# -----------------------------
# 3. Build X and y
# -----------------------------
X_train = train_df[features].copy().fillna(0)
y_train = train_df["label"].copy()

print("\nTraining shape:", X_train.shape)
print("Training labels:")
print(y_train.value_counts())

# -----------------------------
# 4. Train model
# -----------------------------
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -----------------------------
# 5. Save model and features
# -----------------------------
joblib.dump(model, "model/random_forest_2.pkl")
joblib.dump(features, "model/rf_features_2.pkl")

print("\nSaved:")
print("- model/random_forest.pkl")
print("- model/rf_features.pkl")