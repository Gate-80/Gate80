import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

# 1. Load training data
train_df = pd.read_csv("model/gate80_train_noisier2.csv")

if "label" not in train_df.columns:
    raise ValueError("Training file must contain a 'label' column.")

# 2. Use the same minimal 7-feature set
features = [
    "session_duration_sec",
    "requests_per_minute",
    "unique_endpoints",
    "endpoint_entropy",
    "avg_think_time_ms",
    "std_think_time_ms",
    "avg_response_time_ms"
]

X_train = train_df[features].copy()
y_train = train_df["label"].copy()

print("Training shape:", X_train.shape)
print("Training labels:")
print(y_train.value_counts())

# 3. Train pipeline
model = Pipeline([
    ("imputer", SimpleImputer(strategy="constant", fill_value=0)),
    ("scaler", StandardScaler()),
    ("svm", SVC(
        kernel="rbf",
        C=1.0,
        gamma="scale",
        class_weight="balanced",
        probability=True,
        random_state=42
    ))
])

model.fit(X_train, y_train)

# 4. Save
joblib.dump(model, "model/svm_noisy.pkl")
joblib.dump(features, "model/svm_noisy_features.pkl")

print("\nSaved:")
print("- model/svm_noisy.pkl")
print("- model/svm_noisy_features.pkl")