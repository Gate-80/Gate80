import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# 1. Load test data
test_df = pd.read_csv("model/gate80_test_noisier2.csv")

if "label" not in test_df.columns:
    raise ValueError("Test file must contain a 'label' column.")

# 2. Load artifacts
model = joblib.load("model/isolation_forest_noisy.pkl")
imputer = joblib.load("model/if_noisy_imputer.pkl")
scaler = joblib.load("model/if_noisy_scaler.pkl")
features = joblib.load("model/if_noisy_features.pkl")

# 3. Build X and y
X_test = test_df[features].copy()
y_test = test_df["label"].copy()

print("Test shape:", X_test.shape)
print("Test labels:")
print(y_test.value_counts())

# 4. Transform
X_test_imputed = imputer.transform(X_test)
X_test_scaled = scaler.transform(X_test_imputed)

# 5. Predict
raw_pred = model.predict(X_test_scaled)   # 1 normal, -1 anomaly
y_pred = pd.Series(raw_pred).map({1: 0, -1: 1})

scores = model.decision_function(X_test_scaled)

# 6. Evaluate
cm = confusion_matrix(y_test, y_pred)

print("\n=== Confusion Matrix ===")
print(cm)

cm_df = pd.DataFrame(
    cm,
    index=["Actual Normal", "Actual Anomaly"],
    columns=["Pred Normal", "Pred Anomaly"]
)
print(cm_df)

print("\n=== Metrics ===")
print("Accuracy :", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, zero_division=0))
print("Recall   :", recall_score(y_test, y_pred, zero_division=0))
print("F1 Score :", f1_score(y_test, y_pred, zero_division=0))

print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred, zero_division=0))

results_df = test_df.copy()
results_df["if_score"] = scores
results_df["if_pred"] = y_pred

print("\n=== Lowest 10 anomaly scores ===")
print(
    results_df.sort_values("if_score").head(10)[
        ["label", "session_type", "if_score"]
    ]
)