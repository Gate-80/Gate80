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

# 2. Load model and features
model = joblib.load("model/svm_noisy.pkl")
features = joblib.load("model/svm_noisy_features.pkl")

# 3. Build X and y
X_test = test_df[features].copy()
y_test = test_df["label"].copy()

print("Test shape:", X_test.shape)
print("Test labels:")
print(y_test.value_counts())

# 4. Predict
y_pred = model.predict(X_test)

# 5. Evaluate
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