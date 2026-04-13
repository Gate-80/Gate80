import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

# 1. Load training data
train_df = pd.read_csv("model/gate80_train.csv")

if "label" not in train_df.columns:
    raise ValueError("Training file must contain a 'label' column.")

# 2. Feature selection
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

numeric_cols = train_df.select_dtypes(include=["number"]).columns.tolist()
features = [c for c in numeric_cols if c not in drop_cols]

print("Selected features:")
for col in features:
    print("-", col)

# 3. Build X and y
X_train = train_df[features].copy()
y_train = train_df["label"].copy()

print("\nTraining shape:", X_train.shape)
print("Training labels:")
print(y_train.value_counts())

# 4. Train SVM pipeline
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

# 5. Save model and features
joblib.dump(model, "model/svm.pkl")
joblib.dump(features, "model/svm_features.pkl")

print("\nSaved:")
print("- model/svm.pkl")
print("- model/svm_features.pkl")