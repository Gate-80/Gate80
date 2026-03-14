import pandas as pd
import os
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

df = pd.read_csv("dataset/output/baseline_sessions.csv")
#print(df.dtypes)
# numeric statistics
#stats = df.describe()
#print(stats)

# check missing values
#print(df.isnull().sum())



#features = [
   # "requests_per_minute",
    #"session_duration_sec",
    #"error_ratio",
    #"endpoint_entropy",
   # "avg_think_time_ms",
    #"unique_endpoints"
#]

#for f in features:
   # plt.figure()
    #df[f].hist(bins=30)
    #plt.title(f"Distribution of {f}")
    #plt.xlabel(f)
    #plt.ylabel("Frequency")
    #plt.show()

#print(df.skew(numeric_only=True))
#print(df.kurtosis(numeric_only=True))


#corr = df.corr(numeric_only=True)
#sns.heatmap(corr)
#plt.show()
#Q1 = df.quantile(0.25)
#Q3 = df.quantile(0.75)
#IQR = Q3 - Q1
#outliers = ((df < (Q1 - 1.5*IQR)) | (df > (Q3 + 1.5*IQR))).sum()
#print(outliers)

featuress = [
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

X = df[featuress].copy()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# train Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination=0.08,   # between 5% and 10%
    random_state=42
)

model.fit(X_scaled)



# save trained model
joblib.dump(model, "model/isolation_forest.pkl")

# save scaler
joblib.dump(scaler, "model/scaler.pkl")

# anomaly scores and labels
df["anomaly_score"] = model.decision_function(X_scaled)
df["anomaly_label"] = model.predict(X_scaled)

# check anomaly proportion
print("\nAnomaly distribution:")
print(df["anomaly_label"].value_counts())

# show most abnormal sessions
print("\nTop anomalous sessions:")
print(df.sort_values("anomaly_score").head(20))


print(df["anomaly_label"].value_counts())

# show suspicious rows
anomalies = df[df["anomaly_label"] == -1]
print("\nDetected anomalies:")
print(anomalies[[
    "requests_per_minute",
    "error_ratio",
    "admin_action_count",
    "avg_response_time_ms",
    "anomaly_score"
]].head(20))
