import pandas as pd

# load both datasets
baseline = pd.read_csv("model/baseline_sessions.csv")
abnormal = pd.read_csv("model/abnormal_sessions.csv")

# check shapes
print("Baseline shape:", baseline.shape)
print("Abnormal shape:", abnormal.shape)

# check if session IDs are identical
print("\nSame session IDs:", baseline["session_id"].equals(abnormal["session_id"]))

# check if datasets are completely identical
print("Datasets identical:", baseline.equals(abnormal))

# show differences if they exist
diff = baseline.compare(abnormal)
print("\nDifferences:")
print(diff.head(20))