import pandas as pd

df = pd.read_csv("dataset/output/traffic_log_20260326_060131.csv")
print("Raw request rows:", len(df))
print(df.head())


df2 = pd.read_csv("dataset/output/sessions_features.csv")
print("Session rows:", len(df2))
print(df2.head())

df3 = pd.read_csv("dataset/output/baseline_sessions_20260326_171758.csv")
print("Final rows:", len(df3))
print(df3.head())
