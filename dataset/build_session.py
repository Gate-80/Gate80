# Step 2 script

import pandas as pd

df = pd.read_csv('dataset/output/traffic_log_20260327_124508.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True)

print(f"Total requests loaded: {len(df)}")
print(f"Unique session IDs: {df['session_id'].nunique()}")

df = df.sort_values(['session_id', 'timestamp']).reset_index(drop=True)
print("Data sorted successfully!")

INACTIVITY_THRESHOLD = pd.Timedelta(minutes=5)
print(f"Inactivity threshold set to: {INACTIVITY_THRESHOLD}")

sessions = []

for session_id, group in df.groupby('session_id'):
    group = group.reset_index(drop=True)

    sub_session_id = 0
    sub_session_ids = [0]

    for i in range(1, len(group)):
        gap = group.loc[i, 'timestamp'] - group.loc[i-1, 'timestamp']
        if gap > INACTIVITY_THRESHOLD:
            sub_session_id += 1
        sub_session_ids.append(sub_session_id)

    group['sub_session'] = sub_session_ids

    for sub_id, sub_group in group.groupby('sub_session'):
        unique_id = f"{session_id}" if sub_id == 0 else f"{session_id}_part{sub_id+1}"

        sessions.append({
            'session_id':       unique_id,
            'user_id':          sub_group['user_id'].iloc[0],
            'persona':          sub_group['persona'].iloc[0],
            'email':            sub_group['email'].iloc[0],
            'geo_location':     sub_group['geo_location'].iloc[0],
            'client_type':      sub_group['client_type'].iloc[0],
            'start_time':       sub_group['timestamp'].min(),
            'end_time':         sub_group['timestamp'].max(),
            'duration_seconds': round((sub_group['timestamp'].max() - sub_group['timestamp'].min()).total_seconds(), 2),
            'num_requests':     len(sub_group),
            'actions_list':     ', '.join(sub_group['action'].tolist()),
        })

print(f"Sessions built successfully!")

sessions_df = pd.DataFrame(sessions)

print(f"Total sessions: {len(sessions_df)}")
print(f"Sessions split by inactivity: {sessions_df['session_id'].str.contains('_part').sum()}")
print(sessions_df.head())

sessions_df.to_csv('dataset/output/sessions_features.csv', index=False)
print("sessions_features.csv saved successfully!")

# General info
print(sessions_df.info())
print(sessions_df.describe())

# Check for missing values
print(sessions_df.isnull().sum())

# Pick a random session and inspect it
sample = sessions_df.sample(5)
for _, row in sample.iterrows():
    print(f"\nSession: {row['session_id']}")
    print(f"User: {row['user_id']} | Persona: {row['persona']}")
    print(f"Duration: {row['duration_seconds']}s | Requests: {row['num_requests']}")
    print(f"Actions: {row['actions_list']}")
    print("-" * 60)