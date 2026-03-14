import pandas as pd

df = pd.read_csv('dataset/output/mixed_traffic_log.csv')
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
        gap = group.loc[i, 'timestamp'] - group.loc[i - 1, 'timestamp']
        if gap > INACTIVITY_THRESHOLD:
            sub_session_id += 1
        sub_session_ids.append(sub_session_id)

    group['sub_session'] = sub_session_ids

    for sub_id, sub_group in group.groupby('sub_session'):
        unique_id = f"{session_id}" if sub_id == 0 else f"{session_id}_part{sub_id+1}"

        status_series = pd.to_numeric(sub_group['status_code'], errors='coerce')
        response_series = pd.to_numeric(sub_group['response_time_ms'], errors='coerce')
        think_series = pd.to_numeric(sub_group['think_time_ms'], errors='coerce')

        num_requests = len(sub_group)
        num_2xx = status_series.between(200, 299).sum()
        num_4xx = status_series.between(400, 499).sum()
        num_5xx = status_series.between(500, 599).sum()
        num_400 = (status_series == 400).sum()
        num_401 = (status_series == 401).sum()
        num_403 = (status_series == 403).sum()
        num_404 = (status_series == 404).sum()

        error_ratio = round((num_4xx + num_5xx) / num_requests, 4) if num_requests else 0

        admin_requests = sub_group['path'].fillna('').str.contains('/admin').sum()
        auth_requests = sub_group['path'].fillna('').str.contains('/auth').sum()
        wallet_requests = sub_group['path'].fillna('').str.contains('/wallet').sum()

        failed_logins = sub_group['is_failed_login'].fillna(False).astype(str).str.lower().isin(['true', '1']).sum()

        unique_endpoints = sub_group['path'].nunique()
        unique_methods = sub_group['method'].nunique()

        suspicious_flags = 0
        if 'flagged_as_suspicious' in sub_group.columns:
            suspicious_flags = sub_group['flagged_as_suspicious'].fillna(False).astype(str).str.lower().isin(['true', '1']).sum()

        duration_seconds = round(
            (sub_group['timestamp'].max() - sub_group['timestamp'].min()).total_seconds(), 2
        )

        requests_per_second = round(num_requests / duration_seconds, 4) if duration_seconds > 0 else num_requests

        sessions.append({
            'session_id': unique_id,
            'user_id': sub_group['user_id'].iloc[0],
            'persona': sub_group['persona'].iloc[0],
            'email': sub_group['email'].iloc[0],
            'geo_location': sub_group['geo_location'].iloc[0],
            'client_type': sub_group['client_type'].iloc[0],

            'start_time': sub_group['timestamp'].min(),
            'end_time': sub_group['timestamp'].max(),
            'duration_seconds': duration_seconds,
            'num_requests': num_requests,

            # behavioral features for anomaly detection
            'num_2xx': int(num_2xx),
            'num_4xx': int(num_4xx),
            'num_5xx': int(num_5xx),
            'num_400': int(num_400),
            'num_401': int(num_401),
            'num_403': int(num_403),
            'num_404': int(num_404),
            'error_ratio': error_ratio,

            'admin_requests': int(admin_requests),
            'auth_requests': int(auth_requests),
            'wallet_requests': int(wallet_requests),
            'failed_logins': int(failed_logins),

            'unique_endpoints': int(unique_endpoints),
            'unique_methods': int(unique_methods),

            'avg_response_time_ms': round(response_series.mean(), 2) if not response_series.isna().all() else 0,
            'max_response_time_ms': round(response_series.max(), 2) if not response_series.isna().all() else 0,
            'avg_think_time_ms': round(think_series.mean(), 2) if not think_series.isna().all() else 0,

            'requests_per_second': requests_per_second,
            'suspicious_flags': int(suspicious_flags),

            'actions_list': ', '.join(sub_group['action'].astype(str).tolist())
        })

print("Sessions built successfully!")

sessions_df = pd.DataFrame(sessions)

print(f"Total sessions: {len(sessions_df)}")
print(f"Sessions split by inactivity: {sessions_df['session_id'].str.contains('_part').sum()}")
print(sessions_df.head())

sessions_df.to_csv('dataset/abnormal/output/TrafficLog_abnormal_sessions.csv', index=False)
print("TrafficLog_abnormal_sessions.csv saved successfully!")

print(sessions_df.info())
print(sessions_df.describe())
print(sessions_df.isnull().sum())

sample = sessions_df.sample(min(5, len(sessions_df)))
for _, row in sample.iterrows():
    print(f"\nSession: {row['session_id']}")
    print(f"User: {row['user_id']} | Persona: {row['persona']}")
    print(f"Duration: {row['duration_seconds']}s | Requests: {row['num_requests']}")
    print(f"4xx: {row['num_4xx']} | 401: {row['num_401']} | Admin requests: {row['admin_requests']}")
    print(f"Error ratio: {row['error_ratio']} | RPS: {row['requests_per_second']}")
    print("-" * 60)