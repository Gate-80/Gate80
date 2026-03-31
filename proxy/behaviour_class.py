def classify_behavior(session_features: dict) -> str:
    rpm = session_features.get("requests_per_minute", 0)
    error_ratio = session_features.get("error_ratio", 0)
    unique_endpoints = session_features.get("unique_endpoints", 0)
    admin_actions = session_features.get("admin_action_count", 0)
    wallet_ratio = session_features.get("wallet_action_ratio", 0)
    transfer_count = session_features.get("transfer_count", 0)
    avg_think_time = session_features.get("avg_think_time_ms", 0)

    # brute-force style: fast + many failures
    if rpm > 80 and error_ratio > 0.4:
        return "brute_force"

    # scanning style: many endpoints + exploratory failures
    if unique_endpoints > 8 and error_ratio > 0.1:
        return "scanning"

    # fraud style: financial or privileged misuse
    if wallet_ratio > 0.5 or transfer_count > 3 or admin_actions > 5:
        return "fraud"

    # suspicious but unclear
    if avg_think_time < 300 and rpm > 40:
        return "unknown_suspicious"

    return "unknown_suspicious"