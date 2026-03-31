def get_decoy_strategy(behavior_type: str) -> dict:
    mapping = {
        "brute_force": {
            "strategy": "slow_fake_auth",
            "status_code": 401,
            "message": "Invalid credentials",
            "delay_ms": 2500
        },
        "scanning": {
            "strategy": "fake_endpoint_noise",
            "status_code": 404,
            "message": "Resource not found",
            "delay_ms": 800
        },
        "fraud": {
            "strategy": "fake_financial_flow",
            "status_code": 200,
            "message": "Transaction queued",
            "delay_ms": 1200
        },
        "unknown_suspicious": {
            "strategy": "generic_decoy",
            "status_code": 200,
            "message": "Request processed",
            "delay_ms": 1000
        }
    }

    return mapping.get(behavior_type, mapping["unknown_suspicious"])