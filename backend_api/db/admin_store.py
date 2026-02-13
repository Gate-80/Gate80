from typing import Dict, Any, List
from datetime import datetime, timezone

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Simulated admin accounts
T_ADMINS: Dict[str, Dict[str, Any]] = {
    "a_0001": {
        "id": "a_0001",
        "username": "admin",
        "password": "admin123",   # prototype only 
        "role": "SUPER_ADMIN",
        "created_at": "2026-02-01T10:00:00+00:00",
        "updated_at": "2026-02-01T10:00:00+00:00",
    }
}

# Token -> session object
T_ADMIN_SESSIONS: Dict[str, Dict[str, Any]] = {}

# Simple audit logs
T_ADMIN_AUDIT_LOGS: List[Dict[str, Any]] = []