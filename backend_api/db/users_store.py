from datetime import datetime, timezone
from typing import Dict, Any, List

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

T_USERS: Dict[str, Dict[str, Any]] = {
    "u_1001": {
        "id": "u_1001",
        "full_name": "Taif Alsaadi",
        "email": "taif.alsaadi@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Jeddah",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    "u_1002": {
        "id": "u_1002",
        "full_name": "Hanan Alharbi",
        "email": "hanan.alharbi@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Riyadh",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    "u_1003": {
        "id": "u_1003",
        "full_name": "Queen RAMA",
        "email": "queenrama@gmail.com",
        "phone": "+9665XXXXXXX",
        "city": "Los Angeles",
        "is_verified": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
}

T_BANK_ACCOUNTS: List[Dict[str, Any]] = [
    {
        "id": "ba_2001",
        "user_id": "u_1001",
        "bank_name": "Al Rajhi Bank",
        "iban": "SA4420000001234567891234",
        "masked_account_number": "**** **** **** 3192",
        "currency": "SAR",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    {
        "id": "ba_2002",
        "user_id": "u_1002",
        "bank_name": "Saudi National Bank",
        "iban": "SA1520000009876543219876",
        "masked_account_number": "**** **** **** 7741",
        "currency": "SAR",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    {
        "id": "ba_2003",
        "user_id": "u_1003",
        "bank_name": "American Bank",
        "iban": "SA1520000009876543219821",
        "masked_account_number": "**** **** **** 9821",
        "currency": "USD",
        "is_default": True,
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
]

T_PAYMENTS: List[Dict[str, Any]] = [
    {
        "id": "pay_3001",
        "user_id": "u_1001",
        "status": "COMPLETED",
        "amount": {"currency_code": "SAR", "value": "120.00"},
        "merchant": {"name": "RASD Store", "merchant_id": "m_9001"},
        "description": "Order #A1001",
        "created_at": "2026-02-08T21:56:51+00:00",
        "updated_at": "2026-02-08T21:56:51+00:00",
    },
    {
        "id": "pay_3002",
        "user_id": "u_1001",
        "status": "AUTHORIZED",
        "amount": {"currency_code": "SAR", "value": "55.50"},
        "merchant": {"name": "Coffee Spot", "merchant_id": "m_9002"},
        "description": "Coffee beans",
        "created_at": "2026-02-09T10:12:05+00:00",
        "updated_at": "2026-02-09T10:12:05+00:00",
    },
    {
        "id": "pay_3003",
        "user_id": "u_1002",
        "status": "FAILED",
        "amount": {"currency_code": "SAR", "value": "999.00"},
        "merchant": {"name": "ElectroMart", "merchant_id": "m_9010"},
        "description": "Attempted purchase",
        "created_at": "2026-02-10T08:01:00+00:00",
        "updated_at": "2026-02-10T08:01:00+00:00",
    },
]