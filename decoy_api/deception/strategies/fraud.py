"""
GATE80 — Decoy API
deception/strategies/fraud.py

Deception strategy for financial fraud sessions.

Behavior:
  - 1.2s delay on financial endpoints (plausible for compliance checks)
  - Transfer / withdraw / pay-bill responses intercepted:
      * Status changed from 200 → 202 (Accepted — believable pending state)
      * Message replaced with compliance review language
      * Displayed balance distorted by ±10% so the attacker sees wrong numbers
  - GET /wallet balance responses also serve a distorted figure
  - All financial operations appear to succeed — the attacker keeps trying

The balance distortion is bounded (±10%) to stay within a realistic range
while ensuring the attacker never sees the true state.
"""

import json
import random
import asyncio
import logging
from fastapi import Request
from decoy_api.deception.strategies.base import BaseStrategy

logger = logging.getLogger("decoy.deception.fraud")

# Delays
FINANCIAL_DELAY = 1.2
DEFAULT_DELAY   = 0.3

# Paths that trigger financial response transformation
FINANCIAL_WRITE_OPS = ["/transfer", "/withdraw", "/pay-bill", "/topup"]

# Balance distortion range — believable but wrong
DISTORT_MIN = 0.88
DISTORT_MAX = 1.12


def _distort_balance(value_str: str) -> str:
    """Apply ±10% random distortion to a balance string."""
    try:
        value = float(value_str)
        distorted = value * random.uniform(DISTORT_MIN, DISTORT_MAX)
        return f"{distorted:.2f}"
    except (ValueError, TypeError):
        return value_str


class FraudStrategy(BaseStrategy):

    async def pre_process(self, request: Request) -> None:
        """
        Add a deliberate delay on financial endpoints.
        Mimics real compliance/AML processing latency — believable to attacker.
        """
        if any(op in request.url.path for op in FINANCIAL_WRITE_OPS) or "/wallet" in request.url.path:
            await asyncio.sleep(FINANCIAL_DELAY)
        else:
            await asyncio.sleep(DEFAULT_DELAY)

    async def post_process(
        self,
        body: bytes,
        status_code: int,
        path: str,
        session_id: str,
        engine_state: dict,
    ) -> tuple[bytes, int]:
        """
        Transform financial operation responses.

        Write operations (transfer/withdraw/pay-bill):
          - Return 202 with "queued for compliance review" messaging
          - Distort displayed balance so attacker tracks wrong numbers

        Read operations (GET /wallet):
          - Return 200 but with distorted balance
        """
        if status_code not in (200, 201):
            return body, status_code

        is_write = any(op in path for op in FINANCIAL_WRITE_OPS)
        is_read  = "/wallet" in path and not is_write

        if not (is_write or is_read):
            return body, status_code

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body, status_code

        if is_write:
            logger.info(
                "DECOY 💸 [FRAUD] intercepting financial write op: path=%s sid=%s",
                path, session_id,
            )
            data["message"] = "Transaction submitted for compliance review"
            data["status"]  = "PENDING_REVIEW"
            data["review_id"] = f"rev_{session_id[-6:]}_{random.randint(1000, 9999)}"

            if "new_balance" in data:
                original = data["new_balance"]
                data["new_balance"] = _distort_balance(str(original))

            return json.dumps(data).encode(), 202

        if is_read:
            if "balance" in data:
                data["balance"] = _distort_balance(str(data["balance"]))
            return json.dumps(data).encode(), 200

        return body, status_code