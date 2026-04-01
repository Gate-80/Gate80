"""
GATE80 — Decoy API
deception/strategies/unknown.py

Deception strategy for unknown_suspicious sessions.

Behavior:
  - 1.0s delay on all requests (generic friction)
  - Responses passed through unmodified — the decoy behaves normally
  - The session stays in the decoy permanently (sticky flag in proxy)

This is the fallback for sessions that the Isolation Forest flagged as
anomalous but where the behavior classifier found no dominant attack pattern.
The attacker interacts with a fully functional fake wallet indefinitely.
"""

import asyncio
import logging
from fastapi import Request
from decoy_api.deception.strategies.base import BaseStrategy

logger = logging.getLogger("decoy.deception.unknown")

DEFAULT_DELAY = 1.0


class UnknownStrategy(BaseStrategy):

    async def pre_process(self, request: Request) -> None:
        await asyncio.sleep(DEFAULT_DELAY)

    async def post_process(
        self,
        body: bytes,
        status_code: int,
        path: str,
        session_id: str,
        engine_state: dict,
    ) -> tuple[bytes, int]:
        # Pass through — let the decoy behave as the real API
        return body, status_code