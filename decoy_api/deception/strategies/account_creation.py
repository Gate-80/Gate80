"""
GATE80 — Decoy API
deception/strategies/account_creation.py

Deception strategy for account-creation abuse sessions.

OWASP Mapping:
  - OAT-019 (Account Creation / Massive Account Registration)
  - API2:2023 Broken Authentication

Behavior:
  - 0.5s delay on /auth/sign-up requests (compliance-check appearance)
  - Successful signups (201) wrapped with fake "pending email verification"
    so the attacker thinks accounts were created but unusable until verified
  - Velocity tracker — if the attacker creates more than BURST_THRESHOLD
    accounts within BURST_WINDOW seconds, the response gets a fake
    throttle warning. The signup still appears to succeed.
  - Goal: keep the attacker registering forever without producing any real
    accounts that could be used downstream.

This pairs with the standard digital-wallet sign-up endpoint:
    POST /api/v1/auth/sign-up
"""

import json
import asyncio
import logging
import time
import uuid
from fastapi import Request
from decoy_api.deception.strategies.base import BaseStrategy

logger = logging.getLogger("decoy.deception.account_creation")

SIGNUP_DELAY     = 0.5
DEFAULT_DELAY    = 0.3
BURST_THRESHOLD  = 10    # signups within burst window
BURST_WINDOW_SEC = 60    # seconds


class AccountCreationStrategy(BaseStrategy):

    async def pre_process(self, request: Request) -> None:
        """Slow signups slightly so they look like compliance-checked flows."""
        if "/auth/sign-up" in request.url.path:
            await asyncio.sleep(SIGNUP_DELAY)
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
        # Only intercept successful sign-ups; everything else passes through.
        if "/auth/sign-up" not in path:
            return body, status_code
        if status_code not in (200, 201):
            return body, status_code

        # ── Track signup velocity inside burst window ─────────────────────────
        velocity_key = f"account_creation:signup_times:{session_id}"
        signup_times: list[float] = engine_state.get(velocity_key, [])
        now = time.time()

        # Drop timestamps older than the burst window.
        signup_times = [t for t in signup_times if now - t < BURST_WINDOW_SEC]
        signup_times.append(now)
        engine_state[velocity_key] = signup_times

        # ── Wrap response so attacker sees "pending verification" ─────────────
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body, status_code
        if not isinstance(data, dict):
            return body, status_code

        # Replace the user_id with a decoy-only identifier so downstream
        # use of returned IDs against the real backend will not work.
        data["user_id"] = f"u_decoy_{uuid.uuid4().hex[:8]}"
        data["verification_status"] = "pending_email_verification"
        data["verification_message"] = "A verification link has been sent to your email."

        if len(signup_times) >= BURST_THRESHOLD:
            data["throttle_warning"] = (
                "Unusual signup activity detected. New accounts will be reviewed manually."
            )
            logger.warning(
                "DECOY 👥 [ACCT_CREATE] burst threshold hit: %d signups in %ds for sid=%s",
                len(signup_times), BURST_WINDOW_SEC, session_id,
            )
        else:
            logger.info(
                "DECOY 👥 [ACCT_CREATE] decoy signup #%d in window for sid=%s",
                len(signup_times), session_id,
            )

        # Return 201 to keep the appearance of a successful registration.
        return json.dumps(data).encode(), 201
