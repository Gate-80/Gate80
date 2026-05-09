"""
Anthropic backend for the deception planner.

Uses Claude Haiku 4.5 by default — the lightest and fastest Claude model.

Env vars:
  ANTHROPIC_API_KEY (required)
  ANTHROPIC_MODEL   (optional, default "claude-haiku-4-5")
"""
from __future__ import annotations

import os

from anthropic import AsyncAnthropic

from decoy_api.deception.backends.base import BaseDeceptionBackend


DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5")
DEFAULT_MAX_TOKENS = 512
DEFAULT_TEMPERATURE = 0.2


class AnthropicBackend(BaseDeceptionBackend):

    def __init__(self) -> None:
        self._client = AsyncAnthropic()
        self._model = DEFAULT_MODEL
        self.name = self._model

    async def generate_raw(self, prompt: str) -> str:
        message = await self._client.messages.create(
            model=self._model,
            max_tokens=DEFAULT_MAX_TOKENS,
            temperature=DEFAULT_TEMPERATURE,
            messages=[{"role": "user", "content": prompt}],
        )

        for block in message.content:
            if getattr(block, "type", None) == "text":
                return block.text

        raise ValueError("Anthropic response had no text content blocks")
