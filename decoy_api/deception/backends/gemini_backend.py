"""
Gemini backend — extracted from old GeminiDeceptionPlanner.

Env vars:
  GEMINI_API_KEY     (required)
  GEMINI_API_VERSION (optional, default "v1")
  GEMINI_MODEL       (optional, default "gemini-2.5-flash")
"""
from __future__ import annotations

import os
import httpx

from decoy_api.deception.backends.base import BaseDeceptionBackend


GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/{api_version}/models/"
    "{model}:generateContent?key={api_key}"
)
DEFAULT_API_VERSION = os.getenv("GEMINI_API_VERSION", "v1")
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
REQUEST_TIMEOUT = 10.0
DEFAULT_TEMPERATURE = 0.2


class GeminiBackend(BaseDeceptionBackend):

    def __init__(self) -> None:
        self._api_key = os.getenv("GEMINI_API_KEY")
        self._api_version = DEFAULT_API_VERSION
        self._model = DEFAULT_MODEL
        self.name = self._model

    async def generate_raw(self, prompt: str) -> str:
        if not self._api_key:
            raise RuntimeError("GEMINI_API_KEY not configured")

        url = GEMINI_API_URL.format(
            api_version=self._api_version,
            model=self._model,
            api_key=self._api_key,
        )
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": DEFAULT_TEMPERATURE},
        }

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()

        raw_payload = response.json()
        candidates = raw_payload.get("candidates") or []
        if not candidates:
            raise KeyError("missing candidates")

        parts = candidates[0]["content"]["parts"]
        for part in parts:
            text = part.get("text")
            if text:
                return text

        raise KeyError("missing text part")
