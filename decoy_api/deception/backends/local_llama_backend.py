"""
Local Llama backend for the deception planner — uses Ollama.

Setup:
  brew install ollama
  ollama serve
  ollama pull llama3.1:8b

Env vars:
  OLLAMA_HOST  (optional, default "http://localhost:11434")
  OLLAMA_MODEL (optional, default "llama3.1:8b")
"""
from __future__ import annotations

import os

from ollama import AsyncClient

from decoy_api.deception.backends.base import BaseDeceptionBackend


DEFAULT_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
DEFAULT_TEMPERATURE = 0.2


class LocalLlamaBackend(BaseDeceptionBackend):

    def __init__(self) -> None:
        self._client = AsyncClient(host=DEFAULT_HOST)
        self._model = DEFAULT_MODEL
        self.name = f"ollama-{self._model}"

    async def generate_raw(self, prompt: str) -> str:
        response = await self._client.chat(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": DEFAULT_TEMPERATURE},
        )

        content = response.get("message", {}).get("content")
        if not content:
            raise ValueError("Ollama response had no message content")
        return content
