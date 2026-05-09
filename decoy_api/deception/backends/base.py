"""
Pluggable LLM backend interface for the deception planner.

Each backend only has to know how to take a prompt string and return raw
text. Validation, parsing, and allowlist enforcement happen in the planner
itself, so backends stay simple and interchangeable.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseDeceptionBackend(ABC):
    """Abstract base class for LLM backends."""

    name: str = "unknown"

    @abstractmethod
    async def generate_raw(self, prompt: str) -> str:
        """Send the prompt to the LLM and return raw text response.

        Implementations should:
          - Raise an exception on any error (network, auth, rate limit, etc.).
          - Return the LLM's raw output as a string.
        """
        ...
