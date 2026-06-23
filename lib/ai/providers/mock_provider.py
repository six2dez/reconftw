"""Offline mock LLM provider for tests and CI (no network, no API keys)."""

from __future__ import annotations

from lib.ai.providers.base import LLMProvider


class MockProvider(LLMProvider):
    """Deterministic provider that echoes category hints — never calls external APIs."""

    def __init__(self, *, prefix: str = "mock-analysis") -> None:
        self._prefix = prefix
        self.calls: list[str] = []

    @property
    def name(self) -> str:
        return "mock/offline"

    def healthcheck(self) -> None:
        return None

    def generate(self, prompt: str) -> str:
        self.calls.append(prompt)
        head = prompt.strip().splitlines()[0][:120] if prompt.strip() else "empty"
        return f"{self._prefix}: {head}"
