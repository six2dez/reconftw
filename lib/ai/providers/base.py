"""Abstract LLM provider interface for reconFTW AI reporting."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ProviderConfig:
    """Runtime configuration for an LLM backend."""

    provider: str = "auto"
    integrator: str = "pydantic_ai"
    model: str = "llama3:8b"
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    allow_model_pull: bool = False
    timeout_seconds: float = 120.0
    extra: dict[str, str] = field(default_factory=dict)


class LLMProvider(ABC):
    """Provider-agnostic interface for text generation."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider identifier."""

    @abstractmethod
    def healthcheck(self) -> None:
        """Validate connectivity; raise on failure."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate model text for a single prompt."""


class ProviderError(RuntimeError):
    """Raised when provider setup or generation fails."""
