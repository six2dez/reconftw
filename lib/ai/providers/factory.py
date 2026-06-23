"""Provider factory and auto-detection."""

from __future__ import annotations

import os
from typing import Type

from lib.ai.providers.base import LLMProvider, ProviderConfig, ProviderError

# Aliases map to canonical provider types.
_PROVIDER_ALIASES = {
    "auto": "auto",
    "ollama": "ollama",
    "openai": "openai",
    "openai_compatible": "openai_compatible",
    "openai-compat": "openai_compatible",
    "vllm": "openai_compatible",
    "unsloth": "openai_compatible",
    "lmstudio": "openai_compatible",
    "anthropic": "anthropic",
    "mock": "mock",
    "offline": "mock",
}


def normalize_provider_name(name: str) -> str:
    key = (name or "auto").strip().lower()
    return _PROVIDER_ALIASES.get(key, key)


def resolve_provider_type(config: ProviderConfig) -> str:
    """Pick a concrete provider when config.provider is auto."""
    explicit = normalize_provider_name(config.provider)
    if explicit != "auto":
        return explicit

    if config.base_url or os.environ.get("AI_BASE_URL"):
        return "openai_compatible"

    if config.api_key or os.environ.get("OPENAI_API_KEY"):
        return "openai"

    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"

    if normalize_provider_name(os.environ.get("AI_PROVIDER", "")) == "mock":
        return "mock"

    # Default: remote OpenAI-compatible API (no local Ollama/GPU).
    return "openai_compatible"


def _remote_only_enabled() -> bool:
    flag = os.environ.get("AI_REMOTE_ONLY", "")
    return flag.lower() in {"1", "true", "yes", "on"}


def create_provider(config: ProviderConfig) -> LLMProvider:
    """Build an LLM provider from config and integrator choice."""
    provider_type = resolve_provider_type(config)
    integrator = (config.integrator or "pydantic_ai").strip().lower()

    if provider_type == "mock":
        from lib.ai.providers.mock_provider import MockProvider

        return MockProvider()

    if provider_type == "ollama" and _remote_only_enabled():
        raise ProviderError(
            "AI_REMOTE_ONLY is set. Configure AI_BASE_URL + openai_compatible (or openai/anthropic API keys)."
        )

    if integrator in {"langchain", "langchain_openai"}:
        from lib.ai.providers.langchain_provider import LangChainProvider

        return LangChainProvider(config, provider_type=provider_type)

    if integrator in {"pydantic_ai", "pydantic-ai", "pydantic"}:
        from lib.ai.providers.pydantic_ai_provider import PydanticAIProvider

        return PydanticAIProvider(config, provider_type=provider_type)

    raise ProviderError(f"Unsupported AI integrator: {config.integrator}")


def registered_provider_types() -> tuple[str, ...]:
    return tuple(sorted(set(_PROVIDER_ALIASES.values())))
