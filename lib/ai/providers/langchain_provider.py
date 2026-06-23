"""Optional LangChain integrator (OpenAI-compatible + Ollama via ChatOpenAI)."""

from __future__ import annotations

import os

from lib.ai.providers.base import LLMProvider, ProviderConfig, ProviderError
from lib.ai.providers.factory import normalize_provider_name


class LangChainProvider(LLMProvider):
    """LangChain-backed provider for teams already standardized on langchain."""

    def __init__(self, config: ProviderConfig, *, provider_type: str) -> None:
        self._config = config
        self._provider_type = normalize_provider_name(provider_type)
        self._llm = self._build_llm()

    @property
    def name(self) -> str:
        return f"langchain/{self._provider_type}:{self._config.model}"

    def healthcheck(self) -> None:
        if self._provider_type == "openai_compatible":
            base_url = self._config.base_url or os.environ.get("AI_BASE_URL") or "http://127.0.0.1:8000/v1"
            try:
                import httpx

                httpx.get(f"{base_url.rstrip('/')}/models", timeout=5.0)
            except Exception as exc:
                raise ProviderError(f"LangChain endpoint unreachable: {exc}") from exc

    def generate(self, prompt: str) -> str:
        try:
            from langchain_core.messages import HumanMessage

            response = self._llm.invoke([HumanMessage(content=prompt)])
        except Exception as exc:
            raise ProviderError(f"LangChain generation failed: {exc}") from exc

        content = getattr(response, "content", None)
        if not content:
            raise ProviderError("Empty LangChain response")
        return str(content).strip()

    def _build_llm(self) -> object:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise ProviderError(
                "langchain-openai is not installed. Run: uv pip install langchain-openai --python .venv/bin/python3"
            ) from exc

        kwargs: dict[str, object] = {
            "model": self._config.model,
            "timeout": self._config.timeout_seconds,
        }

        api_key = self._config.api_key or os.environ.get("OPENAI_API_KEY")
        if api_key:
            kwargs["api_key"] = api_key

        if self._provider_type == "openai_compatible":
            base_url = self._config.base_url or os.environ.get("AI_BASE_URL") or "http://127.0.0.1:8000/v1"
            kwargs["base_url"] = base_url.rstrip("/")
            kwargs.setdefault("api_key", "local")
        elif self._provider_type == "ollama":
            # Ollama exposes an OpenAI-compatible API on /v1 since recent versions.
            base_url = self._config.base_url or os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434/v1"
            kwargs["base_url"] = base_url.rstrip("/")
            kwargs.setdefault("api_key", "ollama")

        return ChatOpenAI(**kwargs)
