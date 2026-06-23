"""pydantic-ai integrator — default backend for reconFTW AI."""

from __future__ import annotations

import os
import subprocess
from typing import Any

from lib.ai.providers.base import LLMProvider, ProviderConfig, ProviderError
from lib.ai.providers.factory import normalize_provider_name


class PydanticAIProvider(LLMProvider):
    """Wrap pydantic-ai Agent with OpenAI-compatible, Ollama, and Anthropic models."""

    def __init__(self, config: ProviderConfig, *, provider_type: str) -> None:
        self._config = config
        self._provider_type = normalize_provider_name(provider_type)
        self._agent = self._build_agent()

    @property
    def name(self) -> str:
        return f"pydantic-ai/{self._provider_type}:{self._config.model}"

    def healthcheck(self) -> None:
        if self._provider_type == "ollama":
            if os.environ.get("AI_REMOTE_ONLY", "").lower() in {"1", "true", "yes", "on"}:
                raise ProviderError("AI_REMOTE_ONLY: local Ollama healthcheck disabled")
            self._ensure_ollama()
            return
        if self._provider_type == "openai_compatible":
            self._ping_openai_compatible()
            return
        # OpenAI / Anthropic: defer to first generate; keys validated at request time.

    def _ping_openai_compatible(self) -> None:
        import httpx

        base_url = self._config.base_url or os.environ.get("AI_BASE_URL") or "http://127.0.0.1:8000/v1"
        url = f"{base_url.rstrip('/')}/models"
        headers: dict[str, str] = {}
        api_key = self._config.api_key or os.environ.get("AI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            response = httpx.get(url, timeout=5.0, headers=headers or None)
            if response.status_code in {401, 403}:
                raise ProviderError(
                    f"OpenAI-compatible endpoint rejected credentials: {url} ({response.status_code})"
                )
            if response.status_code >= 500:
                raise ProviderError(f"OpenAI-compatible endpoint unhealthy: {url} ({response.status_code})")
            if response.status_code >= 400:
                raise ProviderError(f"OpenAI-compatible endpoint error: {url} ({response.status_code})")
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Unable to reach OpenAI-compatible endpoint at {url}: {exc}") from exc

    def generate(self, prompt: str) -> str:
        try:
            result = self._agent.run_sync(prompt)
        except Exception as exc:
            raise ProviderError(f"Generation failed ({self.name}): {exc}") from exc

        output = getattr(result, "output", None)
        if output is None:
            output = getattr(result, "data", None)
        if output is None:
            raise ProviderError("Empty response from model")
        return str(output).strip()

    def _build_agent(self) -> Any:
        try:
            from pydantic_ai import Agent
        except ImportError as exc:
            raise ProviderError(
                "pydantic-ai is not installed. Run: uv pip install pydantic-ai --python .venv/bin/python3"
            ) from exc

        model = self._build_model()
        return Agent(model)

    def _build_model(self) -> Any:
        model_name = self._config.model

        if self._provider_type == "ollama":
            from pydantic_ai.models.ollama import OllamaModel

            return OllamaModel(model_name)

        if self._provider_type == "anthropic":
            from pydantic_ai.models.anthropic import AnthropicModel

            return AnthropicModel(model_name)

        if self._provider_type in {"openai", "openai_compatible"}:
            from pydantic_ai.models.openai import OpenAIModel
            from pydantic_ai.providers.openai import OpenAIProvider

            api_key = self._config.api_key or os.environ.get("OPENAI_API_KEY") or "local"
            provider_kwargs: dict[str, Any] = {"api_key": api_key}
            base_url = self._config.base_url
            if self._provider_type == "openai_compatible":
                base_url = base_url or os.environ.get("AI_BASE_URL") or "http://127.0.0.1:8000/v1"
            if base_url:
                provider_kwargs["base_url"] = base_url.rstrip("/")
            return OpenAIModel(model_name, provider=OpenAIProvider(**provider_kwargs))

        raise ProviderError(f"Unsupported provider type: {self._provider_type}")

    def _ensure_ollama(self) -> None:
        import shutil

        if shutil.which("ollama") is None:
            raise ProviderError("ollama not found in PATH")

        try:
            subprocess.run(
                ["ollama", "list"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ProviderError("Ollama is not running. Start with: ollama serve") from exc

        if not self._config.allow_model_pull:
            return

        try:
            listed = subprocess.check_output(["ollama", "list"], text=True, timeout=30)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ProviderError("Unable to query ollama models") from exc

        base_model = self._config.model.split(":", 1)[0]
        if base_model not in listed and self._config.model not in listed:
            subprocess.run(["ollama", "pull", self._config.model], check=True, timeout=600)
