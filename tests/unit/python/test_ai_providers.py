#!/usr/bin/env python3
"""Unit tests for lib/ai (no network required)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from lib.ai.analyzer import AnalyzerConfig, analyze_results, read_category_data, save_markdown_or_text
from lib.ai.providers.base import ProviderConfig, ProviderError
from lib.ai.providers.factory import create_provider, normalize_provider_name, resolve_provider_type
from lib.ai.providers.mock_provider import MockProvider
from lib.ai.redaction import redact_text


class MockProviderTests(unittest.TestCase):
    def test_factory_mock_provider(self) -> None:
        provider = create_provider(ProviderConfig(provider="mock", integrator="pydantic_ai"))
        self.assertIsInstance(provider, MockProvider)
        self.assertEqual(provider.generate("hello"), "mock-analysis: hello")

    def test_analyze_results_with_mock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "osint"))
            with open(os.path.join(tmp, "osint", "emails.txt"), "w", encoding="utf-8") as handle:
                handle.write("admin@example.com\n")
            prompts_path = ROOT / "data" / "ai" / "prompts.json"
            with open(prompts_path, "r", encoding="utf-8") as handle:
                prompts = json.load(handle)
            provider = MockProvider()
            cfg = AnalyzerConfig(
                results_dir=tmp,
                output_dir=tmp,
                report_type="brief",
                output_format="md",
                prompts=prompts,
                redact=True,
            )
            results = analyze_results(provider, cfg)
            self.assertIn("osint", results)
            self.assertIn("overview", results)
            self.assertGreaterEqual(len(provider.calls), 1)


class ProviderFactoryTests(unittest.TestCase):
    def test_normalize_aliases(self) -> None:
        self.assertEqual(normalize_provider_name("vllm"), "openai_compatible")
        self.assertEqual(normalize_provider_name("unsloth"), "openai_compatible")
        self.assertEqual(normalize_provider_name("lmstudio"), "openai_compatible")

    def test_resolve_auto_prefers_base_url(self) -> None:
        cfg = ProviderConfig(provider="auto", base_url="http://127.0.0.1:8000/v1")
        self.assertEqual(resolve_provider_type(cfg), "openai_compatible")

    def test_resolve_auto_defaults_remote_compatible(self) -> None:
        cfg = ProviderConfig(provider="auto")
        self.assertEqual(resolve_provider_type(cfg), "openai_compatible")

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False)
    def test_resolve_auto_openai_with_key(self) -> None:
        cfg = ProviderConfig(provider="auto")
        self.assertEqual(resolve_provider_type(cfg), "openai")

    def test_create_provider_unknown_integrator(self) -> None:
        cfg = ProviderConfig(integrator="unknown")
        with self.assertRaises(ProviderError):
            create_provider(cfg)

    @patch.dict(os.environ, {"AI_REMOTE_ONLY": "true"}, clear=False)
    def test_remote_only_blocks_ollama(self) -> None:
        cfg = ProviderConfig(provider="ollama", integrator="pydantic_ai", model="llama3")
        with self.assertRaises(ProviderError):
            create_provider(cfg)

    @patch.dict("sys.modules", {"httpx": MagicMock()})
    def test_openai_compatible_healthcheck_sends_bearer(self) -> None:
        from lib.ai.providers.pydantic_ai_provider import PydanticAIProvider

        mock_httpx = sys.modules["httpx"]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_httpx.get.return_value = mock_response

        cfg = ProviderConfig(
            provider="openai_compatible",
            integrator="pydantic_ai",
            model="test-model",
            base_url="http://127.0.0.1:8888/v1",
            api_key="secret-key",
        )
        provider = object.__new__(PydanticAIProvider)
        provider._config = cfg
        provider._ping_openai_compatible()
        mock_httpx.get.assert_called_once()
        _args, kwargs = mock_httpx.get.call_args
        self.assertEqual(_args[0], "http://127.0.0.1:8888/v1/models")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer secret-key")


class RedactionTests(unittest.TestCase):
    def test_redact_email_and_bearer(self) -> None:
        raw = "contact admin@example.com with Bearer secret-token-123"
        out = redact_text(raw)
        self.assertNotIn("admin@example.com", out)
        self.assertIn("[REDACTED_EMAIL]", out)
        self.assertIn("[REDACTED_TOKEN]", out)


class AnalyzerTests(unittest.TestCase):
    def test_read_category_data_truncates_and_redacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "osint"))
            path = os.path.join(tmp, "osint", "emails.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("user@example.com\n" + ("x" * 100))

            cfg = AnalyzerConfig(
                results_dir=tmp,
                output_dir=tmp,
                report_type="brief",
                output_format="md",
                prompts={},
                max_chars_per_file=20,
                max_files_per_category=5,
                redact=True,
            )
            data = read_category_data("osint", cfg)
            self.assertIn("[REDACTED_EMAIL]", data)
            self.assertLessEqual(len(data), 200)

    def test_save_outputs_md_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = AnalyzerConfig(
                results_dir=tmp,
                output_dir=tmp,
                report_type="brief",
                output_format="md",
                prompts={},
                output_json=os.path.join(tmp, "out.json"),
            )
            results = {"osint": "finding"}
            out_file = save_markdown_or_text(
                results,
                cfg,
                model_name="test-model",
                provider_name="mock/test",
            )
            self.assertTrue(os.path.isfile(out_file))
            with open(cfg.output_json, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["model"], "test-model")
            self.assertEqual(payload["categories"]["osint"], "finding")


if __name__ == "__main__":
    unittest.main()
