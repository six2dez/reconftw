#!/usr/bin/env python3
"""Tests for lib/reconftw_config secrets loading."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from lib.reconftw_config import bootstrap_python_config, load_secrets_file, parse_shell_assignments


class SecretsParserTests(unittest.TestCase):
    def test_parse_export_and_plain_assignments(self) -> None:
        text = """
# comment
export AI_BASE_URL="http://192.168.1.74:8888/v1"
AI_MODEL='gpt-test'
AI_API_KEY=sk-secret
NOT_A_SECRET=ignored
"""
        parsed = parse_shell_assignments(text)
        self.assertEqual(parsed["AI_BASE_URL"], "http://192.168.1.74:8888/v1")
        self.assertEqual(parsed["AI_MODEL"], "gpt-test")
        self.assertEqual(parsed["AI_API_KEY"], "sk-secret")
        self.assertNotIn("NOT_A_SECRET", parsed)

    def test_env_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reconftw.sh").write_text("# stub\n", encoding="utf-8")
            secrets = root / "secrets.cfg"
            secrets.write_text('AI_BASE_URL="http://from-file"\n', encoding="utf-8")
            os.environ["AI_BASE_URL"] = "http://from-env"
            try:
                loaded = load_secrets_file(secrets, apply=True)
                self.assertEqual(loaded, {})
                self.assertEqual(os.environ["AI_BASE_URL"], "http://from-env")
            finally:
                os.environ.pop("AI_BASE_URL", None)

    def test_bootstrap_sets_ai_api_key_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reconftw.sh").write_text("# stub\n", encoding="utf-8")
            (root / "secrets.cfg").write_text(
                'OPENAI_API_KEY="sk-openai"\nAI_BASE_URL="http://llm.local/v1"\n',
                encoding="utf-8",
            )
            for key in ("AI_API_KEY", "AI_BASE_URL", "OPENAI_API_KEY", "RECONFTW_ROOT"):
                os.environ.pop(key, None)
            try:
                result = bootstrap_python_config(root)
                self.assertEqual(result, root)
                self.assertEqual(os.environ["AI_API_KEY"], "sk-openai")
                self.assertEqual(os.environ["AI_BASE_URL"], "http://llm.local/v1")
            finally:
                for key in ("AI_API_KEY", "AI_BASE_URL", "OPENAI_API_KEY", "RECONFTW_ROOT"):
                    os.environ.pop(key, None)


if __name__ == "__main__":
    unittest.main()
