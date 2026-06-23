#!/usr/bin/env python3
"""CLI entrypoint for reconFTW AI report generation."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Ensure repository root is importable when invoked as a script path.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lib.ai.analyzer import (  # noqa: E402
    OUTPUT_FORMATS,
    REPORT_TYPES,
    AnalyzerConfig,
    analyze_results,
    load_prompts,
    save_markdown_or_text,
)
from lib.ai.providers.base import ProviderConfig, ProviderError  # noqa: E402
from lib.ai.providers.factory import create_provider, resolve_provider_type  # noqa: E402
from lib.reconftw_config import bootstrap_python_config  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="reconFTW AI — multi-provider scan analysis")
    parser.add_argument("--results-dir", required=True, help="Directory with reconFTW results")
    parser.add_argument("--output-dir", required=True, help="Directory for generated reports")
    parser.add_argument("--output-json", default="", help="Optional JSON summary output path")
    parser.add_argument("--model", default=os.environ.get("AI_MODEL", "llama3:8b"))
    parser.add_argument("--provider", default=os.environ.get("AI_PROVIDER", "auto"))
    parser.add_argument(
        "--integrator",
        default=os.environ.get("AI_INTEGRATOR", "pydantic_ai"),
        choices=["pydantic_ai", "langchain"],
    )
    parser.add_argument("--base-url", default=os.environ.get("AI_BASE_URL", ""))
    parser.add_argument("--api-key", default=os.environ.get("AI_API_KEY", ""))
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default=os.environ.get("AI_REPORT_TYPE", "md"))
    parser.add_argument("--report-type", choices=REPORT_TYPES, default=os.environ.get("AI_REPORT_PROFILE", "bughunter"))
    parser.add_argument("--prompts-file", required=True)
    parser.add_argument("--max-chars-per-file", type=int, default=int(os.environ.get("AI_MAX_CHARS_PER_FILE", "50000")))
    parser.add_argument("--max-files-per-category", type=int, default=int(os.environ.get("AI_MAX_FILES_PER_CATEGORY", "200")))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("AI_TIMEOUT_SECONDS", "120")))
    parser.add_argument("--redact", dest="redact", action="store_true", default=True)
    parser.add_argument("--no-redact", dest="redact", action="store_false")
    parser.add_argument("--allow-model-pull", action="store_true", default=False)
    parser.add_argument("--strict", action="store_true", default=False)
    parser.add_argument("--skip-healthcheck", action="store_true", default=False)
    parser.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="Use offline mock provider (no LLM server required)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    bootstrap_python_config()
    args = build_parser().parse_args(argv)

    if not os.path.isdir(args.results_dir):
        print(f"[ERROR] Results directory not found: {args.results_dir}", file=sys.stderr)
        return 1

    try:
        prompts = load_prompts(args.prompts_file)
    except OSError as exc:
        print(f"[ERROR] Unable to read prompts file: {exc}", file=sys.stderr)
        return 1

    if args.mock:
        provider_config = ProviderConfig(
            provider="mock",
            integrator="pydantic_ai",
            model="mock",
        )
    else:
        api_key = args.api_key or os.environ.get("AI_API_KEY") or os.environ.get("OPENAI_API_KEY") or None
        base_url = args.base_url or os.environ.get("AI_BASE_URL") or None
        provider_config = ProviderConfig(
            provider=args.provider,
            integrator=args.integrator,
            model=args.model,
            base_url=base_url,
            api_key=api_key,
            allow_model_pull=args.allow_model_pull,
            timeout_seconds=args.timeout,
        )

    skip_health = args.skip_healthcheck or os.environ.get("AI_SKIP_HEALTHCHECK", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    try:
        provider = create_provider(provider_config)
        if not skip_health and not args.mock:
            provider.healthcheck()
    except ProviderError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    analyzer_config = AnalyzerConfig(
        results_dir=args.results_dir,
        output_dir=args.output_dir,
        report_type=args.report_type,
        output_format=args.output_format,
        prompts=prompts,
        max_chars_per_file=args.max_chars_per_file,
        max_files_per_category=args.max_files_per_category,
        redact=args.redact,
        strict=args.strict,
        output_json=args.output_json or None,
    )

    resolved = resolve_provider_type(provider_config)
    if args.mock:
        endpoint = "mock (offline)"
    else:
        endpoint = args.base_url or os.environ.get("AI_BASE_URL") or ""
        if not endpoint and resolved == "openai":
            endpoint = "OpenAI API"
        elif not endpoint and resolved == "anthropic":
            endpoint = "Anthropic API"
    print(
        f"[*] Analyzing with integrator={args.integrator} provider={resolved} "
        f"model={args.model} report={args.report_type}"
    )
    if endpoint:
        print(f"[*] Endpoint: {endpoint}")

    try:
        results = analyze_results(provider, analyzer_config)
        output_file = save_markdown_or_text(
            results,
            analyzer_config,
            model_name=args.model,
            provider_name=provider.name,
        )
    except ProviderError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[*] Results saved to {output_file}")
    if analyzer_config.output_json:
        print(f"[*] JSON summary saved to {analyzer_config.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
