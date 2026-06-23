"""Scan result aggregation and LLM report generation."""

from __future__ import annotations

import glob
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List

from lib.ai.providers.base import LLMProvider, ProviderError
from lib.ai.redaction import redact_text

REPORT_TYPES = ("executive", "brief", "bughunter")
OUTPUT_FORMATS = ("txt", "md")
CATEGORIES = ("osint", "subdomains", "hosts", "webs")


@dataclass
class AnalyzerConfig:
    results_dir: str
    output_dir: str
    report_type: str
    output_format: str
    prompts: dict
    max_chars_per_file: int = 50_000
    max_files_per_category: int = 200
    redact: bool = True
    strict: bool = False
    output_json: str | None = None


def load_prompts(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _iter_category_files(category: str, results_dir: str) -> Iterable[str]:
    category_dir = os.path.join(results_dir, category)
    if not os.path.isdir(category_dir):
        return []
    return sorted(
        path
        for path in glob.glob(os.path.join(category_dir, "**/*"), recursive=True)
        if os.path.isfile(path)
    )


def read_category_data(category: str, config: AnalyzerConfig) -> str:
    files = list(_iter_category_files(category, config.results_dir))
    if not files:
        return f"[Info] No files found in {category}."

    chunks: List[str] = []
    for file_path in files[: config.max_files_per_category]:
        rel = os.path.relpath(file_path, config.results_dir)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                body = handle.read(config.max_chars_per_file)
        except OSError as exc:
            chunks.append(f"[Error] Failed to read {rel}: {exc}")
            continue
        if config.redact:
            body = redact_text(body)
        chunks.append(f"--- {rel} ---\n{body.strip()}")

    if not chunks:
        return f"[Info] No readable files in {category}."
    return "\n".join(chunks)


def _is_empty_payload(payload: str) -> bool:
    lowered = payload.lower()
    return lowered.startswith("[info]") or lowered.startswith("[error]")


def process_category(
    category: str,
    data: str,
    provider: LLMProvider,
    report_type: str,
    prompts: dict,
) -> str:
    if _is_empty_payload(data):
        return data

    template = prompts.get(report_type, {}).get(category, "Analyze this data:\n{data}")
    prompt = template.format(data=data)
    return provider.generate(prompt)


def analyze_results(provider: LLMProvider, config: AnalyzerConfig) -> Dict[str, str]:
    if config.report_type not in REPORT_TYPES:
        raise ProviderError(f"Invalid report type: {config.report_type}")

    raw_by_category: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=len(CATEGORIES)) as pool:
        futures = {
            pool.submit(read_category_data, category, config): category for category in CATEGORIES
        }
        for future in as_completed(futures):
            category = futures[future]
            raw_by_category[category] = future.result()

    if config.strict:
        missing = [cat for cat in CATEGORIES if _is_empty_payload(raw_by_category[cat])]
        if missing:
            raise ProviderError(f"Strict mode: missing data for categories: {', '.join(missing)}")

    results: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=len(CATEGORIES)) as pool:
        futures = {
            pool.submit(
                process_category,
                category,
                raw_by_category[category],
                provider,
                config.report_type,
                config.prompts,
            ): category
            for category in CATEGORIES
        }
        for future in as_completed(futures):
            category = futures[future]
            results[category] = future.result()

    overview_data = "\n\n".join(f"{cat.upper()}:\n{raw_by_category[cat]}" for cat in CATEGORIES)
    results["overview"] = process_category(
        "overview", overview_data, provider, config.report_type, config.prompts
    )
    return results


def save_markdown_or_text(
    results: Dict[str, str],
    config: AnalyzerConfig,
    *,
    model_name: str,
    provider_name: str,
) -> str:
    os.makedirs(config.output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = "md" if config.output_format == "md" else "txt"
    output_file = os.path.join(
        config.output_dir,
        f"reconftw_analysis_{config.report_type}_{timestamp}.{ext}",
    )

    with open(output_file, "w", encoding="utf-8") as handle:
        if config.output_format == "md":
            handle.write("# ReconFTW AI Analysis\n\n")
            handle.write(f"- **Provider**: `{provider_name}`\n")
            handle.write(f"- **Model**: `{model_name}`\n")
            handle.write(f"- **Report Type**: `{config.report_type}`\n")
            handle.write(f"- **Date**: `{timestamp}`\n\n")
            for category, interpretation in results.items():
                handle.write(f"## {category.upper()}\n\n{interpretation}\n\n")
        else:
            handle.write(
                f"ReconFTW AI Analysis\nProvider: {provider_name}\nModel: {model_name}\n"
                f"Report Type: {config.report_type}\nDate: {timestamp}\n"
            )
            handle.write("=" * 60 + "\n\n")
            for category, interpretation in results.items():
                handle.write(f"=== {category.upper()} ===\n{interpretation}\n\n")

    if config.output_json:
        payload = {
            "generated_at": timestamp,
            "provider": provider_name,
            "model": model_name,
            "report_type": config.report_type,
            "categories": results,
        }
        with open(config.output_json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    return output_file
