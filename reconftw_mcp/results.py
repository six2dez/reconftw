"""Scan artifact indexing, report reading, and search (RAG-lite for LLM agents)."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconftw_mcp.layers import Layer, get_layer
from reconftw_mcp.paths import find_reconftw_root, scan_dir

# High-signal artifacts relative to Recon/<domain>/
KEY_ARTIFACTS: tuple[str, ...] = (
    "subdomains/subdomains.txt",
    "webs/webs_all.txt",
    "webs/webs.txt",
    "hosts/ips.txt",
    "hosts/portscan.txt",
    "osint/emails.txt",
    "osint/domain_info.txt",
    "vulns/nuclei.txt",
    "vulns/testssl.txt",
    "report/report.json",
    "report/index.html",
    "report/findings.csv",
    "report/latest/report.json",
    "ai_result/reconftw_analysis.json",
)

REPORT_SECTIONS: tuple[str, ...] = (
    "summary",
    "severities",
    "top_assets",
    "timeline",
    "links",
    "delta",
    "findings_csv",
    "full",
)

REPORT_FILES: tuple[str, ...] = (
    "report/report.json",
    "report/index.html",
    "report/findings.csv",
    "report/latest/report.json",
    "report/latest/index.html",
    "ai_result/reconftw_analysis.json",
)

TEXT_EXTENSIONS = {".txt", ".json", ".jsonl", ".md", ".csv", ".log", ".yaml", ".yml"}


@dataclass
class PathInfo:
    relative: str
    size_bytes: int
    exists: bool


@dataclass
class SearchHit:
    path: str
    line_number: int
    snippet: str


def get_scan_status(domain: str) -> dict:
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    called = base / ".called_fn"
    completed: list[str] = []
    if called.is_dir():
        completed = sorted(p.name.lstrip(".") for p in called.iterdir() if p.is_file())

    counts: dict[str, int] = {}
    for rel in KEY_ARTIFACTS:
        path = base / rel
        if path.is_file():
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    counts[rel] = sum(1 for _ in handle)
            except OSError:
                counts[rel] = 0

    return {
        "domain": domain,
        "scan_dir": str(base),
        "exists": base.is_dir(),
        "completed_functions": completed,
        "line_counts": counts,
    }


def get_result_paths(domain: str, layer_id: str | None = None) -> list[PathInfo]:
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    rel_paths: set[str] = set(KEY_ARTIFACTS)

    if layer_id:
        layer = get_layer(layer_id)
        rel_paths.update(layer.outputs)

    results: list[PathInfo] = []
    for rel in sorted(rel_paths):
        path = base / rel
        if path.is_file():
            results.append(PathInfo(relative=rel, size_bytes=path.stat().st_size, exists=True))
        elif path.is_dir() and path.exists():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in TEXT_EXTENSIONS:
                    rel_child = str(child.relative_to(base))
                    if child.stat().st_size <= 5_000_000:  # skip huge blobs in listing
                        results.append(
                            PathInfo(relative=rel_child, size_bytes=child.stat().st_size, exists=True)
                        )
    return results[:80]  # cap for LLM context


def search_results(
    domain: str,
    query: str,
    *,
    max_hits: int = 25,
    max_snippet: int = 240,
    path_glob: str = "",
) -> list[SearchHit]:
    """Linear search over text artifacts (RAG-lite; use narrow queries)."""
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    if not base.is_dir():
        return []

    pattern = re.compile(re.escape(query), re.IGNORECASE)
    hits: list[SearchHit] = []

    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        if path_glob and not Path(path.name).match(path_glob):
            rel = str(path.relative_to(base))
            if path_glob not in rel:
                continue
        if path.stat().st_size > 2_000_000:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_no, line in enumerate(handle, start=1):
                    if not pattern.search(line):
                        continue
                    snippet = line.strip()
                    if len(snippet) > max_snippet:
                        snippet = snippet[: max_snippet - 3] + "..."
                    hits.append(
                        SearchHit(
                            path=str(path.relative_to(base)),
                            line_number=line_no,
                            snippet=snippet,
                        )
                    )
                    if len(hits) >= max_hits:
                        return hits
        except OSError:
            continue
    return hits


def format_paths(paths: list[PathInfo], domain: str) -> str:
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    lines = [f"scan_dir: {base}", f"artifacts: {len(paths)}"]
    for info in paths:
        flag = "ok" if info.exists else "missing"
        lines.append(f"- [{flag}] {info.relative} ({info.size_bytes} bytes)")
    lines.append("Use search_results(domain, query) to read content; avoid cat-ing large files.")
    return "\n".join(lines)


def format_search(hits: list[SearchHit], query: str) -> str:
    if not hits:
        return f"No matches for query: {query!r}"
    lines = [f"query: {query!r}", f"hits: {len(hits)}"]
    for hit in hits:
        lines.append(f"{hit.path}:{hit.line_number}: {hit.snippet}")
    return "\n".join(lines)


def list_report_files(domain: str) -> list[PathInfo]:
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    results: list[PathInfo] = []
    for rel in REPORT_FILES:
        path = base / rel
        results.append(
            PathInfo(
                relative=rel,
                size_bytes=path.stat().st_size if path.is_file() else 0,
                exists=path.is_file(),
            )
        )
    # Newest AI markdown report
    ai_dir = base / "ai_result"
    if ai_dir.is_dir():
        md_files = sorted(ai_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if md_files:
            rel = str(md_files[0].relative_to(base))
            results.append(
                PathInfo(relative=rel, size_bytes=md_files[0].stat().st_size, exists=True)
            )
    return results


def _load_report_json(base: Path) -> dict[str, Any]:
    for rel in ("report/report.json", "report/latest/report.json"):
        path = base / rel
        if path.is_file():
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, dict):
                return payload
    return {}


def read_report(
    domain: str,
    section: str = "summary",
    *,
    max_chars: int = 12000,
    csv_rows: int = 25,
) -> str:
    """Return a pruned slice of consolidated report data for LLM consumption."""
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    if section not in REPORT_SECTIONS:
        raise KeyError(f"Unknown section {section!r}. Use: {', '.join(REPORT_SECTIONS)}")

    if section == "findings_csv":
        csv_path = base / "report/findings.csv"
        if not csv_path.is_file():
            return "findings_csv: missing (run generate_consolidated_report or full scan first)"
        lines: list[str] = []
        with csv_path.open("r", encoding="utf-8", errors="replace") as handle:
            reader = csv.reader(handle)
            for idx, row in enumerate(reader):
                if idx >= csv_rows + 1:
                    lines.append(f"... truncated after {csv_rows} data rows")
                    break
                lines.append(",".join(row))
        return "findings_csv preview:\n" + "\n".join(lines)

    payload = _load_report_json(base)
    if not payload:
        return (
            "report/report.json missing. Call run_function(domain, "
            "'generate_consolidated_report') after scan modules, or run a full scan end()."
        )

    if section == "full":
        text = json.dumps(payload, indent=2)
        if len(text) > max_chars:
            return text[: max_chars - 3] + "..."
        return text

    if section == "summary":
        subset = {
            "generated_at": payload.get("generated_at"),
            "domain": payload.get("domain"),
            "mode": payload.get("mode"),
            "runtime": payload.get("runtime"),
            "metadata": payload.get("metadata"),
            "summary": payload.get("summary"),
        }
    elif section == "severities":
        subset = {
            "severities": payload.get("severities"),
            "summary": {"findings_total": (payload.get("summary") or {}).get("findings_total")},
        }
    elif section == "top_assets":
        assets = payload.get("top_assets") or []
        subset = {"top_assets": assets[:50]}
    elif section == "timeline":
        timeline = payload.get("timeline") or []
        subset = {"timeline": timeline[-40:]}
    elif section == "links":
        subset = {"links": payload.get("links") or []}
    elif section == "delta":
        subset = {
            "delta_since_last": payload.get("delta_since_last"),
            "alerts_last": payload.get("alerts_last"),
        }
    else:
        subset = {}

    return json.dumps(subset, indent=2)


def read_ai_report(domain: str, *, max_chars: int = 12000) -> str:
    """Read AI analysis JSON or newest markdown summary."""
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    json_path = base / "ai_result/reconftw_analysis.json"
    if json_path.is_file():
        with json_path.open("r", encoding="utf-8") as handle:
            text = handle.read()
        if len(text) > max_chars:
            return text[: max_chars - 3] + "..."
        return text

    ai_dir = base / "ai_result"
    if ai_dir.is_dir():
        md_files = sorted(ai_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        if md_files:
            text = md_files[0].read_text(encoding="utf-8", errors="replace")
            if len(text) > max_chars:
                return text[: max_chars - 3] + "..."
            return text

    return (
        "No AI report found. Enable AI (reconftw -y) with AI_PROVIDER=mock for offline tests, "
        "or configure Ollama/OpenAI-compatible endpoint."
    )


def format_report_files(files: list[PathInfo], domain: str) -> str:
    root = find_reconftw_root()
    base = scan_dir(root, domain)
    lines = [f"scan_dir: {base}", "report artifacts:"]
    for info in files:
        flag = "ok" if info.exists else "missing"
        lines.append(f"- [{flag}] {info.relative} ({info.size_bytes} bytes)")
    lines.append("Use read_report(domain, section) — prefer summary/severities over full.")
    return "\n".join(lines)
