"""MCP stdio server exposing reconFTW layers to LLM agents."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from reconftw_mcp.functions import FUNCTION_CATEGORIES, function_names, get_function, list_functions
from reconftw_mcp.layers import CRITICAL_LAYER_IDS, LAYERS, get_layer, layer_context_markdown, list_layers
from reconftw_mcp.paths import find_reconftw_root, tools_dir
from reconftw_mcp.results import (
    REPORT_SECTIONS,
    format_paths,
    format_report_files,
    format_search,
    get_result_paths,
    get_scan_status,
    list_report_files,
    read_ai_report,
    read_report,
    search_results,
)
from reconftw_mcp.runner import format_run_result, init_scan, run_function, run_layer

try:
    from lib.reconftw_config import bootstrap_python_config
except ImportError:  # pragma: no cover
    bootstrap_python_config = None  # type: ignore[misc, assignment]

server = Server("reconftw")

_LAYER_IDS = sorted(LAYERS.keys())
_FUNCTION_NAMES = list(function_names())

_WORKFLOW = (
    "Recommended flow: get_environment → init_scan(domain) → list_layers(tier=critical) → "
    "run_layer → get_scan_status → list_report_files → read_report(section=summary) → "
    "search_results for details. Never bulk-load Recon/<domain>/ into context."
)


def _text(payload: str) -> list[TextContent]:
    return [TextContent(type="text", text=payload)]


def _domain_prop() -> dict[str, Any]:
    return {
        "type": "string",
        "description": "Target domain (must match Recon/<domain>/ workspace).",
        "minLength": 1,
    }


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_environment",
            description=(
                "Verify RECONFTW_ROOT, tools dir ($HOME/Tools), and critical layer ids. "
                "Call first on new sessions. No scan I/O. "
                + _WORKFLOW
            ),
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
        Tool(
            name="list_layers",
            description=(
                "List predefined recon layers (osint, subs, web, vulns, recon modes). "
                "tier=critical → osint_quick, osint_passive, subs_passive, web_probe, waf_scan, ssl_scan "
                "(each ≤5 min). tier=standard → osint_full, subs_standard, web_detect, recon_passive, vulns_quick. "
                "tier=heavy → subs_brute, web_analyze, vulns_full, recon_full. "
                "Returns id, eta_minutes, usage — no file contents."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tier": {
                        "type": "string",
                        "enum": ["critical", "standard", "heavy"],
                        "description": "Filter by time budget. Omit for all layers.",
                    }
                },
                "additionalProperties": False,
            },
        ),
        Tool(
            name="list_functions",
            description=(
                "List individual reconFTW shell functions for run_function. "
                "Categories: osint (domain_info, emails, …), subdomains (sub_passive, sub_brute, …), "
                "web (webprobe_full, waf_checks, …), vulns (test_ssl, nuclei_check, …), "
                "report (generate_consolidated_report). Returns eta and prerequisites."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": list(FUNCTION_CATEGORIES),
                        "description": "Optional category filter.",
                    }
                },
                "additionalProperties": False,
            },
        ),
        Tool(
            name="get_layer_context",
            description=(
                "Pruned markdown context for one layer: when to use, functions/mode, config profile, "
                "output paths. No scan data. Use before run_layer."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "layer_id": {
                        "type": "string",
                        "enum": _LAYER_IDS,
                        "description": "Layer id from list_layers.",
                    }
                },
                "required": ["layer_id"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="init_scan",
            description=(
                "Create Recon/<domain>/ workspace (reconftw start). "
                "Required once before run_function on a new target. Idempotent."
            ),
            inputSchema={
                "type": "object",
                "properties": {"domain": _domain_prop()},
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="run_layer",
            description=(
                "Execute a predefined layer with tuned MCP config profiles. "
                "Critical (≤5m): osint_quick | osint_passive | subs_passive | web_probe | waf_scan | ssl_scan. "
                "Standard: osint_full (-n) | subs_standard (-s) | web_detect | recon_passive (-p) | vulns_quick. "
                "Heavy (confirm budget): subs_brute | web_analyze | vulns_full (-a) | recon_full (-r). "
                "Returns status + output path hints only."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": _domain_prop(),
                    "layer_id": {"type": "string", "enum": _LAYER_IDS},
                    "ensure_init": {
                        "type": "boolean",
                        "default": True,
                        "description": "Call init_scan if workspace missing.",
                    },
                },
                "required": ["domain", "layer_id"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="run_function",
            description=(
                "Run one reconFTW module function with correct workspace init. "
                "Common queries: domain_info, ip_info, emails, sub_passive, sub_crt, webprobe_full, "
                "waf_checks, test_ssl, crlf_checks, nuclei_check, generate_consolidated_report. "
                "Use list_functions for full catalog. Prefer run_layer for bundled workflows."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": _domain_prop(),
                    "function_name": {
                        "type": "string",
                        "enum": _FUNCTION_NAMES,
                        "description": "Shell function name from modules/*.sh.",
                    },
                    "ensure_init": {"type": "boolean", "default": True},
                },
                "required": ["domain", "function_name"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="get_scan_status",
            description=(
                "Lightweight progress: completed .called_fn markers and line counts for key artifacts "
                "(subdomains, webs, report.json, ai_result). Use before read_report."
            ),
            inputSchema={
                "type": "object",
                "properties": {"domain": _domain_prop()},
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="get_result_paths",
            description=(
                "List artifact paths + sizes under Recon/<domain>/ (no content). "
                "Optionally scope by layer_id. Cap 80 paths. Use before search_results/read_report."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": _domain_prop(),
                    "layer_id": {
                        "type": "string",
                        "enum": _LAYER_IDS,
                        "description": "Optional layer to include its output paths.",
                    },
                },
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="list_report_files",
            description=(
                "List report artifacts: report/report.json, report/index.html, report/findings.csv, "
                "report/latest/*, ai_result/reconftw_analysis.json, newest ai_result/*.md. Paths only."
            ),
            inputSchema={
                "type": "object",
                "properties": {"domain": _domain_prop()},
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="read_report",
            description=(
                "Read consolidated scan report (structured JSON slices). "
                "section=summary (default): counts + metadata. severities: nuclei severity breakdown. "
                "top_assets: hotlist. timeline: last module events. links: artifact quick links. "
                "delta: monitor deltas. findings_csv: CSV preview. full: entire JSON (truncated). "
                "Generate first with run_function(..., generate_consolidated_report) if missing."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": _domain_prop(),
                    "section": {
                        "type": "string",
                        "enum": list(REPORT_SECTIONS),
                        "default": "summary",
                        "description": "Report slice to return (keeps LLM context small).",
                    },
                    "max_chars": {
                        "type": "integer",
                        "default": 12000,
                        "minimum": 500,
                        "maximum": 50000,
                        "description": "Max chars for full section.",
                    },
                    "csv_rows": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "maximum": 200,
                        "description": "Rows for findings_csv section.",
                    },
                },
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="read_ai_report",
            description=(
                "Read AI analysis output (ai_result/reconftw_analysis.json or newest .md). "
                "Requires scan with -y/--ai or lib/ai/cli.py. Use AI_PROVIDER=mock for offline tests."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": _domain_prop(),
                    "max_chars": {
                        "type": "integer",
                        "default": 12000,
                        "minimum": 500,
                        "maximum": 50000,
                    },
                },
                "required": ["domain"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="search_results",
            description=(
                "RAG-lite grep over Recon/<domain>/ text artifacts (.txt, .json, .csv, .md, .log). "
                "Returns path:line snippets. Use narrow queries (emails, CVE, subdomain). "
                "path_glob filters by filename or path substring."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": _domain_prop(),
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Case-insensitive substring to find.",
                    },
                    "max_hits": {"type": "integer", "default": 25, "minimum": 1, "maximum": 100},
                    "path_glob": {
                        "type": "string",
                        "default": "",
                        "description": "Optional filter, e.g. 'subdomains' or '*.json'.",
                    },
                },
                "required": ["domain", "query"],
                "additionalProperties": False,
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "list_layers":
            tier = arguments.get("tier")
            layers = list_layers(tier=tier)
            payload = [
                {
                    "id": layer.id,
                    "name": layer.name,
                    "tier": layer.tier,
                    "eta_minutes": layer.eta_minutes,
                    "description": layer.description,
                    "usage": layer.usage,
                }
                for layer in layers
            ]
            return _text(json.dumps({"layers": payload, "critical_ids": list(CRITICAL_LAYER_IDS)}, indent=2))

        if name == "list_functions":
            category = arguments.get("category")
            fns = list_functions(category=category)
            payload = [
                {
                    "name": fn.name,
                    "category": fn.category,
                    "eta_minutes": fn.eta_minutes,
                    "description": fn.description,
                    "prerequisites": fn.prerequisites,
                }
                for fn in fns
            ]
            return _text(json.dumps({"functions": payload}, indent=2))

        if name == "get_layer_context":
            layer = get_layer(str(arguments["layer_id"]))
            return _text(layer_context_markdown(layer))

        if name == "init_scan":
            result = await asyncio.to_thread(init_scan, str(arguments["domain"]))
            return _text(format_run_result(result))

        if name == "run_layer":
            layer_id = str(arguments["layer_id"])
            layer = get_layer(layer_id)
            prefix = "WARNING: heavy layer — confirm time budget.\n" if layer.tier == "heavy" else ""
            result = await asyncio.to_thread(
                run_layer,
                str(arguments["domain"]),
                layer_id,
                ensure_init=bool(arguments.get("ensure_init", True)),
            )
            return _text(prefix + format_run_result(result, layer))

        if name == "run_function":
            fn_name = str(arguments["function_name"])
            get_function(fn_name)  # validate early
            result = await asyncio.to_thread(
                run_function,
                str(arguments["domain"]),
                fn_name,
                ensure_init=bool(arguments.get("ensure_init", True)),
            )
            return _text(format_run_result(result))

        if name == "get_scan_status":
            status = await asyncio.to_thread(get_scan_status, str(arguments["domain"]))
            return _text(json.dumps(status, indent=2))

        if name == "get_result_paths":
            paths = await asyncio.to_thread(
                get_result_paths,
                str(arguments["domain"]),
                arguments.get("layer_id"),
            )
            return _text(format_paths(paths, str(arguments["domain"])))

        if name == "list_report_files":
            files = await asyncio.to_thread(list_report_files, str(arguments["domain"]))
            return _text(format_report_files(files, str(arguments["domain"])))

        if name == "read_report":
            body = await asyncio.to_thread(
                read_report,
                str(arguments["domain"]),
                str(arguments.get("section", "summary")),
                max_chars=int(arguments.get("max_chars", 12000)),
                csv_rows=int(arguments.get("csv_rows", 25)),
            )
            return _text(body)

        if name == "read_ai_report":
            body = await asyncio.to_thread(
                read_ai_report,
                str(arguments["domain"]),
                max_chars=int(arguments.get("max_chars", 12000)),
            )
            return _text(body)

        if name == "search_results":
            hits = await asyncio.to_thread(
                search_results,
                str(arguments["domain"]),
                str(arguments["query"]),
                max_hits=int(arguments.get("max_hits", 25)),
                path_glob=str(arguments.get("path_glob", "")),
            )
            return _text(format_search(hits, str(arguments["query"])))

        if name == "get_environment":
            root = find_reconftw_root()
            payload = {
                "reconftw_root": str(root),
                "tools_dir": str(tools_dir(root)),
                "critical_layers": list(CRITICAL_LAYER_IDS),
                "layer_ids": _LAYER_IDS,
                "function_count": len(_FUNCTION_NAMES),
                "reconftw_sh": str(root / "reconftw.sh"),
                "mcp_config_dir": str(root / "config" / "mcp"),
                "workflow": _WORKFLOW,
            }
            return _text(json.dumps(payload, indent=2))

        return _text(f"Unknown tool: {name}")
    except KeyError as exc:
        return _text(f"Error: {exc}")
    except FileNotFoundError as exc:
        return _text(f"Error: {exc}")
    except Exception as exc:  # pragma: no cover
        return _text(f"Error: {type(exc).__name__}: {exc}")


def main() -> None:
    if bootstrap_python_config is not None:
        bootstrap_python_config()

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
