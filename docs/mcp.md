# MCP Server

## Overview

reconFTW exposes its recon modes as [Model Context Protocol](https://modelcontextprotocol.io/)
(MCP) tools via `reconftw mcp serve`. An MCP-compatible agent (Claude Desktop, any MCP
client SDK) can connect and trigger subdomain enumeration, web analysis, vulnerability
scanning, or OSINT collection — all running on the same internal pipeline the CLI uses.
The server is **opt-in** (`mcp.enabled = false` by default). It supports both a local
`stdio` pipe (suitable for Claude Desktop) and an HTTP transport with Bearer token auth
(`127.0.0.1` binding only by default). Tool calls are **async**: the server returns a
`run_id` and a resource URI immediately; the actual scan runs on the shared scheduler in
the background.

## Quick Start

**1. Configure reconftw.toml:**

```toml
[mcp]
enabled   = true
api_key   = "<generate with: openssl rand -hex 32>"
transport = "stdio"   # or "http"
port      = 8765      # only used when transport = "http"
```

**2. Start the server:**

```bash
# stdio transport (for Claude Desktop / local agents)
reconftw mcp serve --transport stdio

# HTTP transport (for remote agents; binds 127.0.0.1 only)
reconftw mcp serve --transport http --port 8765
```

Flags override the TOML config. The `--transport` and `--port` flags mirror their
`[mcp]` counterparts.

**3. Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json`):**

```json
{
  "mcpServers": {
    "reconftw": {
      "command": "/path/to/reconftw",
      "args": ["mcp", "serve", "--transport", "stdio"],
      "env": {
        "RECONFTW_MCP_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Restart Claude Desktop after saving the config. The 7 reconFTW tools will appear in the
tool picker.

## Supported Tools

| Tool | Description | Key Inputs |
|------|-------------|------------|
| `recon` | Passive subdomain enumeration + DNS resolution + takeover detection. Full composite (subs+web+vulns+osint) is Phase 9 scope. | `target` |
| `subs` | Subdomain enumeration: passive sources, active DNS resolution, permutation, takeover detection. | `target`, `dry_run` |
| `web` | Web probe + analysis: HTTP probing, WAF detection, URL crawl, JS analysis. | `target`, `dry_run`, `hosts` (optional seed file) |
| `vulns` | Vulnerability scanning: XSS, SQLi, SSRF, SSTI, CRLF, LFI, Nuclei DAST. | `target`, `dry_run`, `urls` (optional seed file) |
| `osint` | OSINT collection: domain info, emails, GitHub leaks, Google dorks, cloud enumeration. | `target`, `dry_run` |
| `monitor` | Monitor mode — Phase 10 scope. Returns `{"status":"not_implemented"}` immediately. | `target`, `interval`, `cycles` |
| `report` | Report regeneration — Phase 10 scope. Returns `{"status":"not_implemented"}` immediately. | `target` |

### Async Execution Model

Every real tool call (recon, subs, web, vulns, osint) is **non-blocking**. The handler:

1. Validates input and checks scope.
2. Generates a crypto/rand `run_id`.
3. Launches the scan on the shared scheduler and returns immediately.
4. Returns `{"run_id": "<id>", "resource": "scan://<id>/findings"}`.

The client subscribes to the resource URI for live JSONL findings. The server emits
`ResourceUpdated` notifications as each pipeline stage completes. Read the resource to
get all accumulated findings at any time:

```bash
# mcp-cli example
mcp call subs '{"target":"example.com"}'
# Response: {"run_id":"abc123...","resource":"scan://abc123.../findings"}

mcp subscribe "scan://abc123.../findings"
# Streams JSONL finding events as each stage completes
```

`monitor` and `report` return `{"status":"not_implemented"}` because their full
implementation is Phase 10 scope. They still return a `run_id` for protocol
consistency.

## Configuration

All `[mcp]` TOML keys and their environment variable equivalents:

| Key | Type | Default | Validation | Env Override |
|-----|------|---------|------------|--------------|
| `enabled` | bool | `false` | — | `RECONFTW_MCP_ENABLED` |
| `api_key` | string | `""` | min 16 chars, max 256 | `RECONFTW_MCP_API_KEY` |
| `transport` | string | `"stdio"` | `stdio` or `http` | `RECONFTW_MCP_TRANSPORT` |
| `port` | int | `8765` | 1024-65535 | `RECONFTW_MCP_PORT` |

The `api_key` is required for both transports. Set it in `reconftw.toml` or via the
environment variable. Generate a strong key:

```bash
openssl rand -hex 32
```

## Security

**Bearer token (HTTP transport):** Every request to the HTTP `/mcp` endpoint must carry:

```
Authorization: Bearer <api_key>
```

Requests without a valid Bearer token receive `401 Unauthorized`. The `/openapi.json`
endpoint is served unauthenticated (it contains no secrets).

**localhost binding:** The HTTP transport always binds `127.0.0.1:<port>`. There is no
option to bind `0.0.0.0` or an external address in the default configuration. Use a
reverse proxy if remote access is needed; the proxy is responsible for TLS and
additional auth.

**Scope sandboxing:** The session scope is fixed at MCP `initialize` time (or captured
from the first tool call's `target` when using the stdio transport). Tool arguments
cannot widen the scope. Attempting to call a tool with a target outside the session
scope returns a tool error containing `"out_of_scope"` — the scan is never started.

**Credential redaction:** The `api_key` and all other reconFTW secrets are registered
with the runtime `Redactor` before the first log line. Any log output that would
otherwise contain the raw secret value is replaced with `***` (two-layer defense: slog
`LogValuer` type-level + substring scrubbing).

**Minimum key length:** 16 characters enforced at config load time. Keys shorter than
16 characters are rejected with a validation error before the server starts.

## Rate Limits

MCP requests share the global scheduler bounded by `[concurrency] max_jobs` (default 4).
Multiple concurrent MCP sessions all submit tasks to the same pool — so if four subs
tasks are already running, a fifth call blocks in the scheduler queue until a slot
opens.

A single MCP tool call may spawn many sub-tool processes internally (subfinder, dnsx,
puredns, etc.). `max_jobs` is the ceiling on **simultaneously executing tasks**, not on
MCP connections.

To adjust the limit:

```toml
[concurrency]
max_jobs = 8   # allow up to 8 parallel tasks across all sessions
```

## Examples

**Subdomain scan via mcp-cli:**

```bash
mcp call subs '{"target":"example.com"}'
# {"run_id":"8f3a...","resource":"scan://8f3a.../findings"}

mcp subscribe "scan://8f3a.../findings"
# streams JSONL findings as stages complete
```

**HTTP transport — check auth is enforced:**

```bash
# Without token: expect 401
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://127.0.0.1:8765/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
# 401

# With token: expect tools/list response
curl -s -X POST http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $RECONFTW_MCP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

**OpenAPI schema reference:**

```bash
curl -s http://127.0.0.1:8765/openapi.json | python3 -m json.tool | head -20
```

Full HTTP transport schema is available at `/openapi.json`. See also
[docs/openapi.json](/openapi.json) for the bundled schema.

**Python MCP client — async tool call + resource subscription:**

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def run():
    params = StdioServerParameters(
        command="reconftw", args=["mcp", "serve", "--transport", "stdio"]
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("subs", {"target": "example.com"})
            print(result.content[0].text)
            # {"run_id":"...","resource":"scan://.../findings"}

asyncio.run(run())
```
