# reconFTW MCP layer reference

Layers are exposed via `reconftw-mcp` MCP server. Critical tiers target **≤5 minutes**.

## Install (uvx)

```bash
export RECONFTW_ROOT=/path/to/reconftw   # git checkout with reconftw.sh + modules/
export RECONFTW_TOOLS=$HOME/Tools        # external tools from install.sh

# From local checkout:
uvx --from /path/to/reconftw reconftw-mcp

# Editable install (same as install.sh setup_reconftw_venv):
uv pip install -e /path/to/reconftw --python .venv/bin/python3
```

The wheel ships Python (`reconftw_mcp`, `lib.ai`) and MCP config profiles. **Bash modules still require `RECONFTW_ROOT`** pointing at the full git checkout.

## Deployment (Docker / Terraform / Proxmox / Axiom)

| Path | Python / MCP behavior |
|------|------------------------|
| `install.sh` | `setup_reconftw_venv()` installs AI deps + `uv pip install -e .` into `.venv` |
| `Docker/Dockerfile` | Runs `./install.sh` — MCP package lands in `/reconftw/.venv` automatically |
| `Terraform/reconFTW.yml` | Ansible runs `./install.sh --verbose` — same venv path |
| `Proxmox/reconftw_prox_deploy.sh` | Runs `./install.sh` in LXC |
| Axiom | Unchanged; MCP does not replace `modules/axiom.sh` fleet logic |

Docker images clone **upstream** GitHub until your fork is merged; local MCP changes require building from your checkout:

```bash
docker build -f Docker/Dockerfile -t reconftw:local .
```

## Cursor MCP config

```json
{
  "mcpServers": {
    "reconftw": {
      "command": "uvx",
      "args": ["--from", "/home/kitten/Documents/reconftw", "reconftw-mcp"],
      "env": {
        "RECONFTW_ROOT": "/home/kitten/Documents/reconftw",
        "RECONFTW_TOOLS": "/home/kitten/Tools"
      }
    }
  }
}
```

## Agent workflow

1. `get_environment` — verify paths
2. `init_scan(domain)` — once per target
3. `list_layers` tier=critical → `run_layer`
4. `get_scan_status` / `list_report_files`
5. `read_report` section=summary|severities (not full tree)
6. `search_results` for grep-style pivots
7. `read_ai_report` after `reconftw -y` (use `AI_PROVIDER=mock` offline)

## AI without LLM server

```bash
export AI_PROVIDER=mock
./reconftw.sh -d example.com -y -c domain_info
# or: .venv/bin/python3 lib/ai/cli.py --mock --results-dir Recon/example.com ...
```

## MCP tools

| Tool | Purpose |
|------|---------|
| `list_layers` | Layer catalog (critical/standard/heavy) |
| `list_functions` | Individual shell functions for `run_function` |
| `run_layer` / `run_function` | Execute recon |
| `list_report_files` / `read_report` | Structured report access |
| `read_ai_report` | AI summary JSON/Markdown |
| `search_results` | RAG-lite grep over artifacts |
