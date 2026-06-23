#!/usr/bin/env bats

setup() {
  PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export RECONFTW_ROOT="$PROJECT_ROOT"
}

@test "MCP package, functions catalog, and config profiles exist" {
  [ -f "$PROJECT_ROOT/reconftw_mcp/server.py" ]
  [ -f "$PROJECT_ROOT/reconftw_mcp/functions.py" ]
  [ -f "$PROJECT_ROOT/pyproject.toml" ]
  [ -f "$PROJECT_ROOT/lib/__init__.py" ]
  [ -f "$PROJECT_ROOT/config/mcp/osint_light.cfg" ]
  [ -x "$PROJECT_ROOT/reconftw_mcp/scripts/run_function.sh" ]
}

@test "reconftw.sh supports --mcp-init flag" {
  grep -q 'mcp-init\|mcp_init' "$PROJECT_ROOT/reconftw.sh"
}

@test "python MCP unit tests pass" {
  run python3 "$PROJECT_ROOT/tests/unit/python/test_mcp_layers.py"
  [ "$status" -eq 0 ]
}

@test "list_layers returns critical tier entries" {
  run python3 -c "
import os, json
os.environ['RECONFTW_ROOT']='${PROJECT_ROOT}'
from reconftw_mcp.layers import list_layers, CRITICAL_LAYER_IDS
c = list_layers(tier='critical')
assert len(c) == len(CRITICAL_LAYER_IDS)
print(json.dumps([x.id for x in c]))
"
  [ "$status" -eq 0 ]
  [[ "$output" == *"osint_quick"* ]]
}

@test "MCP server defines report and function catalog tools" {
  grep -q 'name="read_report"' "$PROJECT_ROOT/reconftw_mcp/server.py"
  grep -q 'name="read_ai_report"' "$PROJECT_ROOT/reconftw_mcp/server.py"
  grep -q 'name="list_report_files"' "$PROJECT_ROOT/reconftw_mcp/server.py"
  grep -q 'name="list_functions"' "$PROJECT_ROOT/reconftw_mcp/server.py"
}

@test "MCP server list_tools when mcp package installed" {
  run python3 -c "
import importlib.util
if importlib.util.find_spec('mcp') is None:
    print('skip: mcp not installed')
    raise SystemExit(0)
import os, asyncio
os.environ['RECONFTW_ROOT']='${PROJECT_ROOT}'
from reconftw_mcp.server import list_tools
tools = asyncio.run(list_tools())
names = {t.name for t in tools}
assert 'read_report' in names
print('ok')
"
  [ "$status" -eq 0 ]
}

@test "pyproject.toml declares package and entry points" {
  grep -q 'name = "reconftw"' "$PROJECT_ROOT/pyproject.toml"
  grep -q 'reconftw-mcp = "reconftw_mcp.server:main"' "$PROJECT_ROOT/pyproject.toml"
}

@test "install.sh wires setup_reconftw_venv to pyproject" {
  grep -q 'uv pip install -e' "$PROJECT_ROOT/install.sh"
  grep -q 'setup_reconftw_venv' "$PROJECT_ROOT/install.sh"
}
