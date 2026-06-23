"""Execute reconFTW layers and functions from MCP."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from reconftw_mcp.layers import Layer, get_layer
from reconftw_mcp.paths import config_profile, find_reconftw_root, scan_dir

try:
    from lib.reconftw_config import bootstrap_python_config, secrets_env_for_subprocess
except ImportError:  # pragma: no cover
    bootstrap_python_config = None  # type: ignore[misc, assignment]
    secrets_env_for_subprocess = None  # type: ignore[misc, assignment]


@dataclass
class RunResult:
    ok: bool
    layer_id: str
    domain: str
    elapsed_seconds: float
    command: str
    stdout_tail: str
    stderr_tail: str
    message: str


def _tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def _base_env(root: Path) -> dict[str, str]:
    if secrets_env_for_subprocess is not None:
        env = secrets_env_for_subprocess(root)
    else:
        env = os.environ.copy()
    env["RECONFTW_ROOT"] = str(root)
    env["SCRIPTPATH"] = str(root)
    env.setdefault("PATH", os.environ.get("PATH", ""))
    # Ensure uv/go/rust tool paths
    home = Path.home()
    for extra in (
        home / ".local/bin",
        home / "go/bin",
        home / ".cargo/bin",
    ):
        if extra.is_dir():
            env["PATH"] = f"{extra}:{env['PATH']}"
    tools = os.environ.get("RECONFTW_TOOLS", str(home / "Tools"))
    env["RECONFTW_TOOLS"] = tools
    return env


def _reconftw_cmd(root: Path, domain: str, *args: str, config: Path | None = None) -> list[str]:
    cmd = [str(root / "reconftw.sh"), "-d", domain, *args]
    if config:
        cmd.extend(["-f", str(config)])
    return cmd


def init_scan(domain: str) -> RunResult:
    """Initialize Recon/<domain> workspace via reconftw start()."""
    root = find_reconftw_root()
    start = time.monotonic()
    cmd = _reconftw_cmd(root, domain, "--mcp-init")
    proc = subprocess.run(
        cmd,
        cwd=root,
        env=_base_env(root),
        capture_output=True,
        text=True,
        timeout=300,
    )
    elapsed = time.monotonic() - start
    ok = proc.returncode == 0
    return RunResult(
        ok=ok,
        layer_id="init",
        domain=domain,
        elapsed_seconds=elapsed,
        command=" ".join(cmd),
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
        message="Scan workspace initialized" if ok else "init_scan failed",
    )


def run_function(
    domain: str,
    function_name: str,
    *,
    ensure_init: bool = True,
    config_profile_name: str = "",
) -> RunResult:
    root = find_reconftw_root()
    if ensure_init and not scan_dir(root, domain).is_dir():
        init_scan(domain)

    start = time.monotonic()
    script = root / "reconftw_mcp" / "scripts" / "run_function.sh"
    if not script.is_file():
        # uvx wheel install: script lives next to package
        script = Path(__file__).resolve().parent / "scripts" / "run_function.sh"
    cmd = ["bash", str(script), domain, function_name]
    env = _base_env(root)
    profile = config_profile(root, config_profile_name) if config_profile_name else None
    if profile:
        env["RECONFTW_MCP_PROFILE"] = str(profile)
    proc = subprocess.run(
        cmd,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=7200,
    )
    elapsed = time.monotonic() - start
    ok = proc.returncode == 0
    return RunResult(
        ok=ok,
        layer_id=function_name,
        domain=domain,
        elapsed_seconds=elapsed,
        command=" ".join(cmd),
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
        message=f"Function {function_name} completed" if ok else f"Function {function_name} failed",
    )


def run_layer(domain: str, layer_id: str, *, ensure_init: bool = True) -> RunResult:
    layer = get_layer(layer_id)
    root = find_reconftw_root()
    profile = config_profile(root, layer.config_profile) if layer.config_profile else None

    if ensure_init and not scan_dir(root, domain).is_dir():
        init_scan(domain)

    start = time.monotonic()

    if layer.mode:
        flag = f"-{layer.mode}"
        cmd = _reconftw_cmd(root, domain, flag, config=profile)
        proc = subprocess.run(
            cmd,
            cwd=root,
            env=_base_env(root),
            capture_output=True,
            text=True,
            timeout=7200,
        )
        elapsed = time.monotonic() - start
        ok = proc.returncode == 0
        return RunResult(
            ok=ok,
            layer_id=layer_id,
            domain=domain,
            elapsed_seconds=elapsed,
            command=" ".join(cmd),
            stdout_tail=_tail(proc.stdout),
            stderr_tail=_tail(proc.stderr),
            message=f"Layer {layer_id} ({layer.name}) finished" if ok else f"Layer {layer_id} failed",
        )

    if not layer.functions:
        return RunResult(
            ok=False,
            layer_id=layer_id,
            domain=domain,
            elapsed_seconds=0,
            command="",
            stdout_tail="",
            stderr_tail="",
            message=f"Layer {layer_id} has no functions or mode",
        )

    combined_out: list[str] = []
    combined_err: list[str] = []
    ok = True
    commands: list[str] = []

    for func in layer.functions:
        result = run_function(
            domain,
            func,
            ensure_init=False,
            config_profile_name=layer.config_profile,
        )
        commands.append(result.command)
        combined_out.append(result.stdout_tail)
        combined_err.append(result.stderr_tail)
        if not result.ok:
            ok = False
            break

    elapsed = time.monotonic() - start
    return RunResult(
        ok=ok,
        layer_id=layer_id,
        domain=domain,
        elapsed_seconds=elapsed,
        command=" && ".join(commands),
        stdout_tail=_tail("\n".join(combined_out)),
        stderr_tail=_tail("\n".join(combined_err)),
        message=f"Layer {layer_id}: {len(layer.functions)} function(s)",
    )


def format_run_result(result: RunResult, layer: Layer | None = None) -> str:
    lines = [
        f"status: {'ok' if result.ok else 'error'}",
        f"domain: {result.domain}",
        f"layer: {result.layer_id}",
        f"elapsed_seconds: {result.elapsed_seconds:.1f}",
        f"command: {result.command}",
        f"message: {result.message}",
    ]
    if layer:
        lines.append(f"tier: {layer.tier} (~{layer.eta_minutes} min expected)")
        if layer.outputs:
            lines.append("result_paths_hint: " + ", ".join(layer.outputs))
    if result.stderr_tail.strip():
        lines.append(f"stderr_tail:\n{result.stderr_tail}")
    if result.stdout_tail.strip():
        lines.append(f"stdout_tail:\n{result.stdout_tail}")
    lines.append("next: get_result_paths or search_results (do not load full dirs into context)")
    return "\n".join(lines)
