"""Load secrets.cfg into Python/MCP runtime (existing os.environ wins)."""

from __future__ import annotations

import os
import re
from pathlib import Path

_ASSIGN_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

# Keys loaded from secrets.cfg for AI, MCP, and API modules.
SECRETS_KEYS: frozenset[str] = frozenset(
    {
        "AI_BASE_URL",
        "AI_API_KEY",
        "AI_PROVIDER",
        "AI_MODEL",
        "AI_REMOTE_ONLY",
        "AI_SKIP_HEALTHCHECK",
        "AI_INTEGRATOR",
        "AI_REPORT_TYPE",
        "AI_REPORT_PROFILE",
        "AI_TIMEOUT_SECONDS",
        "AI_ALLOW_MODEL_PULL",
        "AI_MAX_CHARS_PER_FILE",
        "AI_MAX_FILES_PER_CATEGORY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "RECONFTW_ROOT",
        "RECONFTW_TOOLS",
        "SHODAN_API_KEY",
        "WHOISXML_API",
        "PDCP_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "XSS_SERVER",
        "COLLAB_SERVER",
    }
)


def _strip_shell_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_shell_assignments(text: str) -> dict[str, str]:
    """Parse bash-style VAR=value / export VAR=value lines (skip comments)."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGN_RE.match(stripped)
        if not match:
            continue
        key, raw_value = match.group(1), match.group(2)
        if key in SECRETS_KEYS or key.startswith("AI_") or key.startswith("RECONFTW_"):
            result[key] = _strip_shell_value(raw_value)
    return result


def find_reconftw_root() -> Path | None:
    env_root = os.environ.get("RECONFTW_ROOT", "").strip()
    if env_root:
        root = Path(env_root).expanduser().resolve()
        if (root / "reconftw.sh").is_file():
            return root
    pkg_root = Path(__file__).resolve().parents[1]
    if (pkg_root / "reconftw.sh").is_file():
        return pkg_root
    cwd = Path.cwd().resolve()
    if (cwd / "reconftw.sh").is_file():
        return cwd
    return None


def load_secrets_file(path: Path, *, apply: bool = True) -> dict[str, str]:
    """Load secrets.cfg; do not override variables already in os.environ."""
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_shell_assignments(text)
    applied: dict[str, str] = {}
    for key, value in parsed.items():
        if not value:
            continue
        if key in os.environ and os.environ[key]:
            continue
        applied[key] = value
        if apply:
            os.environ[key] = value
    return applied


def bootstrap_python_config(root: Path | None = None) -> Path | None:
    """Load secrets.cfg for standalone Python entrypoints (AI CLI, MCP)."""
    resolved = root or find_reconftw_root()
    if resolved is None:
        return None
    if not os.environ.get("RECONFTW_ROOT"):
        os.environ["RECONFTW_ROOT"] = str(resolved)
    load_secrets_file(resolved / "secrets.cfg")
    # AI_API_KEY alias
    if not os.environ.get("AI_API_KEY") and os.environ.get("OPENAI_API_KEY"):
        os.environ["AI_API_KEY"] = os.environ["OPENAI_API_KEY"]
    return resolved


def secrets_env_for_subprocess(root: Path | None = None) -> dict[str, str]:
    """Build env dict for MCP subprocesses (merge secrets into parent env)."""
    env = os.environ.copy()
    resolved = root or find_reconftw_root()
    if resolved is None:
        return env
    for key, value in load_secrets_file(resolved / "secrets.cfg", apply=False).items():
        if key not in env or not env[key]:
            env[key] = value
    if not env.get("AI_API_KEY") and env.get("OPENAI_API_KEY"):
        env["AI_API_KEY"] = env["OPENAI_API_KEY"]
    env.setdefault("RECONFTW_ROOT", str(resolved))
    env.setdefault("SCRIPTPATH", str(resolved))
    return env
