"""Resolve reconFTW root, tools directory, and scan output paths."""

from __future__ import annotations

import os
from pathlib import Path


def find_reconftw_root() -> Path:
    """Locate the reconFTW repository (must contain reconftw.sh)."""
    env_root = os.environ.get("RECONFTW_ROOT", "").strip()
    if env_root:
        root = Path(env_root).expanduser().resolve()
        if (root / "reconftw.sh").is_file():
            return root
        raise FileNotFoundError(f"RECONFTW_ROOT set but reconftw.sh not found: {root}")

    # Installed package: repo root is parent of reconftw_mcp/
    pkg_root = Path(__file__).resolve().parents[1]
    if (pkg_root / "reconftw.sh").is_file():
        return pkg_root

    # CWD fallback (developer running from checkout)
    cwd = Path.cwd().resolve()
    if (cwd / "reconftw.sh").is_file():
        return cwd

    raise FileNotFoundError(
        "Cannot find reconFTW root. Set RECONFTW_ROOT to the directory containing reconftw.sh"
    )


def tools_dir(root: Path | None = None) -> Path:
    """Return external tools directory ($HOME/Tools by default)."""
    override = os.environ.get("RECONFTW_TOOLS", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    default = Path.home() / "Tools"
    if default.is_dir():
        return default
    return default


def scan_dir(root: Path, domain: str) -> Path:
    return (root / "Recon" / domain).resolve()


def config_profile(root: Path, profile: str) -> Path | None:
    if not profile:
        return None
    candidates = [
        root / "config" / "mcp" / profile,
        Path(__file__).resolve().parents[1] / "config" / "mcp" / profile,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
