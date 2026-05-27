# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1

import asyncio
import os
from typing import Callable

from spike import proc, ui


async def run(target: str, collect: Callable[[str], None]) -> None:
    """Run github-subdomains against target and collect subdomains via text output.

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1 axis (c)
    Parse shape: text output, one subdomain per line.
    Credential: GITHUB_TOKENS env var → file path (per OQ4 locked decision).
    T-01-03-SI-02: token file path passed to subprocess, NOT token contents.
    """
    tokens_path = os.environ.get("GITHUB_TOKENS", "")
    if not tokens_path:
        ui.skip("github-subdomains", "GITHUB_TOKENS unset or empty")
        return
    if not os.path.isfile(tokens_path):
        ui.skip("github-subdomains", f"GITHUB_TOKENS file not found: {tokens_path}")
        return
    if os.path.getsize(tokens_path) == 0:
        ui.skip("github-subdomains", "GITHUB_TOKENS file is empty")
        return

    def line_fn(line: bytes) -> None:
        subdomain = line.decode(errors="replace").strip()
        if subdomain:
            collect(subdomain)

    try:
        await proc.run(
            "github-subdomains",
            ["-d", target, "-t", tokens_path, "-k", "-q"],
            line_fn=line_fn,
        )
    except FileNotFoundError:
        ui.skip("github-subdomains", "not in PATH")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        ui.warn(f"github-subdomains: {e}")
