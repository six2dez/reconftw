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
    """Run gitlab-subdomains against target and collect subdomains via text output.

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1 axis (d)
    Parse shape: text output, one subdomain per line.
    Credential: GITLAB_TOKENS env var → file path (per OQ4 locked decision).
    T-01-03-SI-02: token file path passed to subprocess, NOT token contents.
    """
    tokens_path = os.environ.get("GITLAB_TOKENS", "")
    if not tokens_path:
        ui.skip("gitlab-subdomains", "GITLAB_TOKENS unset or empty")
        return
    if not os.path.isfile(tokens_path):
        ui.skip("gitlab-subdomains", f"GITLAB_TOKENS file not found: {tokens_path}")
        return
    if os.path.getsize(tokens_path) == 0:
        ui.skip("gitlab-subdomains", "GITLAB_TOKENS file is empty")
        return

    def line_fn(line: bytes) -> None:
        subdomain = line.decode(errors="replace").strip()
        if subdomain:
            collect(subdomain)

    try:
        await proc.run(
            "gitlab-subdomains",
            ["-d", target, "-t", tokens_path],
            line_fn=line_fn,
        )
    except FileNotFoundError:
        ui.skip("gitlab-subdomains", "not in PATH")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        ui.warn(f"gitlab-subdomains: {e}")
