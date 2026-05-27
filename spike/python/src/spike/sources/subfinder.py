# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1

import json
from typing import Callable

from spike import proc, ui


async def run(target: str, collect: Callable[[str], None]) -> None:
    """Run subfinder against target and collect subdomains via streaming NDJSON.

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1 axis (a)
    Parse shape: NDJSON streaming — each line is {"host": "sub.example.com", ...}
    """

    def line_fn(line: bytes) -> None:
        if not line:
            return
        try:
            obj = json.loads(line)
            host = obj.get("host", "")
            if host:
                collect(host)
        except (json.JSONDecodeError, KeyError):
            ui.warn(f"subfinder: malformed NDJSON line: {line[:80]!r}")

    try:
        await proc.run(
            "subfinder",
            ["-d", target, "-silent", "-json", "-all", "-max-time", "180"],
            line_fn=line_fn,
        )
    except FileNotFoundError:
        ui.skip("subfinder", "not in PATH")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        ui.warn(f"subfinder: {e}")


import asyncio  # noqa: E402  (stdlib; deferred to after proc import for clarity)
