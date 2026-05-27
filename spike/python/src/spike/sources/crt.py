# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1

import asyncio
import json
from typing import Callable

from spike import proc, ui


async def run(target: str, collect: Callable[[str], None]) -> None:
    """Run crt against target and collect subdomains via buffered JSON-array parse.

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1 axis (b)
    Parse shape: JSON ARRAY (buffered, NOT streaming) — output is a single JSON array blob.
    """
    buf = bytearray()

    def line_fn(line: bytes) -> None:
        buf.extend(line + b"\n")

    try:
        await proc.run(
            "crt",
            ["-s", "-json", "-l", "200", target],
            line_fn=line_fn,
        )
    except FileNotFoundError:
        ui.skip("crt", "not in PATH")
        return
    except asyncio.CancelledError:
        raise
    except Exception as e:
        ui.warn(f"crt: {e}")
        return

    if not buf:
        return

    try:
        data = json.loads(bytes(buf))
        if isinstance(data, list):
            for item in data:
                subdomain = item.get("subdomain", "") if isinstance(item, dict) else ""
                if subdomain:
                    collect(subdomain)
    except json.JSONDecodeError:
        ui.warn("crt: malformed JSON output")
