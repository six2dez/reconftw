# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.2

import asyncio
import json
import os

from spike import proc, ui
from spike.output import atomic_write_jsonl


async def run(subs_file: str, out_file: str) -> None:
    """Invoke httpx with the locked minimal flag set and write NDJSON-shaped host records
    to out_file via atomic_write_jsonl at end.

    Locked flags: -l <subs_file> -silent -json -status-code -title -tech-detect -no-color -threads 50 -timeout 10

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.2
    Locked: spike/README.md §Slice Locked
    T-01-03-SI-05: proc.run uses create_subprocess_exec — never shell=True.
    """
    # PITFALL §1.4: never stdin-pipe; use -l for file-based input
    if not os.path.isfile(subs_file):
        ui.warn(f"httpx: subs_file does not exist: {subs_file}")
        return
    if os.path.getsize(subs_file) == 0:
        ui.skip("httpx", "subs_file is empty")
        return

    lines: list[dict] = []

    def line_fn(line: bytes) -> None:
        if not line:
            return
        try:
            lines.append(json.loads(line))
        except json.JSONDecodeError:
            ui.warn(f"httpx: malformed NDJSON line: {line[:80]!r}")

    try:
        await proc.run(
            "httpx",
            [
                "-l", subs_file,
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-no-color",
                "-threads", "50",
                "-timeout", "10",
            ],
            line_fn=line_fn,
        )
    except FileNotFoundError:
        ui.skip("httpx", "not in PATH")
        return
    except asyncio.CancelledError:
        raise
    except Exception as e:
        ui.warn(f"httpx: {e}")
        return

    if lines:
        atomic_write_jsonl(out_file, lines)
    else:
        ui.warn("httpx: no hosts responded")
