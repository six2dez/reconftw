# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Standard Stack §Python Spike

import asyncio
import os
import signal
import sys

import typer

from spike import httpx_probe, passive, ui

app = typer.Typer()


@app.command()
def main(
    target: str = typer.Option(..., "--target", help="Target domain"),
) -> None:
    """reconFTW v2 Python spike — throwaway PoC for language ADR measurement."""
    rc = asyncio.run(_run(target))
    sys.exit(rc)


async def _run(target: str) -> int:
    """Async entrypoint: passive fan-out → httpx probe, with SIGINT signal handler."""
    loop = asyncio.get_running_loop()
    cancel_event = asyncio.Event()

    def _on_sigint() -> None:
        cancel_event.set()

    loop.add_signal_handler(signal.SIGINT, _on_sigint)

    os.makedirs("out", exist_ok=True)

    ui.info(f"passive: starting (target={target})")
    try:
        await passive.run(target, "out/subs.jsonl")
    except Exception as e:
        ui.err(f"passive failed: {e}")
        return 1

    if cancel_event.is_set():
        ui.warn("spike: cancelled after passive phase")
        return 1

    ui.info("httpx: probing")
    try:
        await httpx_probe.run("out/subs.jsonl", "out/hosts.jsonl")
    except Exception as e:
        ui.err(f"httpx failed: {e}")
        return 1

    ui.info("spike: done")
    return 0


if __name__ == "__main__":
    app()

# STATUS at Plan 01-03 close:
#   - Slice complete: 4 passive sources + httpx probe + atomic JSONL writes
#   - Tests: 5/5 unit, integration gated by @pytest.mark.integration
#   - Measurements captured: spike/python/out/.killtree_result, .xplat_ordinal; spike/.spike_sessions.log
#   - PyInstaller single-binary built at spike/python/dist/spike (M3b)
#   - Wave 2 complete; Plan 01-04 (comparison + ADR draft) is next
