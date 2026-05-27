# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1

import asyncio
import os
import signal
from typing import Callable


async def run(
    name: str,
    args: list[str],
    line_fn: Callable[[bytes], None] | None = None,
    timeout: float | None = None,
) -> int:
    """Run name+args under process-group isolation (preexec_fn=os.setsid / start_new_session=True).
    On cancellation/timeout, sends SIGTERM to the entire process group via
    os.killpg, waits 5 seconds grace, then SIGKILL escalation.

    stdout is streamed line-by-line through line_fn; None means stdout is discarded.

    Returns process exit code.

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
    Pitfall: .planning/research/PITFALLS.md §1.2 (kill-tree, top-impact)
    """
    proc = await asyncio.create_subprocess_exec(
        name,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        preexec_fn=os.setsid,  # makes the child the process-group leader (POSIX)
    )

    async def _read_stdout() -> None:
        if proc.stdout is None:
            return
        async for line in proc.stdout:
            if line_fn is not None:
                line_fn(line.rstrip(b"\n"))

    async def _drain_stderr() -> None:
        if proc.stderr is None:
            return
        async for _ in proc.stderr:
            pass

    try:
        if timeout is not None:
            await asyncio.wait_for(
                asyncio.gather(_read_stdout(), _drain_stderr()),
                timeout=timeout,
            )
        else:
            await asyncio.gather(_read_stdout(), _drain_stderr())
        return await proc.wait()
    except (asyncio.CancelledError, asyncio.TimeoutError):
        # Kill the entire process group: SIGTERM first, then SIGKILL if still running
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            if proc.returncode is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
        raise
