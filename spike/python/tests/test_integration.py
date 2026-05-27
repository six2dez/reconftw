# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.3.2

import asyncio
import os
import pathlib
import shutil
import signal
import subprocess

import pytest


@pytest.mark.integration
async def test_killtree_real_tools(tmp_path):
    """Integration test: build spike binary, launch against hackerone.com as subprocess,
    wait for descendants (subfinder/httpx) to spawn, capture PIDs, send SIGINT,
    wait 12s, assert all descendants dead.
    Gated by @pytest.mark.integration — runs nightly via `make integration-test`, NOT per-push.
    Per RESEARCH.md §1.3.2.
    """
    spike_bin = pathlib.Path(__file__).parent.parent / "dist" / "spike"
    if not spike_bin.exists():
        pytest.skip("dist/spike binary not built (run: make build)")
    if not shutil.which("subfinder") and not shutil.which("crt"):
        pytest.skip("no external tools (subfinder, crt) found in PATH")

    # Launch spike binary as subprocess (process-group leader)
    proc_obj = await asyncio.create_subprocess_exec(
        str(spike_bin),
        "--target", "hackerone.com",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    spike_pid = proc_obj.pid

    # Wait for tool subprocesses to spawn
    await asyncio.sleep(5)

    # Capture descendants
    pgrep_result = subprocess.run(
        ["pgrep", "-P", str(spike_pid)],
        capture_output=True,
        text=True,
    )
    descendant_pids = set(
        int(p) for p in pgrep_result.stdout.strip().splitlines() if p.strip()
    )

    # Send SIGINT to spike process group
    try:
        os.killpg(os.getpgid(spike_pid), signal.SIGINT)
    except ProcessLookupError:
        pass

    # Wait up to 12s for spike to exit
    try:
        await asyncio.wait_for(proc_obj.wait(), timeout=12.0)
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(spike_pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    await asyncio.sleep(1)

    survivors = []
    for pid in descendant_pids:
        try:
            os.kill(pid, 0)
            survivors.append(pid)
        except (ProcessLookupError, PermissionError):
            pass

    assert not survivors, (
        f"Kill-tree FAILED: {len(survivors)} processes still alive: {survivors}"
    )
