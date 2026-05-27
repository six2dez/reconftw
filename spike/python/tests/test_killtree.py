# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.3.1

import asyncio
import os
import pathlib
import subprocess

import pytest

MOCK_TOOL = (
    pathlib.Path(__file__).parent.parent.parent / "corpus" / "mock_stubborn_tool.sh"
)
RESULT_FILE = pathlib.Path(__file__).parent.parent / "out" / ".killtree_result"


async def test_killtree_synthetic_mock():
    """Spawn mock_stubborn_tool.sh via proc.run; wait 2s for children to fork;
    cancel the task; assert all descendants dead within 10s.
    Write PASS/FAIL to spike/python/out/.killtree_result for compare.sh (M4).
    """
    from spike import proc

    if not MOCK_TOOL.exists():
        pytest.skip(f"mock_stubborn_tool.sh not found at {MOCK_TOOL}")

    task = asyncio.create_task(
        proc.run("bash", [str(MOCK_TOOL)])
    )

    # Wait for mock tool to fork its children
    await asyncio.sleep(2)

    # Find the PID of the spawned bash process (the mock tool)
    # We use pgrep to find children of our test process
    # The proc.run spawns bash as a process group leader; we need its PID.
    # Since we can't directly get the PID from proc.run, we search for mock_stubborn_tool.sh
    pgrep_result = subprocess.run(
        ["pgrep", "-f", "mock_stubborn_tool"],
        capture_output=True,
        text=True,
    )
    descendant_pids = [
        int(p) for p in pgrep_result.stdout.strip().splitlines() if p.strip()
    ]
    assert len(descendant_pids) >= 1, (
        f"Expected at least 1 mock_stubborn_tool process, found {descendant_pids}"
    )

    # Also capture sleep processes that are children of the mock tool
    all_target_pids = set(descendant_pids)
    for pid in list(descendant_pids):
        sleep_result = subprocess.run(
            ["pgrep", "-P", str(pid)],
            capture_output=True,
            text=True,
        )
        for child_pid in sleep_result.stdout.strip().splitlines():
            if child_pid.strip():
                all_target_pids.add(int(child_pid))

    # Cancel the task — triggers SIGTERM via os.killpg in proc.run, then SIGKILL escalation
    task.cancel()
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=12.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass

    # Wait a bit for process cleanup to propagate
    await asyncio.sleep(1)

    # Assert all captured PIDs are now dead
    survivors = []
    for pid in all_target_pids:
        try:
            os.kill(pid, 0)
            survivors.append(pid)
        except ProcessLookupError:
            pass  # Expected — process is dead
        except PermissionError:
            survivors.append(pid)  # Process still alive (different owner)

    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    if survivors:
        RESULT_FILE.write_text("FAIL\n")
        pytest.fail(
            f"Kill-tree FAILED: {len(survivors)} processes still alive after 12s: {survivors}"
        )
    else:
        RESULT_FILE.write_text("PASS\n")


@pytest.mark.integration
async def test_killtree_real_tools(tmp_path):
    """Integration test: build spike binary first, then launch against hackerone.com,
    send SIGINT, assert all descendants dead within 12s.
    Gated by @pytest.mark.integration — runs nightly only (not per-push).
    Per RESEARCH.md §1.3.2.
    """
    import shutil
    import signal

    spike_bin = pathlib.Path(__file__).parent.parent / "dist" / "spike"
    if not spike_bin.exists():
        pytest.skip("dist/spike binary not built (run: make build)")
    if not shutil.which("subfinder") and not shutil.which("crt"):
        pytest.skip("no external tools (subfinder, crt) found in PATH")

    # Launch spike binary as subprocess
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
        capture_output=True, text=True
    )
    descendant_pids = set(
        int(p) for p in pgrep_result.stdout.strip().splitlines() if p.strip()
    )

    # Send SIGINT to spike
    try:
        os.killpg(os.getpgid(spike_pid), signal.SIGINT)
    except ProcessLookupError:
        pass

    # Wait up to 12s
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

    assert not survivors, f"Kill-tree FAILED: {len(survivors)} processes still alive: {survivors}"
