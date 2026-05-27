# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2

import json
import os
import tempfile


def atomic_write_jsonl(target: str, lines: list[dict]) -> None:
    """Write lines (each a dict) to target atomically as JSONL.
    4-step pattern: tempfile (same dir as target) + fsync + os.replace + parent-dir fsync.
    Parent-dir fsync is the often-forgotten step (most implementations stop at 3).

    Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2
    Pitfall: .planning/research/PITFALLS.md §3.1 (atomic write, top-5)
    """
    d = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(
        prefix=os.path.basename(target) + ".tmp.", dir=d, text=False
    )
    try:
        with os.fdopen(fd, "wb") as f:
            for line in lines:
                f.write(json.dumps(line).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)  # atomic rename
        # Critical: fsync parent dir (the often-forgotten step)
        parent_fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_with_fault(
    target: str, lines: list[dict], fault_point: str | None = None
) -> None:
    """Internal testing-only variant that supports fault injection via fault_point.
    Used by test_atomic_crash_safe to inject os._exit(1) at specific points.
    Valid fault_point values: "after_fsync" (exits after fsync, before os.replace).

    Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md §Task 2
    """
    d = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(
        prefix=os.path.basename(target) + ".tmp.", dir=d, text=False
    )
    try:
        with os.fdopen(fd, "wb") as f:
            for line in lines:
                f.write(json.dumps(line).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())

        # Fault injection point — called after fsync, before os.replace
        if fault_point == "after_fsync":
            os._exit(1)  # noqa: SLF001

        os.replace(tmp, target)  # atomic rename
        # Critical: fsync parent dir
        parent_fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
