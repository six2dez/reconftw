# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2

import json
import os
import subprocess
import sys
import textwrap


def test_atomic_happy_path(tmp_path):
    """Write 100 dicts via atomic_write_jsonl; assert file exists, 100 lines, all valid JSON."""
    from spike.output import atomic_write_jsonl

    out = tmp_path / "out.jsonl"
    records = [{"id": i, "value": f"item-{i}"} for i in range(100)]
    atomic_write_jsonl(str(out), records)

    assert out.exists(), "output file must exist after atomic_write_jsonl"
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 100, f"expected 100 lines, got {len(lines)}"
    for i, line in enumerate(lines):
        obj = json.loads(line)
        assert obj["id"] == i
        assert obj["value"] == f"item-{i}"


def test_atomic_crash_safe(tmp_path):
    """Fault-injection test: child process that calls _atomic_write_with_fault(after_fsync)
    exits with os._exit(1) AFTER fsync but BEFORE os.replace.
    The original target file must survive intact (no torn write ever observed).

    Retried up to 10 times; test PASSES if all 10 invocations produce a clean state.
    """
    target = tmp_path / "subs.jsonl"
    # Pre-populate with known content
    original_content = '{"prev": true}\n'
    target.write_text(original_content)
    original_bytes = target.read_bytes()

    new_records = [{"subdomain": f"sub{i}.example.com", "source": "test"} for i in range(50)]
    new_jsonl = "".join(json.dumps(r) + "\n" for r in new_records).encode()

    # Script that calls _atomic_write_with_fault with fault point "after_fsync"
    child_script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(tmp_path.parent.parent.parent / "src")!r})
        import json
        from spike.output import _atomic_write_with_fault

        records = [
            {{"subdomain": f"sub{{i}}.example.com", "source": "test"}}
            for i in range(50)
        ]
        _atomic_write_with_fault({str(target)!r}, records, fault_point="after_fsync")
    """)

    # Run 10 times, each time assert no torn write
    for attempt in range(10):
        result = subprocess.run(
            [sys.executable, "-c", child_script],
            capture_output=True,
        )
        # Child exits via os._exit(1) — non-zero exit expected
        # The target must be EITHER original OR new full content — NEVER partial
        current_bytes = target.read_bytes()
        is_original = current_bytes == original_bytes
        is_new = current_bytes == new_jsonl
        assert is_original or is_new, (
            f"Attempt {attempt}: torn write detected! "
            f"File is neither original ({len(original_bytes)} bytes) "
            f"nor new ({len(new_jsonl)} bytes); got {len(current_bytes)} bytes: {current_bytes[:100]!r}"
        )
        # Restore original for next attempt
        target.write_bytes(original_bytes)
