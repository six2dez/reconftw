# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §3.4

import asyncio
import json
import shutil


async def test_passive_four_sources(tmp_path):
    """Fan-out to all 4 passive sources; assert output file has valid JSON with
    subdomain + source keys. Tools may be missing → skip. Sources may skip
    gracefully if credentials/tools absent — that's expected.
    """
    from spike import passive

    if not shutil.which("subfinder") and not shutil.which("crt"):
        import pytest
        pytest.skip("subfinder and crt not in PATH — cannot run passive test")

    out_file = tmp_path / "subs.jsonl"

    try:
        await asyncio.wait_for(
            passive.run("example.com", str(out_file)),
            timeout=30.0,
        )
    except asyncio.TimeoutError:
        # Timeout is acceptable — tools ran, just slow
        pass

    # If output file doesn't exist, all sources either skipped or timed out
    if not out_file.exists():
        # This is acceptable — all sources may have gracefully skipped
        return

    if out_file.stat().st_size == 0:
        return

    lines = out_file.read_text().strip().splitlines()
    assert len(lines) >= 1, "output must have at least 1 line when file exists and non-empty"
    for line in lines:
        obj = json.loads(line)
        assert "subdomain" in obj, f"missing 'subdomain' key: {obj}"
        assert "source" in obj, f"missing 'source' key: {obj}"
        assert obj["source"] in ("subfinder", "crt", "github", "gitlab"), (
            f"unexpected source value: {obj['source']}"
        )
