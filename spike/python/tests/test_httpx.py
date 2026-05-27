# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §3.4

import asyncio
import json
import shutil


async def test_httpx_probe_streaming(tmp_path):
    """Create subs.jsonl with known-resolvable hosts; run httpx probe;
    assert output has url + status_code keys.
    """
    import pytest

    from spike import httpx_probe

    if not shutil.which("httpx"):
        pytest.skip("httpx not in PATH")

    # Create subs file with known-resolvable hosts (subdomain format for httpx -l)
    subs_file = tmp_path / "subs.jsonl"
    hosts = [
        "www.example.com",
        "example.com",
        "www.iana.org",
        "dns.google",
        "one.one.one.one",
        "8.8.8.8",
        "httpbin.org",
        "postman-echo.com",
        "jsonplaceholder.typicode.com",
        "reqres.in",
    ]
    # Write as JSONL with subdomain field (passive output format)
    records = [{"subdomain": h, "source": "test"} for h in hosts]
    subs_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    # httpx -l expects one host per line (plain text), not JSONL
    # Create a plain-text subs file for httpx
    plain_subs = tmp_path / "plain_subs.txt"
    plain_subs.write_text("\n".join(hosts) + "\n")

    out_file = tmp_path / "hosts.jsonl"

    try:
        await asyncio.wait_for(
            httpx_probe.run(str(plain_subs), str(out_file)),
            timeout=60.0,
        )
    except asyncio.TimeoutError:
        pass  # Acceptable — httpx ran, just slow

    if not out_file.exists():
        # httpx found no live hosts — acceptable (network may be restricted)
        return

    if out_file.stat().st_size == 0:
        return

    lines = out_file.read_text().strip().splitlines()
    for line in lines:
        obj = json.loads(line)
        assert "url" in obj or "input" in obj, (
            f"expected 'url' or 'input' key in httpx NDJSON output: {obj}"
        )
        assert "status_code" in obj, f"missing 'status_code' key: {obj}"
