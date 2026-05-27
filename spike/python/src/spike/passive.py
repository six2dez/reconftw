# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1

import asyncio
import re

from spike.output import atomic_write_jsonl
from spike.sources import crt, github, gitlab, subfinder

# T-01-03-SI-01: domain validation regex (mirrors validate_domain() in lib/validation.sh)
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


async def run(target: str, out_file: str) -> None:
    """Fan-out to 4 passive sources concurrently using asyncio.TaskGroup.
    Each source's results are collected, deduped, and written atomically to out_file as JSONL.

    Source: bash modules/subdomains.sh:sub_passive() (lines 507-553)
    Pitfall §2.4: avoid `for x in xs: await scan(x)` — use TaskGroup for fan-out.
    Pitfall §2.5: TaskGroup is safer than `asyncio.gather(...)` — orphan handling correct by default.

    T-01-03-SI-01: Validate target with regex before passing to subprocesses.
    """
    # T-01-03-SI-01: validate target before any subprocess call
    if not _DOMAIN_RE.match(target):
        raise ValueError(
            f"Invalid target domain (must match ^[a-zA-Z0-9.-]+$): {target!r}"
        )

    # collected: subdomain → source; deduplication by key
    collected: dict[str, str] = {}

    async with asyncio.TaskGroup() as tg:
        tg.create_task(
            subfinder.run(target, lambda s: collected.setdefault(s, "subfinder"))
        )
        tg.create_task(crt.run(target, lambda s: collected.setdefault(s, "crt")))
        tg.create_task(
            github.run(target, lambda s: collected.setdefault(s, "github"))
        )
        tg.create_task(
            gitlab.run(target, lambda s: collected.setdefault(s, "gitlab"))
        )

    records = [
        {"subdomain": sub, "source": src} for sub, src in collected.items()
    ]
    atomic_write_jsonl(out_file, records)
