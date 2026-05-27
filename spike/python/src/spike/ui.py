# SPDX-License-Identifier: MIT
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md
# Locked scope: spike/README.md §Scope
# Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §3.4

import sys


def info(msg: str) -> None:
    print(f"[INFO] {msg}", file=sys.stderr, flush=True)


def skip(component: str, reason: str) -> None:
    print(f"[SKIP] {component}: {reason}", file=sys.stderr, flush=True)


def warn(msg: str) -> None:
    print(f"[WARN] {msg}", file=sys.stderr, flush=True)


def err(msg: str) -> None:
    print(f"[ERR ] {msg}", file=sys.stderr, flush=True)
