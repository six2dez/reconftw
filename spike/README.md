# reconFTW v2 Language Spike

## Purpose

This directory contains throwaway Proof-of-Concept implementations of the same recon slice in both Go and Python, used to make a measured, data-driven language choice for the reconFTW v2.0 rewrite. The language decision is signed in `.planning/decisions/0001-language.md` (created in Plan 01-05 after the spike runs). **This code is THROWAWAY — it does NOT evolve into production. Phase 3 Foundation rebuilds against the chosen language's stack; spike code is reference material in git history only.**

## Scope (Locked by Plan 01-01)

The following Open Questions from `.planning/phases/01-language-adr-spike/01-RESEARCH.md` are locked here as planner decisions. Plans 01-02 and 01-03 MUST implement against these locked decisions without deviation.

- **OQ1 (config loader): EXCLUDED from spike** — `--target` only via stdlib flag/argparse. No TOML config loading in the spike. (Per researcher EXCLUDE recommendation: config loading tests the config library, not the orchestration pattern; it would bias LoC counts without adding comparison signal.)

- **OQ2 (CLI lib): INCLUDED** — Go uses `cobra v1.9.1`, Python uses `typer 0.21.x` (parity with Phase 3). (Per researcher INCLUDE recommendation: both are locked for Phase 3 anyway; using them in the spike keeps code-shape parity so spike-to-production mapping is direct.)

- **OQ3 (PyInstaller measurement): INCLUDED** — Python spike measures both `uv tool install` venv AND `pyinstaller --onefile` size; the PyInstaller binary (`spike/python/dist/spike`) is the canonical M5 RSS measurement target (shape-parity with Go's stripped binary). The `.venv` is kept for M3a venv-size measurement only. Measuring against the PyInstaller binary is required for apples-to-apples M5 comparison — measuring the venv wrapper script would systematically under-measure Python's actual process RSS. (Per researcher INCLUDE recommendation.)

- **OQ4 (credentials):** Throwaway tokens at `spike/corpus/.tokens.github` and `spike/corpus/.tokens.gitlab` (gitignored). If either absent at spike-time → that source skips gracefully (logged at `[SKIP]` level). Token files MUST NEVER be committed — both are in `.gitignore`. (Per researcher recommendation: accept the graceful-skip branch as a testable code path; real tokens needed for full subdomain set, but the skip path validates the credential-handling code.)

- **OQ5 (target rotation):** `compare.sh <target>` accepts one target arg; defaults to `example.com`. Maintainer runs once per target manually. No automated rotation — the comparison runner is not a cron job. (Per researcher recommendation: simplicity over automation for a 1-week spike harness.)

## Layout

```
spike/
├── README.md                       # This file
├── compare.sh                       # Comparison runner (bash + GNU coreutils + jq)
├── comparison.json                  # Output of compare.sh (gitignored)
├── corpus/
│   ├── targets.txt                  # 3 test targets, one per line
│   ├── mock_stubborn_tool.sh        # Synthetic mock for kill-tree test
│   └── expected/                    # Expected outputs (subdomain sets per target, regenerated weekly)
│       └── .gitkeep
├── baselines/
│   ├── .gitkeep
│   └── example.com.expected       # Bash v1 reference subdomain set (or placeholder)
├── go/                              # Go spike implementation (Plan 01-02)
│   └── .gitkeep
└── python/                          # Python spike implementation (Plan 01-03)
    └── .gitkeep
```

## Running

### Go spike

```bash
# Build
make -C spike/go build
# Produces: spike/go/bin/spike

# Unit tests
make -C spike/go test

# Integration tests (requires external tools)
make -C spike/go integration-test
```

### Python spike

```bash
# Install dependencies and build
make -C spike/python build
# Also builds PyInstaller binary: spike/python/dist/spike

# Unit tests
make -C spike/python test

# Integration tests (requires external tools)
make -C spike/python integration-test
```

### Comparison

```bash
# Run both spikes against default target (example.com) and emit spike/comparison.json
./spike/compare.sh

# Run against a specific target
./spike/compare.sh example.com

# Run against all 3 corpus targets (manually, one at a time)
./spike/compare.sh example.com
./spike/compare.sh example.com
./spike/compare.sh controlled-lab.test
```

## Slice Locked

Both spikes implement EXACTLY this recon slice. No additions, no substitutions.

### Passive sources (4 — all must be present in both implementations)

- `subfinder` — passive multi-source aggregator; NDJSON output; exercises subprocess streaming of long output
- `crt` — crt.sh certificate transparency; JSON-array output (single blob, not streaming); exercises different JSON parse shape
- `github-subdomains` — GitHub-based subdomain search; line-text output; exercises authenticated source + file-based credential handling
- `gitlab-subdomains` — GitLab-based subdomain search; line-text output; exercises 2-source optional credential logic (skip gracefully if `spike/corpus/.tokens.gitlab` absent)

### httpx flags (locked set — do not add or remove)

```
httpx -l <subs_file> -silent -json -status-code -title -tech-detect -no-color -threads 50 -timeout 10
```

All 8 flags are required: `-l` (file-based input, avoids stdin race condition), `-silent` (suppress banner/progress noise), `-json` (NDJSON line-by-line output for streaming test), `-status-code` (at least one real NDJSON field), `-title` (second field), `-tech-detect` (exercises async tech-detection), `-no-color` (prevents ANSI codes breaking JSON parse), `-threads 50` (bounded concurrency to avoid DoS).

### Atomic-write contract (4-step — both spikes must implement all 4 steps)

Every output artifact file in `spike/{lang}/out/*.jsonl` must be written atomically:
1. Create tempfile in the same directory as the target (same filesystem, avoids cross-device rename)
2. Write all data and `fsync()` the tempfile
3. Rename/replace tempfile to target path (atomic on POSIX filesystems)
4. `fsync()` the parent directory (often missed — required to survive power-loss between rename and directory update)

### Kill-tree contract (process-group kill — both spikes must implement this exact pattern)

Every subprocess invocation uses `Setpgid: true` (Go) or `preexec_fn=os.setsid` (Python) to make the child the process-group leader. On cancellation:
1. Send `SIGTERM` to the process group (`kill(-pgid, SIGTERM)` / `os.killpg(pgid, SIGTERM)`)
2. Allow 5-second `WaitDelay` grace period
3. If still alive after 5s, escalate to `SIGKILL` on the process group
4. `cmd.Wait()` / `await proc.wait()` to reap the zombie

This is the `Setpgid/setsid + signal-on-group + 5s WaitDelay grace + SIGKILL escalation` pattern. The `_kill_tree()` depth-first `pgrep -P` walk from bash v1 `lib/parallel.sh` is NOT used in v2 spikes — v2 uses process-group primitives directly, which is simpler and more reliable since there is no job-control constraint.

## Metrics (M1-M6)

Both spikes are scored against these 6 metrics. `compare.sh` collects all 6 automatically when both spike binaries are built.

| # | Metric | Type | How Measured | Pass/Fail |
|---|--------|------|--------------|-----------|
| M1 | Dev velocity (LoC) | Numeric | `tokei spike/{lang}/ --output json` (code-only, exclude tests) | No threshold — noise-band tie-breaker |
| M2 | Dev velocity (hours) | Numeric | Sum of per-session timer logs in `spike/.spike_sessions.log` | No threshold — noise-band tie-breaker |
| M3 | Packaging footprint | Numeric (bytes) | Go: stripped binary bytes. Python: venv kB (M3a) + PyInstaller binary bytes (M3b) | Go < 80 MB; Python venv < 600 MB (sanity bounds) |
| M4 | Kill-tree correctness | Binary (PASS/FAIL) | Synthetic mock test: all descendants dead within 10s after SIGINT | **KILLER-FEATURE OVERRIDE — fail = lose regardless of other metrics** |
| M5 | RSS under load | Numeric (kB) | `/usr/bin/time -l` (macOS) or `-v` (Linux) on spike run against `example.com` | No hard threshold — noise-band tie-breaker |
| M6 | Cross-platform pain | Ordinal (1/2/3) | 1=first try, 2=config change needed, 3=code change needed | 3 = killer-feature override |
| + | MCP library support | Ordinal (1/2/3) | 1=official SDK at v1.x stable | **Both langs = 1. NOT a tie-breaker signal.** |

**Tie-breaker rule (DEC-04):** If all numeric metrics (M1/M2/M3/M5) are within a 25% noise band AND no killer-feature override is triggered: **choose Go** (single-binary distribution wins). This rule is invoked ONLY when the noise-band condition is confirmed — see ADR verdict format.

## Throwaway

This code does NOT evolve into production. Phase 3 Foundation rebuilds against the chosen language's stack from scratch; spike code is reference material in git history only. Every source file in `spike/go/` and `spike/python/` carries a comment at the top: `// Spike PoC — DO NOT EVOLVE INTO PRODUCTION` (Go) or `# Spike PoC — DO NOT EVOLVE INTO PRODUCTION` (Python). If you find yourself thinking "I could reuse this in Phase 3," stop — Phase 3's codebase starts clean.
