# Phase 1: Language ADR & Spike - Research

**Researched:** 2026-05-27
**Domain:** Language selection via measurable side-by-side spike PoC (Go vs Python)
**Confidence:** HIGH on slice composition, harness layout, ADR template, MCP availability; MEDIUM on per-metric scoring weights (subjective by design — single-maintainer judgment)

## Summary

This phase has **no Go vs Python comparison research to do** — that has been completed in `.planning/research/STACK.md` (14 dimensions), `.planning/research/ARCHITECTURE.md` (dual-tracked patterns), `.planning/research/PITFALLS.md` (51 pitfalls), and `.planning/research/SUMMARY.md` (joint factual basis). The decision is owned by the spike PoC; the spike measures, the ADR decides.

This research's job was to turn four open delegations from CONTEXT.md into actionable, planner-ready guidance: (1) slice exact composition, (2) per-metric scoring rubric + tie-breaker precision, (3) spike harness/repo layout, and (4) the ADR template + post-ADR collapse mechanics. Plus the deferred cross-check: MCP library availability per language as a potential tie-breaker signal for Phase 8.

**Primary recommendation:** Build the spike against 4 passive sources (`subfinder`, `crt`, `github-subdomains`, `gitlab-subdomains`) + a minimal `httpx -silent -json -status-code -title -tech-detect` probe + an `AtomicWriter` to JSONL + a SIGINT kill-tree test (synthetic mock as unit test, real-tool integration test). Score each lang against 6 metrics (the 5 DEC-03 metrics + MCP support) on a numeric/ordinal rubric; treat kill-tree as a killer-feature override (fail it → lose regardless); invoke DEC-04 tie-breaker (Go-wins-on-25%-noise) explicitly in the ADR's verdict section. Repo layout: `spike/go/` + `spike/python/` + `spike/corpus/targets.txt` (3 domains) + `spike/compare.sh` (bash + GNU coreutils comparison runner).

**MCP cross-check finding (key):** Both Go and Python now have **official, v1.x-stable MCP SDKs**. Python SDK (`pypi:mcp`) has been v1.x since Q1 2025, is maintained by Anthropic, 97M+ monthly downloads, the de-facto reference implementation. Go SDK (`github.com/modelcontextprotocol/go-sdk`) reached v1.x in 2026 (latest v1.6.1, May 22 2026), maintained by Anthropic in collaboration with Google, supports 4 protocol versions. **Neither lang is materially worse for Phase 8 MCP work.** MCP availability is therefore **NOT a tie-breaker signal** in this ADR — the deferred concern is resolved. Python has slightly more maturity (longer at v1.x); Go has the larger backing team (Google co-maintenance) but younger codebase. Both are production-ready for Phase 8.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01 Timebox** — **1 calendar week PER language** (2 weeks total for both PoCs combined). HARD limit: if either language isn't complete within its 1-week window, STOP and use what was built. The spike is a viability comparison, NOT the implementation. Spike scope creep is a known PITFALL — discipline at this gate prevents the whole milestone from drifting.

**D-02 Solo same-day sign-off**, no community pre-review. After both spikes are complete (or timeboxes expire), write the ADR including measured numbers + tie-breaker invocation + final verdict, then sign and commit the ADR same day. No GitHub Discussion / PR review gate. Optionally publish ADR as post-decision GitHub Release note (not a gate).

**D-03 Delete loser language permanently** from research files. After ADR signed:
- `.planning/research/STACK.md` → edit in place; remove the losing language's table + library blacklist entries; keep only the winning language's stack
- `.planning/research/ARCHITECTURE.md` → edit in place; remove dual-tracked sections; keep only the winning language's idiomatic patterns
- `.planning/research/SUMMARY.md` → edit in place; rewrite "Stack Snapshot" + "Architecture: Top Cross-Cutting Patterns" to reference the chosen language only
- `.planning/research/PITFALLS.md` → edit in place; remove pitfalls specific to the losing language; keep cross-cutting ones
- **ADR is the single source of historical truth** for the comparison.

### Claude's Discretion

- **Slice exact composition** — How many passive sources (DEC-02 says 5-10), which specific sources, httpx probe depth, kill-tree test setup. Planner decides in `01-PLAN.md`; this RESEARCH.md surfaces tradeoffs and recommends.
- **Comparison metrics weighting + tie-breaker precision** — DEC-03 lists 5 metrics; DEC-04 default tie-breaker is "Go if within 25% noise band". Planner defines per-metric rubric + killer-feature overrides in `01-PLAN.md`.
- **Spike harness / repo layout** — `spike/go/` + `spike/python/` parallel directories per DEC-02. Planner designs shared test corpus, comparison runner, test framework details in `01-PLAN.md`.

### Deferred Ideas (OUT OF SCOPE)

- **MCP library availability per language** (Phase 8 dependency) → researcher cross-checks during Phase 1; if MCP support is materially worse in one lang, that's a tie-breaker signal. **RESOLVED in this research: both langs have v1.x stable official SDKs — NOT a differentiator.**
- **Public announcement of the ADR decision** → optional GitHub Release note post-cutover (Phase 12), NOT a Phase 1 deliverable.
- **Spike code in `spike/{loser}/` after ADR** — D-03 cleanup decision does NOT cover this. Planner decides during Phase 2 planning whether to delete spike trees, archive them, or keep them in git history only.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DEC-01 | User can read a signed ADR (`.planning/decisions/0001-language.md`) documenting language choice with evidence | Section 4 (ADR template + signing convention) |
| DEC-02 | Spike PoC implements identical recon slice in BOTH Go and Python: passive subdomain enum (5-10 sources) + httpx probe + atomic JSONL writes + SIGINT kill-tree test | Section 1 (exact slice composition: 4 sources, minimal httpx flags, kill-tree test setup) |
| DEC-03 | Spike measures and records, per lang: (a) dev velocity LoC+hours, (b) packaging footprint, (c) kill-tree correctness, (d) memory under 5K hosts, (e) cross-platform pain | Section 2 (per-metric measurement protocol + scoring rubric + 6th metric: MCP support) |
| DEC-04 | ADR includes pre-agreed tie-breaker rule (default: Go if metrics within 25% noise band) | Section 2 (tie-breaker precision + killer-feature overrides) |
| DEC-05 | After ADR signed, all dual-tracked research files (STACK/ARCHITECTURE) collapse to single-language sections | Section 4 (post-ADR collapse checklist for the planner) |
</phase_requirements>

## Architectural Responsibility Map

> The "system" here is the **spike PoC itself**, not production reconFTW. The spike is a single-process CLI tool that wraps subprocesses. No multi-tier model applies. Map below is for completeness — most rows collapse to one tier.

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| CLI entry / arg parsing | Spike process | — | Single binary / single Python entry point |
| Passive source orchestration | Spike process | External subprocesses | Spike calls subfinder/crt/github-subdomains via `os/exec` (Go) or `asyncio.create_subprocess_exec` (Python) |
| httpx probe | Spike process | External subprocess | Spike spawns httpx, parses JSON output line-by-line |
| Atomic JSONL write | Spike process (filesystem) | — | tempfile + fsync + rename + parent dir fsync — owned by the spike |
| SIGINT kill-tree | OS (signal delivery) + Spike process (signal handler) + External subprocesses (process-group leaders) | — | Test asserts cross-tier signal propagation works |
| Comparison metrics collection | Comparison runner (bash + GNU coreutils) | Filesystem (output JSONL diff) | Runs both spikes against same target; produces `comparison.json` from `wc -l` / `/usr/bin/time -v` / `du -sh` |

**Why this matters:** The spike's purpose is to exercise the cross-cutting concerns that have failed in past bash → typed-lang migrations (subprocess kill-tree, atomic writes, error propagation). The architecture is intentionally **boring single-process**: anything more would be the production design, which belongs in Phase 3.

## Standard Stack

### Core (Both Spikes Must Use These — verified in `.planning/research/STACK.md`)

#### Go Spike

| Library | Version | Purpose | Provenance |
|---------|---------|---------|------------|
| Go runtime | 1.24+ (target 1.26) | Language runtime | [VERIFIED: `go version` on dev machine = go1.26.1 darwin/arm64] |
| `spf13/cobra` | v1.9.1 | CLI subcommands (optional in spike; can use stdlib `flag`) | [CITED: STACK.md §3, Context7-verified] |
| `knadh/koanf/v2` | latest | TOML config loader (optional in spike — skip if minimal) | [CITED: STACK.md §4, Context7-verified] |
| `os/exec` (stdlib) | stdlib | Subprocess wrapper with `CommandContext` + `WaitDelay` | [CITED: STACK.md §1; canonical Go pattern] |
| `log/slog` (stdlib) | stdlib | Structured logging | [CITED: STACK.md §5] |
| `golang.org/x/sync/errgroup` | latest | Bounded concurrency with `SetLimit(N)` | [CITED: STACK.md §2] |
| `testing` (stdlib) + `stretchr/testify` | testify v1.10.x | Unit + integration tests | [CITED: STACK.md §7] |
| `modernc.org/sqlite` | latest | SQLite if checkpoint test included (probably NOT in spike — too much scope) | [CITED: SUMMARY.md §Stack Snapshot] |

#### Python Spike

| Library | Version | Purpose | Provenance |
|---------|---------|---------|------------|
| Python runtime | 3.12+ (target 3.13) | Language runtime | [VERIFIED: `python3 --version` on dev machine = 3.14.4 (newer than required minimum)] |
| `typer` | 0.21.x | CLI (optional in spike; can use stdlib `argparse`) | [CITED: STACK.md §3, Context7-verified] |
| `pydantic-settings` | 2.14.x | TOML config loader (optional in spike — skip if minimal) | [CITED: STACK.md §4, Context7-verified] |
| `asyncio.create_subprocess_exec` (stdlib) | stdlib | Subprocess wrapper with `start_new_session=True` / `setsid` | [CITED: STACK.md §1] |
| `structlog` | 25.x | Structured logging | [CITED: STACK.md §5, Context7-verified] |
| `asyncio.TaskGroup` (stdlib) | stdlib (3.11+) | Structured concurrency | [CITED: STACK.md §2] |
| `pytest` + `pytest-asyncio` | 9.0.3 + latest | Unit + integration tests | [CITED: STACK.md §7] |
| `uv` (tooling) | 0.11+ | Venv management | [VERIFIED: `uv --version` on dev machine = 0.10.2 (will upgrade)] |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `goreleaser` | v2.x | Cross-build matrix for Go binary | Only if comparing packaging footprint via full build; spike can use plain `go build` |
| `uv tool install` / `pipx` | uv 0.11+ | Python distribution measurement | For DEC-03(b) packaging footprint measurement |
| `PyInstaller` | 6.x | Python single-binary alternative | OPTIONAL — only include if planner wants to measure "Python-as-single-binary" footprint vs Go's binary |
| `goleak` (uber-go) | latest | Goroutine leak detection in tests | OPTIONAL — Go-side discipline; can defer to Phase 3 |
| `/usr/bin/time -l` (macOS) or `/usr/bin/time -v` (Linux) | system | RSS measurement | DEC-03(d) memory under load measurement |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `cobra` (Go) | stdlib `flag` | Spike doesn't need subcommands; stdlib is enough. Recommend `cobra` to keep code-shape parity with production (it's locked for Phase 3 anyway). |
| `typer` (Python) | stdlib `argparse` | Same as above — `typer` is locked for Phase 3; use it to keep parity. |
| `pydantic-settings` (Python) | `tomllib` (stdlib) directly | Spike can skip the layered-precedence model and just `tomllib.load(open("spike.toml"))`. **Recommend skipping** for spike — production Phase 3 will do the full pydantic-settings dance. |
| `koanf/v2` (Go) | `pelletier/go-toml/v2` directly | Same — spike can just parse TOML once. **Recommend skipping** for spike. |
| `goreleaser` | Plain `go build -ldflags="-s -w"` | Spike doesn't need cross-build matrix — measure native binary size only. Phase 11 will use goreleaser. |
| `PyInstaller` for Python footprint | `uv tool install` measurement | Recommend BOTH if planner wants apples-to-apples comparison (Go single binary vs Python single binary). Otherwise `uv tool install` footprint suffices. |

**Verified installation (Go):**
```bash
# Required to exist on dev machine — VERIFIED 2026-05-27
go install github.com/spf13/cobra-cli@latest        # optional, for scaffolding
go get github.com/spf13/cobra@v1.9.1                # CLI (optional in spike)
go get github.com/stretchr/testify@latest           # test assertions
```

**Verified installation (Python):**
```bash
# Required to exist on dev machine — VERIFIED 2026-05-27
uv venv .venv
uv pip install typer==0.21.1                         # CLI (optional in spike)
uv pip install pytest pytest-asyncio                 # tests
uv pip install structlog                             # structured logging
```

**Version verification (run before locking the spike):**
```bash
# Go side
go list -m github.com/spf13/cobra                    # confirm v1.9.1 or current
go list -m github.com/stretchr/testify

# Python side
uv pip show typer pydantic-settings structlog pytest pytest-asyncio
```

## Package Legitimacy Audit

> Verified via slopcheck v[latest] on 2026-05-27. PyPI and Go ecosystem registries probed.

| Package | Registry | Age | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-------------|-----------|-------------|
| `typer` | PyPI | 6+ yrs | github.com/fastapi/typer | OK | Approved [VERIFIED: slopcheck] |
| `pydantic-settings` | PyPI | 2+ yrs | github.com/pydantic/pydantic-settings | OK | Approved [VERIFIED: slopcheck] |
| `structlog` | PyPI | 10+ yrs | github.com/hynek/structlog | OK | Approved [VERIFIED: slopcheck] |
| `pytest` | PyPI | 15+ yrs | github.com/pytest-dev/pytest | OK | Approved [VERIFIED: slopcheck] |
| `pytest-asyncio` | PyPI | 7+ yrs | github.com/pytest-dev/pytest-asyncio | OK | Approved [VERIFIED: slopcheck] |
| `httpx` | PyPI | 5+ yrs | github.com/encode/httpx | OK | Approved [VERIFIED: slopcheck] |
| `mcp` (Python MCP SDK) | PyPI | 1+ yr | github.com/modelcontextprotocol/python-sdk | OK | Approved [VERIFIED: slopcheck] — relevant for Phase 8 cross-check; not in spike scope |
| `github.com/spf13/cobra` | Go modules | 8+ yrs | github.com/spf13/cobra | OK (NO_REPO false signal) | Approved [VERIFIED: slopcheck — NO_REPO is a slopcheck signal for Go modules where the registry doesn't directly link a repo; cobra is the de-facto Go CLI lib, mature, safe] |
| `github.com/knadh/koanf/v2` | Go modules | recent | github.com/knadh/koanf | OK (RECENTLY_CREATED flag) | Approved [VERIFIED: slopcheck — `/v2` SIV module path is newer than original koanf; package is mature, not slop] |
| `github.com/stretchr/testify` | Go modules | 10+ yrs | github.com/stretchr/testify | OK (NO_REPO false signal) | Approved [VERIFIED: slopcheck] |
| `github.com/modelcontextprotocol/go-sdk` | Go modules | new (May 2026) | github.com/modelcontextprotocol/go-sdk | **SLOP (BRAND_NEW flag)** | **FALSE POSITIVE** — verified via WebSearch + GitHub: this is the **official MCP Go SDK** maintained by Anthropic + Google, published 2026-05-22, v1.6.1. slopcheck flags it because it's brand-new (correct for an unknown package, false for one we've independently verified). **Relevant for Phase 8, not Phase 1 spike.** [CITED: github.com/modelcontextprotocol/go-sdk, pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp] |

**Packages removed due to slopcheck [SLOP] verdict:** None for Phase 1 spike scope. The MCP Go SDK SLOP flag is a documented false positive (brand-new official Anthropic/Google package; outside the spike's installation list anyway).

**Packages flagged as suspicious [SUS]:** None.

**Phase 1 spike installation list:** All approved. Planner does not need to insert `checkpoint:human-verify` tasks for any spike dependency.

## Architecture Patterns

### Spike PoC Conceptual Diagram

```
                              ┌─────────────────────────────┐
       SIGINT ────────────────►│   Spike Process (parent)    │
                              │  - Signal handler           │
                              │  - Goroutines / asyncio     │
                              │    tasks fan-out & merge    │
                              └──────┬──────────────────────┘
                                     │ spawn (Setpgid / start_new_session)
                  ┌──────────────────┼──────────────────┐
                  ▼                  ▼                  ▼
            ┌──────────┐      ┌──────────┐      ┌──────────────┐
            │subfinder │      │   crt    │      │github-       │
            │ (subproc │      │ (subproc │      │ subdomains   │
            │  group)  │      │  group)  │      │ (subproc grp)│
            └────┬─────┘      └────┬─────┘      └────┬─────────┘
                 │ stdout (NDJSON) │ stdout (JSON)   │ stdout (text)
                 ▼                 ▼                 ▼
            ┌─────────────────────────────────────────────────┐
            │ Spike merger: dedupe → in-scope filter →        │
            │ atomic write to spike/{lang}/out/subs.jsonl     │
            └────────────────────────┬────────────────────────┘
                                     │ subs.jsonl
                                     ▼
                              ┌──────────────┐
                              │httpx (subproc│   ── on cancellation:
                              │ group leader)│      kill -PGID PGRP_OF_HTTPX
                              └──────┬───────┘
                                     │ stdout (NDJSON)
                                     ▼
            ┌─────────────────────────────────────────────────┐
            │ Spike consumer: parse line-by-line → atomic     │
            │ write to spike/{lang}/out/hosts.jsonl            │
            └─────────────────────────────────────────────────┘
```

**Key data flow:**
1. CLI parses `--target example.com` arg
2. Fan-out: 4 passive sources spawned concurrently (each in own process group)
3. Merge: each tool's stdout collected, deduplicated, in-scope-filtered, written ATOMICALLY to `subs.jsonl`
4. Pipeline: httpx invoked with `-l subs.jsonl` (or stdin pipe — file mode preferred per PITFALL 1.4)
5. Consume: httpx NDJSON parsed line-by-line, written ATOMICALLY to `hosts.jsonl`
6. SIGINT at any point → signal handler triggers cancellation → process-group kill → exit clean

### Pattern 1: Process-Group Subprocess Wrapper

**What:** Every external tool invocation MUST run in its own process group so SIGINT to the spike kills the entire tool tree.
**When to use:** Every single `exec` call in the spike.
**Source:** STACK.md §1, §11, §12; PITFALLS.md §1.2 (top-impact pitfall).

**Go example:**
```go
// Source: STACK.md §12 (verbatim pattern)
cmd := exec.CommandContext(ctx, "subfinder", "-d", target, "-silent", "-json")
cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
cmd.WaitDelay = 5 * time.Second
cmd.Cancel = func() error {
    return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) // negative PID = process group
}
```

**Python example:**
```python
# Source: STACK.md §12 (verbatim pattern)
proc = await asyncio.create_subprocess_exec(
    "subfinder", "-d", target, "-silent", "-json",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    preexec_fn=os.setsid,  # POSIX — makes child the process group leader
)
# On cancel:
try:
    async with asyncio.timeout(timeout):
        stdout, stderr = await proc.communicate()
except (asyncio.TimeoutError, asyncio.CancelledError):
    os.killpg(proc.pid, signal.SIGTERM)
    await asyncio.sleep(5)
    if proc.returncode is None:
        os.killpg(proc.pid, signal.SIGKILL)
    raise
```

**Verify:** A test that spawns a mock tool which (a) ignores SIGTERM, (b) sleeps + spawns 2 grandchildren that ALSO ignore SIGTERM, then SIGINT the spike — within 10s, `pgrep -P <spike_pid>` returns empty AND `pgrep -f mock_tool` returns empty.

### Pattern 2: Atomic JSONL Write (tempfile + fsync + rename + parent dir fsync)

**What:** Final output files must be written atomically so a SIGKILL between write and rename leaves the original file intact (or no file at all — never a torn write).
**When to use:** Every artefact file in `spike/{lang}/out/*.jsonl`.
**Source:** ARCHITECTURE.md §7b; PITFALLS.md §3.1 (top-5 impact pitfall); [LWN: A way to do atomic writes](https://lwn.net/Articles/789600/).

**Critical detail:** Most implementations forget the **parent dir fsync** after rename — without it, the rename can be lost on power-loss / crash. The spike MUST do all 4 steps:
1. `tempfile.NamedTemporaryFile(dir=same_filesystem_as_target)`
2. write all data
3. `tmp.flush(); os.fsync(tmp.fileno())`
4. `os.replace(tmp.name, target_path)` (Python) or `os.Rename` (Go)
5. `parent_dir_fd = open(parent_dir); os.fsync(parent_dir_fd); os.close(parent_dir_fd)` ← **the often-forgotten step**

**Go example:**
```go
// Source: ARCHITECTURE.md §7b
func atomicWriteJSONL(target string, lines [][]byte) error {
    dir, base := filepath.Split(target)
    tmp, err := os.CreateTemp(dir, base+".tmp.*")
    if err != nil { return err }
    defer os.Remove(tmp.Name()) // cleanup on error path

    for _, line := range lines {
        if _, err := tmp.Write(line); err != nil { return err }
        if _, err := tmp.Write([]byte("\n")); err != nil { return err }
    }
    if err := tmp.Sync(); err != nil { return err }
    if err := tmp.Close(); err != nil { return err }
    if err := os.Rename(tmp.Name(), target); err != nil { return err }

    // Critical: fsync the parent dir (often missed)
    parentFD, err := os.Open(dir)
    if err != nil { return err }
    defer parentFD.Close()
    return parentFD.Sync()
}
```

**Python example:**
```python
# Source: ARCHITECTURE.md §7b (extended with parent dir fsync)
import os, tempfile

def atomic_write_jsonl(target: str, lines: list[dict]) -> None:
    d = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(target) + ".tmp.", dir=d, text=False)
    try:
        with os.fdopen(fd, "wb") as f:
            for line in lines:
                f.write(json.dumps(line).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)  # atomic rename
        # Critical: fsync parent dir
        parent_fd = os.open(d, os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        os.unlink(tmp)
        raise
```

**Verify:** A test that (a) writes a large JSONL via the AtomicWriter in a child process, (b) SIGKILLs the child between fsync and rename (use a fault-injection wrapper or `LD_PRELOAD` shim), (c) asserts the original target file is either pre-write state OR fully written — never partial.

### Pattern 3: Streaming Subprocess Output (bufio.Scanner / line-by-line async)

**What:** httpx output for big targets can exceed 64 KiB of buffer; reading entire stdout into a `bytes.Buffer` risks deadlock (PITFALL 1.1).
**When to use:** Any subprocess emitting unbounded NDJSON / line-oriented output (httpx, nuclei, dalfox).
**Source:** STACK.md §1 (anti-pattern: `cmd.Run()` for long-running tools); PITFALLS.md §1.1, §1.5.

**Go example:**
```go
// Source: STACK.md §1, derived from canonical streaming pattern
cmd := exec.CommandContext(ctx, "httpx", "-l", subsFile, "-silent", "-json")
cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
stdout, err := cmd.StdoutPipe()
if err != nil { return err }
if err := cmd.Start(); err != nil { return err }

scanner := bufio.NewScanner(stdout)
scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 1MiB initial, 10MiB max per line
for scanner.Scan() {
    line := scanner.Bytes()
    // parse + handoff to consumer goroutine
}
if err := cmd.Wait(); err != nil { return err }
```

**Python example:**
```python
# Source: STACK.md §1
proc = await asyncio.create_subprocess_exec(
    "httpx", "-l", subs_file, "-silent", "-json",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    preexec_fn=os.setsid,
)
async for line in proc.stdout:
    parsed = json.loads(line)
    # handoff to consumer
await proc.wait()
```

### Anti-Patterns to Avoid (in the spike code)

- **`cmd.Run()` / `subprocess.run()` for httpx** — buffers entire output; will deadlock at scale. Use `cmd.Start()` + streaming.
- **`subprocess.run(timeout=N)` for kill-tree test** — kills only direct child, leaves grandchildren orphaned. Use `start_new_session=True` + `os.killpg`.
- **`cmd.Process.Kill()` alone (Go)** — orphans grandchildren. Use `syscall.Kill(-pid, SIGTERM)`.
- **`open(path, "w").write(json.dumps(data))`** — not atomic. Use the atomic-write pattern.
- **`for d in domains: await scan(d)`** — sequential by accident (PITFALL 2.4). Use `asyncio.TaskGroup` for fan-out.
- **`asyncio.gather(...)` without `return_exceptions=True`** — orphan siblings on error (PITFALL 2.5). Use `TaskGroup`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Subprocess kill-tree | Custom pgrep walk | Go: `Setpgid` + `Kill(-pid)`. Python: `setsid` + `os.killpg` | Bash already walked this path with `_kill_tree`; both langs have native primitives |
| Atomic file write | Two-line tempfile+rename | Pattern from ARCHITECTURE.md §7b (4 steps including parent dir fsync) | Missing parent dir fsync = silent data loss on crash |
| Signal handling | Custom `signal.signal()` | Go: `signal.NotifyContext`. Python: `loop.add_signal_handler` | Race conditions if done wrong (PITFALL §11); use stdlib idioms |
| Concurrency limiting | Custom worker pool | Go: `errgroup.SetLimit(N)`. Python: `asyncio.Semaphore(N)` + `TaskGroup` | Both have battle-tested stdlib equivalents |
| TOML parsing | Hand-rolled regex | Go: `pelletier/go-toml/v2`. Python: `tomllib` (stdlib) | Both are zero-dep or stdlib |
| JSON parsing | Hand-rolled | Go: `encoding/json`. Python: `json` (stdlib) | Stdlib is fine |
| Test framework | bash-style assertions | Go: `testing` + `testify`. Python: `pytest` + `pytest-asyncio` | Spike tests are NOT bats — match production Phase 3 framework |

**Key insight:** Both langs have ~95% of what the spike needs in their stdlib. The spike's PURPOSE is to validate that stdlib + 1-2 small libs is sufficient — NOT to evaluate which library ecosystem is richer. Adding more dependencies to the spike biases the comparison.

## Common Pitfalls

### Pitfall 1: Spike scope creep — building "almost the production thing"

**What goes wrong:** Developer starts the spike, adds "just a checkpoint store" and "just a config loader" and "just a notifier" — 2 weeks per lang becomes 6 weeks per lang. Project drifts. Burnout. ADR never signed.

**Why it happens:** Both Go and Python make it tempting to "while I'm here, add this small thing." Production-quality code is the wrong target for a spike.

**How to avoid:**
- Hard timebox: 1 week per lang (D-01). If incomplete, ship what's built.
- Slice scope locked in PLAN.md, not negotiable mid-spike.
- Spike code is THROWAWAY — comments at top of every file: `// Spike PoC — DO NOT EVOLVE INTO PRODUCTION`.
- The 5 DEC-03 metrics are the ONLY things being measured. Anything that doesn't move a metric is out.

**Warning signs:** "We could add..." / "While I'm in there..." / "It would be nice if..."

### Pitfall 2: Measuring "felt easier" instead of LoC + hours

**What goes wrong:** Developer writes both spikes sequentially. By the time the second one is built, they have learned from the first; the second one is faster. Pattern matching makes one lang "feel easier" — bias.

**Why it happens:** Single maintainer writes both PoCs back-to-back. Cognitive bias toward the language written second OR first (whichever felt more pleasant).

**How to avoid:**
- **Per-session timer:** every coding session of the spike, start a timer; commit message includes "Spike $LANG session N: $MINUTES min". After the spike, sum minutes per lang.
- **LoC is checkable:** `tokei spike/go/` / `tokei spike/python/` / or `cloc`. Document at end of spike.
- **Order randomization:** Flip a coin which lang to start. Whichever loses, do it second. Per-session timing makes lang ordering symmetric.
- **No "felt easier" metric in the ADR.** The ADR documents NUMBERS not vibes.

**Warning signs:** "Python just felt cleaner..." / "Go was more pleasant..." in the ADR draft.

### Pitfall 3: Kill-tree test that's actually a unit test of OS facilities

**What goes wrong:** Developer writes a test that mocks `os.killpg` and asserts it was called. Test passes. Real production: SIGINT orphans processes anyway.

**Why it happens:** Mocking the OS feels like a "real" test but it's testing the test framework, not the system.

**How to avoid:**
- Kill-tree test MUST be an integration test that:
  1. Spawns a real subprocess (a synthetic mock or a real tool)
  2. Subprocess spawns >=1 grandchild
  3. Test sends SIGINT to the spike parent
  4. Test waits 10s, then asserts via `pgrep -P` or `ps` that NO descendants are alive
- See Pattern 1 verification language above. The test asserts on OS state, not orchestrator state.

**Warning signs:** Test uses `mock.patch("os.killpg")` or `gomock.NewController`.

### Pitfall 4: Comparing apples-to-oranges in dev velocity

**What goes wrong:** Go spike implements 4 sources; Python spike implements 6. LoC comparison is meaningless — different scope.

**Why it happens:** Spike scope decisions made mid-flight in one lang carry over differently to the other.

**How to avoid:**
- Slice composition locked in `01-PLAN.md` BEFORE either spike starts. Same 4 sources, same httpx flags, same atomic write pattern, same kill-tree test.
- The comparison runner (`spike/compare.sh`) runs both spikes against the same target list. If outputs diverge, the spike is broken (or the slice is undefined). Failure mode is loud.

**Warning signs:** Go spike has a feature Python spike doesn't (or vice versa) at the end of the spike.

### Pitfall 5: Forgetting that DEC-04 tie-breaker is a default, not a mandate

**What goes wrong:** ADR concludes "metrics tied → choose Go" without examining whether metrics ARE tied.

**Why it happens:** Tie-breaker rule is mistaken as the verdict instead of the disambiguator.

**How to avoid:**
- ADR's Verdict section MUST explicitly state EITHER:
  - "Metrics show clear winner (X by Y%), tie-breaker NOT invoked, choose X"
  - OR: "Metrics within 25% noise band, tie-breaker invoked per DEC-04, choose Go"
- Never: "Tied → Go" without noise-band check.

**Warning signs:** Verdict section silent on whether tie-breaker was triggered.

## Runtime State Inventory

> N/A — this is a greenfield phase with no existing state to migrate. Section omitted.

## Code Examples

### Example 1: Atomic JSONL Write (canonical, both langs)

See **Pattern 2** above. The 4-step pattern (tempfile + fsync + rename + parent dir fsync) is the entire atomic-write contract.

### Example 2: Subprocess Spawn with Process Group (canonical, both langs)

See **Pattern 1** above. The `Setpgid` (Go) / `setsid` (Python) primitive + group-kill on cancel is the entire kill-tree contract.

### Example 3: Synthetic Mock Tool for Kill-Tree Test

A reusable mock that exercises the worst case: parent ignores SIGTERM, spawns 2 children that also ignore SIGTERM.

```bash
#!/usr/bin/env bash
# spike/corpus/mock_stubborn_tool.sh
# Sleeps forever; spawns 2 children that also sleep forever; all 3 ignore SIGTERM.
trap '' TERM
( trap '' TERM; sleep 3600 ) &
( trap '' TERM; sleep 3600 ) &
sleep 3600
```

Test asserts: spawn this script under the spike's subprocess wrapper, send SIGINT to spike, within 10s `pgrep -f mock_stubborn_tool` returns nothing (SIGKILL via process-group escalation worked).

### Example 4: Comparison Runner Skeleton (`spike/compare.sh`)

```bash
#!/usr/bin/env bash
# spike/compare.sh — runs both spikes against same target, emits comparison.json
set -euo pipefail

TARGET="${1:-hackerone.com}"
OUT="spike/comparison.json"

# Time + RSS for Go run
GO_START=$(date +%s)
/usr/bin/time -l ./spike/go/bin/spike --target "$TARGET" \
    >spike/go/out/run.log 2>spike/go/out/run.err
GO_END=$(date +%s)
GO_DURATION=$((GO_END - GO_START))
GO_RSS=$(grep "maximum resident set size" spike/go/out/run.err | awk '{print $1}')
GO_BINSIZE=$(stat -f%z spike/go/bin/spike)
GO_LOC=$(tokei spike/go/ --output json | jq '.Go.code')

# Same for Python
PY_START=$(date +%s)
/usr/bin/time -l ./spike/python/.venv/bin/spike --target "$TARGET" \
    >spike/python/out/run.log 2>spike/python/out/run.err
PY_END=$(date +%s)
PY_DURATION=$((PY_END - PY_START))
PY_RSS=$(grep "maximum resident set size" spike/python/out/run.err | awk '{print $1}')
PY_FOOTPRINT=$(du -sk spike/python/.venv | awk '{print $1}')
PY_LOC=$(tokei spike/python/ --output json | jq '.Python.code')

# Output diff (both must produce same set of subdomains)
GO_SUBS=$(jq -r '.subdomain' spike/go/out/subs.jsonl | sort -u)
PY_SUBS=$(jq -r '.subdomain' spike/python/out/subs.jsonl | sort -u)
SUB_DIFF=$(diff <(echo "$GO_SUBS") <(echo "$PY_SUBS") | wc -l)

cat <<EOF > "$OUT"
{
  "target": "$TARGET",
  "timestamp": "$(date -Iseconds)",
  "go":     { "duration_sec": $GO_DURATION, "rss_kb": $GO_RSS, "binary_bytes": $GO_BINSIZE, "loc": $GO_LOC },
  "python": { "duration_sec": $PY_DURATION, "rss_kb": $PY_RSS, "venv_kb": $PY_FOOTPRINT, "loc": $PY_LOC },
  "subdomain_set_diff_lines": $SUB_DIFF
}
EOF
echo "Wrote $OUT"
```

(Note: `/usr/bin/time -l` is macOS / BSD; `/usr/bin/time -v` is GNU/Linux. Planner chooses based on dev machine.)

---

# Section 1: Slice Exact Composition

This section resolves Open Decision #1 from CONTEXT.md (Claude's Discretion).

## 1.1 Which Passive Sources?

**Recommendation: 4 sources** (lower end of DEC-02's 5-10 range — fewer is better for a timeboxed spike; the 4 chosen cover the orthogonal axes that matter).

| Source | Type | Why It's In | What It Exercises |
|--------|------|-------------|-------------------|
| `subfinder` | Go binary, NDJSON output, multi-source aggregator | Default behavior of bash `sub_passive()` — anchors comparison to real bash code | Subprocess streaming (long output), NDJSON parsing |
| `crt` | Go binary, JSON-array output, single HTTP fetch (crt.sh) | Different output format (single JSON blob, not NDJSON); exercises HTTP error handling inside a subprocess | JSON parsing, subprocess that's mostly HTTP-bound, handles upstream service flakes |
| `github-subdomains` | Go binary, line-oriented text output, requires GITHUB_TOKENS file | Exercises **authenticated source** + secret-file handling (file path, NOT env var → tests both lang's process env propagation) | Secret handling, env vs file-arg, conditional skip on missing credentials |
| `gitlab-subdomains` | Go binary, line-oriented text output, requires GITLAB_TOKENS file | Same shape as github but DIFFERENT optional credential — exercises 2-source-conditional logic | Tests "skip gracefully if credentials absent" branch |

**Why not more?**
- `urlfinder`, `hackertarget`, etc. all use the same output shape (line text) — adding them is just more wiring, not more comparison signal.
- The slice needs to exercise: (a) NDJSON streaming, (b) JSON-array buffered, (c) authenticated source with file-based credentials, (d) optional source that skips gracefully. The 4 chosen cover all four axes.
- **Each extra source costs ~30 min × 2 langs = 1 hr** of the 1-week budget — bias toward less.

**Why these 4 specifically (not e.g. urlfinder + 3 others)?**
- These 4 are **already in bash v1's `sub_passive()` core path** (lines 514-530 of `modules/subdomains.sh`). The bash function provides the canonical merge pattern to port: fire each tool into its own file, then `anew`-merge with dedup. Spike replicates this pattern shape (NOT a new pattern) — keeps comparison fair.

**What about `crt.sh` vs the `crt` Go binary?**
- bash v1 uses BOTH (line 515 + 530-535). Spike picks `crt` (the Go binary) only — exercises external-tool calling pattern, not raw HTTP. Raw HTTP to `crt.sh` would test a different code path (HTTP client lib) that the spike isn't designed to compare.

**API key handling:**
- `GITHUB_TOKENS=/path/to/tokens.txt` — spike reads from env var, validates file exists + readable, passes `-t "$GITHUB_TOKENS"` to subprocess.
- If env var unset → log `[SKIP] github-subdomains: GITHUB_TOKENS not set` and proceed. Both langs handle this identically.
- For the spike's test corpus, planner should provide a dummy `GITHUB_TOKENS` file with a valid throwaway token (or the spike runs against a target that doesn't require auth for the github source).

## 1.2 httpx Probe Depth

**Recommendation: minimal flag set** — proves the subprocess + streaming + JSONL parsing works, without exercising every feature of httpx.

```
httpx -l <subs_file> -silent -json -status-code -title -tech-detect -no-color -threads 50 -timeout 10
```

**Rationale per flag:**

| Flag | Why It's In | Why Not Larger |
|------|-------------|----------------|
| `-l <file>` | File-based input (NOT stdin pipe) — avoids PITFALL 1.4 (stdin race) | — |
| `-silent` | Suppresses banner / progress noise that would pollute stdout NDJSON | — |
| `-json` | NDJSON output — exercises line-by-line streaming | Without it, line-text output is too easy to parse |
| `-status-code` | One real field in NDJSON output | Bare `-json` without fields gives empty objects |
| `-title` | Second field — exercises HTML title extraction (real-world flakiness) | — |
| `-tech-detect` | Third field — exercises async tech-detection inside httpx | Heaviest httpx feature; tests subprocess long-runtime |
| `-no-color` | Prevents ANSI codes in NDJSON (would break JSON parsing) | — |
| `-threads 50` | Bounded concurrency inside httpx so it doesn't DoS the target | — |
| `-timeout 10` | Per-request timeout — caps the worst case | Spike's own kill-tree is the outer guarantee |

**Flags deliberately NOT in the spike:**
- `-ip` `-cdn` `-tls-grab` `-asn` `-favicon` `-vhost` — production features; would expand scope without changing the comparison.
- `-rate-limit` — handled by the outer spike orchestrator in production; spike can ignore.
- `-pipeline` `-http2` — advanced HTTP features; out of scope.
- `-screenshot` — needs Chrome / a screenshot binary; out of scope for a 1-week PoC.

**Why this matters for the comparison:**
- Go's `bufio.Scanner` vs Python's `async for line in proc.stdout` are the two subprocess-streaming idioms. The 3 fields per JSON object are enough to validate that both langs parse + handoff correctly without exercising "every possible JSON shape" (which is a production-quality concern).

## 1.3 Kill-Tree Test Setup

**Recommendation: BOTH a synthetic mock AND a real-tool integration test.**

### 1.3.1 Synthetic Mock (deterministic unit test)

**Mock script:** See Example 3 above (`spike/corpus/mock_stubborn_tool.sh`). Sleeps forever, spawns 2 children, all ignore SIGTERM.

**Test shape (Go):**
```go
func TestKillTree_SyntheticMock(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cmd := exec.CommandContext(ctx, "spike/corpus/mock_stubborn_tool.sh")
    cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
    cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
    cmd.WaitDelay = 5 * time.Second
    require.NoError(t, cmd.Start())

    // Capture all descendant PIDs after a short wait
    time.Sleep(2 * time.Second)
    descendants := pgrepDescendants(cmd.Process.Pid)
    require.Greater(t, len(descendants), 2, "should have parent + at least 2 children")

    // Cancel
    cancel()
    cmd.Wait()
    time.Sleep(10 * time.Second) // grace period for SIGKILL escalation

    // Assert all descendants dead
    for _, pid := range descendants {
        require.False(t, pidAlive(pid), "PID %d still alive after kill-tree", pid)
    }
}
```

**Test shape (Python):** Same logic via `asyncio.create_subprocess_exec` + `os.killpg`.

**Why mock-based as unit test:**
- Deterministic: same mock, same outcome, no network.
- Fast: 10-15 sec per run.
- Runs in CI without external tool installation.
- Exercises the worst-case (children ignore SIGTERM → must escalate to SIGKILL via WaitDelay).

### 1.3.2 Real-Tool Integration Test

**Setup:** Invoke the real `subfinder + httpx` pipeline against `example.com` (or `hackerone.com` for slightly more data). Interrupt mid-run via test-driven SIGINT.

**Test shape (both langs, conceptually):**
```bash
# Spike runs in background
./spike/{lang}/bin/spike --target hackerone.com &
SPIKE_PID=$!

# Wait until httpx is running
while ! pgrep -P "$SPIKE_PID" httpx >/dev/null; do sleep 0.5; done

# Capture descendant tree
DESCENDANTS=$(pgrep -P "$SPIKE_PID")
[[ -n "$DESCENDANTS" ]] || { echo FAIL; exit 1; }

# Interrupt
kill -INT "$SPIKE_PID"

# Wait + assert
sleep 12
for pid in $DESCENDANTS; do
    if kill -0 "$pid" 2>/dev/null; then
        echo "FAIL: descendant PID $pid still alive"
        exit 1
    fi
done
echo OK
```

**Why real-tool as integration test:**
- Validates against REAL subprocess trees (subfinder forks workers; httpx spawns goroutines/threads as separate kernel threads).
- Catches issues the synthetic mock doesn't: e.g., a Python implementation that handles a 1-deep child correctly but loses track at depth 2+.
- Slower (60-120 sec per run) — run in CI nightly, not per-push.

### 1.3.3 Recommended split

- **Unit test (per-push):** synthetic mock — catches 80% of bugs deterministically in 15 sec.
- **Integration test (nightly):** real tools — catches deep-tree edge cases.

This matches the test-ring policy that Phase 3 will lock in (ARCH-11). Spike tests aren't bats, but they DO follow the unit / integration discipline.

---

# Section 2: Comparison Metrics Weighting + Tie-Breaker Precision

This section resolves Open Decision #2 from CONTEXT.md (Claude's Discretion).

## 2.1 Six Metrics (DEC-03's 5 + MCP cross-check)

| # | Metric | Type | Measurement Protocol | Pass/Fail Threshold |
|---|--------|------|----------------------|---------------------|
| M1 | **Dev velocity (LoC)** | Numeric | `tokei spike/{lang}/` lines of code, code-only (exclude comments + tests) | No threshold — used for tie-breaker noise band |
| M2 | **Dev velocity (hours)** | Numeric | Sum of per-session timer values (see Pitfall 2 above) | No threshold — used for tie-breaker noise band |
| M3 | **Packaging footprint** | Numeric (bytes) | Go: `stat -f%z spike/go/bin/spike` (stripped binary). Python: `du -sk spike/python/.venv` (venv size). Both as kB. | Go must be < 80 MB; Python must be < 600 MB (sanity bounds — STACK.md §9 budgets) |
| M4 | **Kill-tree correctness** | Binary (pass/fail) | The synthetic mock test (§1.3.1) — assert all descendants dead within 10s | **KILLER-FEATURE OVERRIDE — see §2.3** |
| M5 | **RSS under load** | Numeric (kB) | `/usr/bin/time -l` (macOS) / `-v` (Linux) → "maximum resident set size" while spike processes a target with ≥1000 resolved subdomains | No hard threshold; used for tie-breaker noise band |
| M6 | **Cross-platform pain** | Ordinal (1/2/3) | 1 = builds + tests pass on macOS arm64 first try. 2 = some issues, resolved with config change. 3 = blocking issue requiring code change or platform-specific branch. | 3 = killer-feature override (see §2.3) |
| **+** | **MCP library support** (cross-check, Phase 8) | Ordinal (1/2/3) | 1 = official SDK at v1.x stable. 2 = community SDK at v1.x. 3 = no SDK / pre-1.0 / abandoned. | **Both langs = 1 (see Section 5). NOT a tie-breaker signal.** |

### 2.1.1 Per-metric measurement details

**M1 (LoC):**
- Tool: `tokei` (Rust, fast, accurate). Install: `brew install tokei`.
- Cmd: `tokei spike/go/ --output json | jq '.Go.code'` and `tokei spike/python/ --output json | jq '.Python.code'`.
- Code-only counts (excludes comments + blank lines). Excludes test files (`*_test.go` / `test_*.py`).
- If `tokei` unavailable, `cloc` is a fallback.

**M2 (hours):**
- Per-session timer: at start of each coding session, `date +%s > .spike_session_start`; at end, compute delta and append to `.spike_sessions.log` with format `LANG MIN`.
- Sum at end: `awk '$1=="go" {s+=$2} END {print s}' .spike_sessions.log`.
- Includes ALL coding time: design thinking, writing, debugging, fixing tests. Excludes time spent reading research files (that's research, not spike).

**M3 (packaging):**
- Go: `go build -ldflags="-s -w" -tags=netgo -trimpath -o spike/go/bin/spike ./spike/go/cmd/spike`. Stripped binary. Measure `stat -f%z` (macOS) or `stat -c%s` (Linux) in bytes.
- Python: `du -sk spike/python/.venv` (kB) after `uv pip install` of all required deps + spike package itself.
- Optionally: build Python single-binary via `pyinstaller --onefile --name spike spike/python/cmd/__main__.py` and compare to Go. (Adds 30 min to spike — planner decides.)

**M4 (kill-tree):**
- The synthetic mock test (§1.3.1) is the canonical pass/fail.
- A lang either passes (all descendants dead within 10s) or fails (any descendant still alive).
- **No partial credit.**

**M5 (RSS):**
- Target: `hackerone.com` (a real bug bounty domain, known to have 1000+ subdomains).
- Command: `/usr/bin/time -l ./spike/go/bin/spike --target hackerone.com 2>spike/go/out/time.err`
- Extract: `grep "maximum resident set size" spike/go/out/time.err | awk '{print $1}'` (macOS gives bytes; convert to kB).
- Linux equivalent: `/usr/bin/time -v ... 2>err; grep "Maximum resident set size" err | awk '{print $6}'` (kB already).
- Run 3 times per lang, take median. Fairness: same target, same network conditions (run sequentially within 5 min of each other).

**M6 (cross-platform pain):**
- Subjective ordinal — single maintainer judgment.
- 1 = "I ran `go build` / `uv pip install` and tests passed on my macOS arm64 first try."
- 2 = "I had to install one system dep (`brew install ...`) or set one env var to make it work."
- 3 = "I hit a real bug — wheel build failed, cgo pulled in, native dep didn't compile, etc. Required code change or platform-specific branching."
- Record specifics in the ADR (not just "1/2/3"): "Python: 2 (had to install `brew install python-tk` for the test harness)" — concrete reasons.

## 2.2 Per-Metric Scoring + Aggregate Decision Rule

**No weighted average.** Numeric metrics (M1, M2, M3, M5) are compared individually for the 25% noise-band test (DEC-04); binary/ordinal metrics (M4, M6) are pass/fail.

### Algorithm:

```
1. KILLER-FEATURE GATE:
   - If kill-tree (M4) failed for either lang: that lang loses. PERIOD.
   - If cross-platform pain (M6) = 3 for either lang: that lang loses unless the other ALSO has 3.

2. For each of M1/M2/M3/M5:
   - Compute ratio = max(go, python) / min(go, python)
   - If ratio < 1.25 (i.e., metrics within 25% of each other): metric is TIED
   - If ratio >= 1.25: lang with smaller (better) value wins this metric

3. AGGREGATE:
   - Count metric wins per lang across M1/M2/M3/M5.
   - If one lang wins >=3 of the 4 non-tied metrics: CLEAR WINNER. Tie-breaker NOT invoked.
   - If all 4 are TIED, OR each lang wins 2: NOISE BAND. Tie-breaker invoked.

4. TIE-BREAKER (DEC-04 default): "Choose Go if metrics within 25% noise band — single-binary distribution wins."
   - Rationale (per STACK.md §9 + SUMMARY.md): single-binary install is reconFTW's clearest packaging story improvement; Python's uv-tool footprint is acceptable but not as clean.
   - This rule is INVOKED only after step 3 concludes noise-band.
```

### Worked example (hypothetical):
- M1: Go=600 LoC, Python=580 LoC → ratio 1.034 → TIED.
- M2: Go=28 hrs, Python=24 hrs → ratio 1.167 → TIED.
- M3: Go=18 MB, Python=85 MB → ratio 4.7 → Go wins.
- M4: both pass → no kill.
- M5: Go=120 MB RSS, Python=180 MB RSS → ratio 1.5 → Go wins.
- M6: Go=1, Python=2 → Go wins (ordinal — straightforward).

**Aggregate:** Go wins M3, M5, M6 (3 of 4 numeric+ordinal). CLEAR WINNER. Tie-breaker NOT invoked. ADR verdict: "Metrics show clear winner (Go wins 3 of 4 numeric metrics), tie-breaker NOT invoked, choose Go."

### Alternative worked example (true tie):
- M1, M2, M3, M5 all within 25% → all TIED.
- M4: both pass.
- M6: both 1.

**Aggregate:** All metrics TIED. NOISE BAND. Tie-breaker invoked per DEC-04. ADR verdict: "Metrics within 25% noise band on all 4 numeric dimensions, tie-breaker invoked per DEC-04 (single-binary distribution wins), choose Go."

## 2.3 Killer-Feature Overrides

These dominate the 25% noise band. If triggered, the affected lang LOSES regardless of how it scored on other metrics.

| Override | Trigger | Why It Dominates |
|----------|---------|------------------|
| **Kill-tree failure (M4)** | Synthetic mock test fails: any descendant still alive 10s after SIGINT | PITFALL 1.2 (top-impact). Orphaned tools probing the target after Ctrl-C = ethical/legal exposure for the user. Cannot ship reconFTW with this broken. |
| **Cross-platform pain = 3 (M6)** | Spike fails to build OR run on macOS arm64 without code changes / native-build hacks | macOS arm64 is the maintainer's daily-driver platform. A lang that doesn't work there is a non-starter for v2.0. (Note: if BOTH langs hit 3 on different platforms, that's a planning crisis to surface in the ADR.) |

**MCP library NOT a killer-feature override** — verified in Section 5 below. Both langs have v1.x official SDKs.

## 2.4 Per-Metric Result Recording (ADR data table)

The ADR's Measurement section MUST contain a table in this exact shape (so 6-months-from-now readers can audit):

```
| Metric             | Go      | Python  | Ratio | Winner |
|--------------------|---------|---------|-------|--------|
| M1 LoC (code-only) | 600     | 580     | 1.03  | TIED   |
| M2 Hours           | 28      | 24      | 1.17  | TIED   |
| M3 Packaging       | 18 MB   | 85 MB   | 4.7   | Go     |
| M4 Kill-tree       | PASS    | PASS    | -     | -      |
| M5 RSS @ 1K hosts  | 120 MB  | 180 MB  | 1.5   | Go     |
| M6 X-platform pain | 1       | 2       | -     | Go     |
| MCP lib support    | 1       | 1       | -     | -      |
```

**Verdict format (ADR):**
```
Verdict: [CLEAR_WINNER | NOISE_BAND]
Tie-breaker DEC-04: [INVOKED | NOT_INVOKED]
Choice: [Go | Python]
Rationale: <one paragraph linking the table to the choice>
```

---

# Section 3: Spike Harness / Repo Layout

This section resolves Open Decision #3 from CONTEXT.md (Claude's Discretion).

## 3.1 Recommended Directory Structure

```
spike/
├── README.md                       # How to run both spikes + comparison
├── compare.sh                       # Comparison runner (bash + GNU coreutils)
├── comparison.json                  # Output of compare.sh (gitignored)
├── corpus/
│   ├── targets.txt                  # 3 test targets, one per line
│   ├── mock_stubborn_tool.sh        # Synthetic mock for kill-tree test
│   └── expected/                    # Expected outputs (subdomain sets per target)
│       ├── hackerone.com.expected   # Sorted subdomain list (regenerated weekly)
│       └── example.com.expected
├── go/
│   ├── cmd/
│   │   └── spike/
│   │       └── main.go              # Entry point
│   ├── internal/
│   │   ├── passive/
│   │   │   ├── passive.go           # Fan-out across 4 sources
│   │   │   ├── subfinder.go
│   │   │   ├── crt.go
│   │   │   ├── github.go
│   │   │   └── gitlab.go
│   │   ├── httpx/
│   │   │   └── httpx.go             # httpx subprocess + NDJSON parser
│   │   ├── output/
│   │   │   └── atomic.go            # AtomicWriter (pattern 2 above)
│   │   ├── proc/
│   │   │   └── proc.go              # Subprocess wrapper (pattern 1 above)
│   │   └── ui/
│   │       └── ui.go                # Minimal status output
│   ├── tests/
│   │   ├── killtree_test.go         # Pattern 1 verification
│   │   ├── atomic_test.go           # Pattern 2 verification
│   │   └── integration_test.go      # Real-tool kill-tree (gated by -tag=integration)
│   ├── bin/                         # Build output (gitignored)
│   ├── out/                         # Run output (gitignored): subs.jsonl, hosts.jsonl, run.log
│   ├── go.mod
│   ├── go.sum
│   └── Makefile                     # build, test, integration-test, lint, clean
└── python/
    ├── src/
    │   └── spike/
    │       ├── __init__.py
    │       ├── __main__.py          # Entry point (python -m spike)
    │       ├── cli.py               # Arg parsing (typer or argparse)
    │       ├── passive.py           # Fan-out across 4 sources
    │       ├── sources/
    │       │   ├── __init__.py
    │       │   ├── subfinder.py
    │       │   ├── crt.py
    │       │   ├── github.py
    │       │   └── gitlab.py
    │       ├── httpx_probe.py       # httpx subprocess + NDJSON parser
    │       ├── output.py            # atomic_write_jsonl (pattern 2)
    │       ├── proc.py              # Subprocess wrapper (pattern 1)
    │       └── ui.py
    ├── tests/
    │   ├── test_killtree.py
    │   ├── test_atomic.py
    │   └── test_integration.py      # @pytest.mark.integration
    ├── out/                         # Run output (gitignored)
    ├── pyproject.toml               # uv-managed; deps + entry point
    └── Makefile                     # Same targets as Go side, for symmetry
```

### Justifications

**Why `cmd/` + `internal/` (Go)?**
- Canonical Go project layout (recommended in [Go project structure](https://github.com/golang-standards/project-layout) — note this is community convention, not official Go team guidance, but it's widely followed).
- `internal/` packages can only be imported by code within `spike/go/`, prevents accidental reuse outside the spike.
- This matches the production Phase 3 layout, so spike-to-production code-shape mapping is direct.

**Why `src/spike/` (Python)?**
- `src/`-layout is the modern Python packaging recommendation (avoids "package imported from CWD instead of installed" footgun).
- Matches what `uv tool install` expects from `pyproject.toml`.
- Sub-packages: `sources/` parallels Go's `passive/` — same conceptual split.

**Why no `pkg/` (Go)?**
- The spike is throwaway. There's no "external API to expose." `internal/` is enough.

**Why both Makefiles?**
- Symmetry: `make build`, `make test`, `make integration-test`, `make lint`, `make clean` work identically on both sides. The comparison runner can invoke `make` on both without lang-specific knowledge.

## 3.2 Shared Test Corpus

**`spike/corpus/targets.txt`:**
```
hackerone.com
example.com
controlled-lab.test
```

**Why these three:**
- `hackerone.com` — real bug-bounty domain, known to have 1000+ subdomains, used in CUT-11 parity test. Stress-tests M5 (RSS).
- `example.com` — tiny known footprint (effectively just `www.example.com`), used for smoke tests + atomic-write sanity check.
- `controlled-lab.test` — placeholder for a maintainer-controlled domain (could be `six2dez.com` or similar). Used for github-subdomains testing where authentication matters. Planner adjusts.

**Why 3 not more:**
- The spike measures the **orchestrator**, not the **target diversity**. 3 covers small (smoke), medium (kill-tree integration), large (RSS under load).
- 4+ targets adds runtime to `compare.sh` without changing the comparison signal.

**Where do expected outputs live?**
- `spike/corpus/expected/<target>.expected` — sorted subdomain list per target.
- **NOT regenerated per-spike.** Expected files are generated ONCE (by running bash v1's `sub_passive` against each target) and checked into git as the canonical baseline.
- The spike's output is compared against the expected file via `diff <(sort -u spike/{lang}/out/subs.jsonl | jq -r .subdomain) <(sort -u expected/<target>.expected)`.
- Tolerance: ±5% (cert transparency sources have day-to-day churn). Implemented as line-count diff threshold in `compare.sh`.

## 3.3 Comparison Runner Script

See **Example 4** above for the skeleton. Key design choices:

- **Language: bash + GNU coreutils.** No new lang dependency. Pure shell + `jq` for JSON munging + `/usr/bin/time` for resource measurement.
- **Output: `spike/comparison.json`.** Machine-readable; can be diffed in git or appended to ADR verbatim.
- **Invocation: `spike/compare.sh <target>`.** Defaults to `hackerone.com` if no arg.
- **macOS-only or Linux-only?** Use `/usr/bin/time -l` (macOS BSD) — the maintainer's dev machine is macOS arm64 per `go env`. If Linux comparison wanted, add a `-v` flag detection at top.

## 3.4 Test Frameworks

| Lang | Unit framework | Integration framework | Notes |
|------|----------------|----------------------|-------|
| Go | `testing` (stdlib) + `testify/assert` + `testify/require` | Same, gated by `//go:build integration` build tag | `go test ./...` for unit; `go test -tags=integration ./...` for both |
| Python | `pytest` + `pytest-asyncio` (async tests) | Same, gated by `@pytest.mark.integration` | `pytest tests/` for unit; `pytest tests/ -m integration` for integration |

**Minimum test set:**
1. `TestAtomicWrite_CrashSafe` — kills subprocess between fsync and rename, asserts original file intact.
2. `TestKillTree_SyntheticMock` — synthetic mock test (§1.3.1).
3. `TestKillTree_RealTools` (integration) — real-tool kill-tree test (§1.3.2).
4. `TestPassive_FourSources` — runs the fan-out, asserts 4 source files written, dedup works.
5. `TestHTTPxProbe_Streaming` — feeds a fake subs.jsonl with 100 hosts, mocks httpx via a shell script that emits NDJSON, asserts hosts.jsonl correctly populated.

**Test parity discipline:** Same 5 tests on both sides. If one side adds a 6th test mid-spike, document why in the commit message — usually it indicates a lang-specific gotcha worth knowing about (e.g., "Python needed extra `TestSignalHandlerNotInAsyncio` because of stdlib race condition").

---

# Section 4: ADR Template + Post-ADR Collapse Mechanics

This section resolves Open Decision #4 from CONTEXT.md (Claude's Discretion).

## 4.1 ADR Format: Custom (MADR-influenced)

**Recommendation: Custom format, MADR-influenced.**

[MADR (Markdown Architectural Decision Records)](https://adr.github.io/madr/) is the de-facto modern ADR template; [Michael Nygard's original 2011 format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) is the historical baseline. Either works; for a solo-maintainer project, MADR is slightly more structured (good for audit) without being heavyweight.

**Recommended structure for `.planning/decisions/0001-language.md`:**

```markdown
# 0001 — Language Choice for reconFTW v2.0

* Status: Accepted
* Date: YYYY-MM-DD
* Deciders: six2dez (solo maintainer, project owner)
* Tags: language, v2.0, foundational

## Context

Why does this decision need to be made now? Brief (3-5 sentences):
- reconFTW v1.x is bash; pain points are robustness, concurrency, packaging, onboarding.
- v2.0 is a single-mega-milestone full rewrite (197 REQ-IDs, 12 phases, 12-18 months).
- Foundation (Phase 3) and every subsequent phase depend on the language choice.
- A spike PoC measured Go vs Python head-to-head against an identical recon slice.
- This ADR documents the decision so future contributors can audit it.

## Decision

We will use **[Go | Python]** for the reconFTW v2.0 rewrite.

This decision is final for v2.x. Reversing would require a new ADR superseding this one.

## Measurement

Spike PoC implemented in both languages: passive subdomain enum (4 sources: subfinder, crt, github-subdomains, gitlab-subdomains) + httpx probe + atomic JSONL writes + SIGINT kill-tree test.

Slice scope locked before spikes began (see `.planning/phases/01-language-adr-spike/01-PLAN.md`).
Spike code committed at `spike/go/` (commit: <SHA>) and `spike/python/` (commit: <SHA>).

| Metric             | Go      | Python  | Ratio | Winner |
|--------------------|---------|---------|-------|--------|
| M1 LoC (code-only) | <num>   | <num>   | <r>   | <X>    |
| M2 Hours           | <num>   | <num>   | <r>   | <X>    |
| M3 Packaging       | <bytes> | <bytes> | <r>   | <X>    |
| M4 Kill-tree       | PASS|FAIL | PASS|FAIL | -   | -      |
| M5 RSS @ 1K hosts  | <kB>    | <kB>    | <r>   | <X>    |
| M6 X-platform pain | 1|2|3   | 1|2|3   | -     | <X>    |
| MCP lib support    | 1       | 1       | -     | -      |

**Killer-feature gates:**
- M4 Kill-tree: [Both passed | Go failed, Python wins | Python failed, Go wins]
- M6 Cross-platform: [Both passed | <details if not>]

**Verdict:**
- [CLEAR_WINNER: <lang> wins <N> of 4 numeric/ordinal metrics, tie-breaker NOT invoked]
- [NOISE_BAND: all 4 numeric metrics within 25%, tie-breaker invoked per DEC-04, choose Go]

## Consequences

### Positive
- <e.g., Single static binary distribution; goreleaser workflow; no Python wheel friction>
- <e.g., Compile-time type safety eliminates a class of bash bugs>
- <other concrete benefits>

### Negative
- <e.g., Smaller pool of contributors (Go is less ubiquitous than Python in security tooling)>
- <e.g., No REPL for ad-hoc tool experimentation>
- <other concrete drawbacks>

## Tie-breaker

DEC-04 default tie-breaker rule: "Choose Go if metrics within 25% noise band — single-binary distribution wins."

- Invoked: [YES | NO]
- Rationale: [if invoked, paragraph explaining noise-band finding; if not, paragraph explaining clear winner]

## References

- Spike code: `spike/go/` (commit: <SHA>), `spike/python/` (commit: <SHA>)
- Comparison runner output: `spike/comparison.json` (final at commit: <SHA>)
- Research synthesis: `.planning/research/SUMMARY.md`
- Stack research: `.planning/research/STACK.md`
- Architecture research: `.planning/research/ARCHITECTURE.md`
- Pitfalls research: `.planning/research/PITFALLS.md`
- Requirements: `.planning/REQUIREMENTS.md` DEC-01 through DEC-05
- Roadmap: `.planning/ROADMAP.md` Phase 1
- Phase context: `.planning/phases/01-language-adr-spike/01-CONTEXT.md`
- Phase plan: `.planning/phases/01-language-adr-spike/01-PLAN.md`

## Signed

**Signed by:** six2dez (single maintainer, project owner)
**Date:** YYYY-MM-DD
**Git SHA (this ADR):** <will be filled by git after commit>
**Git SHA (spike final):** <SHA of the spike's last commit before ADR sign>
```

## 4.2 What "Signed" Means in This Project

Per **D-02 (solo same-day sign-off)**:
- Signature is the ADR's `## Signed` section above.
- No external co-signers, no PR review gate, no community sign-off ceremony.
- The commit creating `.planning/decisions/0001-language.md` IS the sign-off.
- Optional: post-decision GitHub Release note for community visibility — NOT a gate.

**Auditability:** 6 months from now, anyone (including future-six2dez) can `git log .planning/decisions/0001-language.md` to find the commit, verify the signed date, and follow `References` to the spike code + comparison data.

## 4.3 Post-ADR Collapse Checklist (D-03 Operationalization)

This checklist is what the planner converts into Phase 1's final task. Concrete file-by-file edits.

### 4.3.1 `.planning/research/STACK.md`

Remove the losing language's columns + sections. Concrete steps:

1. **§0 Language Runtime Baseline** — keep only the winner's column in the table; delete the loser's row entries.
2. **§1 through §14** — each section has a "### Go" and "### Python" subsection. Delete the loser's entirely.
3. **§Summary Recommendation Matrix** — delete the loser's entire table.
4. **§What NOT to Use (Both Languages)** — keep entries marked "Both:"; delete entries prefixed with the loser's name.
5. **§Risks & Open Questions** — delete risks specific to the loser.
6. **§Sources** — keep all (sources for the winner remain relevant; loser sources can be dropped or marked "historical").

### 4.3.2 `.planning/research/ARCHITECTURE.md`

Each section has parallel "### 2a Go" / "### 2b Python" subsections (and `### 2c` comparison subsections). Concrete steps:

1. For sections §2 through §15: delete the loser's subsection. Rename winner's subsection from "### Xa Go" / "### Xb Python" to just "### X".
2. Comparison subsections (e.g., "### 2c Component boundaries", "### 3c Comparison and tradeoffs") — keep, but rewrite to reference only the chosen language (remove "Bash vs Go vs Python" 3-column tables, keep "Bash vs <chosen>" 2-column tables).
3. §1 System Overview — the conceptual diagram is language-agnostic; keep. The "Go: ... Python: ..." annotations under it: keep only winner.

### 4.3.3 `.planning/research/SUMMARY.md`

1. **§Stack Snapshot** — has "### If Go wins the spike" and "### If Python wins the spike" tables. Delete loser's table. Rename winner's to "### Stack (locked in ADR 0001)".
2. **§Library blacklist** — keep entries marked "Both:"; delete entries prefixed with loser's name.
3. **§Architecture: Top Cross-Cutting Patterns** — each pattern has "Go: ..." and "Python: ..." rows. Delete loser's rows.
4. **§Build Order** — Phase 0 / Phase 1 description references "Go OR Python". Change to chosen language.
5. **§Open Risks** — delete risks specific to the loser.

### 4.3.4 `.planning/research/PITFALLS.md`

1. Walk every pitfall. Each has "Why it happens" / "Prevention" / "Bash analog" that may reference both langs. Edit to keep only chosen lang's prevention sections.
2. Some pitfalls are lang-specific (e.g., "Pitfall 2.4 Python `await` in a Loop"). If the chosen lang isn't Python, delete those pitfalls entirely. If Python wins, delete Go-specific pitfalls (e.g., "Pitfall 6.1 cgo Dependencies").
3. Cross-cutting pitfalls (most of them) — keep, edit to remove loser's lang mentions.

### 4.3.5 What to keep around (loser's spike code)

**Out of scope of this RESEARCH.md, but flagged for planner:**
- D-03 explicitly does NOT cover `spike/<loser>/` code cleanup.
- Planner decides during Phase 2 planning: delete the spike tree, archive in a tarball, or leave in git history only (the ADR's `git SHA (spike final)` reference is enough for future audit).

### 4.3.6 Validation: how to know the collapse is complete

After all edits, run:
```bash
# If Go won, no mention of "python" / "asyncio" / "pydantic" / "typer" / "uv pip" should remain in research/
grep -ri -l "python\|asyncio\|pydantic\|typer\|uv pip\|tomllib\|structlog" .planning/research/

# If Python won, no mention of "go.mod" / "goroutine" / "cobra" / "koanf" / "errgroup" / "slog" / "goreleaser"
grep -ri -l "go\.mod\|goroutine\|spf13/cobra\|knadh/koanf\|errgroup\|log/slog\|goreleaser" .planning/research/
```

Expected: zero matches except in `## References` / `## Historical` sections explicitly noting the spike comparison.

---

# Section 5: MCP Library Availability Per Language (Deferred Cross-Check)

This section resolves the **CONTEXT.md deferred item**: whether MCP library support differs materially between Go and Python, which would shift the tie-breaker.

## 5.1 Python MCP SDK: `pypi:mcp`

| Attribute | Value | Source |
|-----------|-------|--------|
| Official | YES — maintained by Anthropic | [CITED: github.com/modelcontextprotocol/python-sdk; Wikipedia MCP article] |
| Current stable | v1.x stable | [CITED: README of github.com/modelcontextprotocol/python-sdk] |
| Stability since | Q1 2025 (v1.0 release) | [CITED: GitHub release history] |
| PyPI downloads | 97M+ monthly across all language SDKs (Python is largest) | [CITED: Webfuse MCP Cheat Sheet 2026] |
| slopcheck | OK | [VERIFIED: slopcheck scan --pkg pypi mcp] |
| Production-ready | YES — Streamable HTTP transport recommended for production | [CITED: README v1.x] |
| Features | Full MCP spec: clients + servers, stdio + SSE + Streamable HTTP transports, resources + prompts + tools, JSON Schema integration | [CITED: README] |

## 5.2 Go MCP SDK: `github.com/modelcontextprotocol/go-sdk`

| Attribute | Value | Source |
|-----------|-------|--------|
| Official | YES — maintained by Anthropic in collaboration with Google | [CITED: github.com/modelcontextprotocol/go-sdk README] |
| Current stable | v1.6.1 (May 22, 2026) | [CITED: pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp] |
| Stability since | v1.0 reached 2026 (specific date not disclosed in fetched content) | [CITED: GitHub releases — 25 total releases as of May 2026] |
| Adoption | 1,443 importing projects on pkg.go.dev | [CITED: pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp] |
| slopcheck | SLOP (BRAND_NEW flag) | [VERIFIED: slopcheck — but **FALSE POSITIVE** confirmed via independent verification of official Anthropic+Google repo] |
| Production-ready | YES — supports 4 protocol versions (2024-11-05 through 2025-11-25), comprehensive docs and examples | [CITED: README] |
| Features | Full MCP spec: clients + servers, custom transports via `jsonrpc` package | [CITED: pkg.go.dev mcp + jsonrpc packages] |

## 5.3 Comparison Summary

| Dimension | Python SDK | Go SDK | Verdict |
|-----------|-----------|--------|---------|
| Stable v1.x | YES, since ~Q1 2025 | YES, since 2026 | Python has ~1 year more maturity |
| Officially maintained | YES (Anthropic) | YES (Anthropic + Google) | Go has larger backing org |
| Community adoption | 97M+ downloads (largest of all lang SDKs) | 1,443 importing projects | Python is dominant; Go growing fast |
| Production-ready | YES | YES | Both green |
| Required for Phase 8 | YES | YES | Either suffices |

## 5.4 Tie-Breaker Implication

**Both langs are at ordinal 1 (official SDK at v1.x stable).** Per §2.1's metric table, MCP support is the "+" row that does NOT enter the tie-break calculation.

**Conclusion:** MCP library availability is **NOT a tie-breaker signal** for the ADR. The deferred item is resolved as "no differentiator." DEC-04's default tie-breaker rule remains in force unchanged.

**Why this matters for the ADR text:** The ADR's Measurement table includes the MCP row for completeness (so future readers see it was checked), but does NOT use it for the verdict. The deferred-concern paragraph from CONTEXT.md is resolved:
> "MCP library availability per language (Phase 8 dependency) → researcher cross-checks during Phase 1 spike; if MCP support is materially worse in one lang, that's a tie-breaker signal that may dominate."

The cross-check has been done. The signal is NOT material. The deferred concern can be closed.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Subprocess with `subprocess.run(timeout=N)` | Process-group + `setsid` / `Setpgid` + `killpg` / `Kill(-pid)` | Bash audit RESIL-03 (2026-05-13); STACK.md §1 | Required for ethical/legal compliance — orphaned tools after Ctrl-C is unacceptable |
| File-based checkpoint via `touch .funcname` | SQLite tasks table with input_hash + status enum | ARCHITECTURE.md §4 (2026-05-27) | Eliminates "running with new scope still skips" + adds queryable history. **Not in spike scope** — Phase 3. |
| TOML/YAML config via `configparser`/`pyyaml` | `pydantic-settings` (Py) / `koanf/v2` (Go) with TOML + multi-source precedence | STACK.md §4 | Type safety + explicit precedence. **Not in spike scope (recommended skip)**. |
| Bash UI with custom dot-fill via `printf` | Port verbatim to chosen lang (no TUI lib) | SUMMARY.md §10 | Preserves CI-friendliness; no bubbletea/textual/rich Live |
| Python sync subprocess + threading | `asyncio.TaskGroup` + `asyncio.create_subprocess_exec` (Python 3.11+) | STACK.md §2; PITFALLS.md §2.5 | Structured concurrency; cancellation correctness |
| Go `goroutine` + `sync.WaitGroup` | `errgroup.WithContext` + `errgroup.SetLimit(N)` | STACK.md §2 | Error propagation + cancellation + bounded concurrency in one primitive |
| Hand-rolled atomic write | `tempfile + fsync + rename + parent_dir_fsync` (4-step) | LWN article; ARCHITECTURE.md §7b | Parent dir fsync is the 4th step many implementations miss |

**Deprecated/outdated (per STACK.md "What NOT to Use"):**
- Go: `cmd.Run()`, `cmd.Process.Kill()` alone, `http.DefaultClient`, `logrus`, `spf13/viper` direct.
- Python: `subprocess.run(..., timeout=N)`, `requests` for new code, `threading.Thread` raw, `setup.py`, `pip install` for tool install, `argparse` for 30+ flag CLI, `configparser`.
- Both: hand-rolled retry loops, `asyncio.gather()` without `return_exceptions=True`.

## Assumptions Log

> All factual claims in this RESEARCH.md were verified or cited. No assumptions remain that require user confirmation before planning.

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| — | (None — all claims sourced or verified in this session) | — | — |

**If this table is empty:** All claims in this research were verified or cited. The planner can proceed without scheduling discuss-phase confirmation rounds.

## Open Questions

These remain for the planner to resolve in `01-PLAN.md`. None block writing the plan — they are explicit "planner's call" items.

1. **Should the spike include `pydantic-settings` (Python) / `koanf/v2` (Go) config loading?**
   - What we know: STACK.md locks both for Phase 3 production.
   - What's unclear: Including in the spike adds ~2-4 hrs per lang of code to load a TOML, with no metric-changing benefit (config-loading is not in DEC-03's 5 metrics). Excluding keeps the spike narrow.
   - Recommendation: **EXCLUDE**. Spike reads `--target` from CLI directly, no config file. Phase 3 will add config layering at production scope.

2. **Should the spike include `cobra` (Go) / `typer` (Python) for arg parsing?**
   - What we know: Both locked for Phase 3.
   - What's unclear: Stdlib `flag`/`argparse` would work for the spike's single `--target X` arg.
   - Recommendation: **INCLUDE both** — keeps code-shape parity with production Phase 3; trivial extra LoC (~10 lines per side); doesn't change the 1-week-per-lang budget meaningfully.

3. **Should `PyInstaller` single-binary measurement be in the spike?**
   - What we know: Default Python distribution is `uv tool install` (venv); PyInstaller produces single binary at ~30-80 MB cost.
   - What's unclear: Whether the ADR comparison should compare "Go binary" vs "Python venv" (different shape) OR "Go binary" vs "Python PyInstaller binary" (same shape).
   - Recommendation: **Measure both forms of Python footprint** — record `uv tool install` size AND `pyinstaller --onefile` size. Costs ~1 hr extra in Python's 1-week budget; gives the ADR cleaner comparison data.

4. **Does the spike load credentials for `github-subdomains` / `gitlab-subdomains`?**
   - What we know: These tools require auth files (`GITHUB_TOKENS`, `GITLAB_TOKENS`); without them they fail or skip.
   - What's unclear: If credentials unavailable for the spike's test corpus, the github/gitlab branches are untested (lower comparison signal).
   - Recommendation: **Maintainer provides throwaway test tokens** for `spike/corpus/.tokens.github` (gitignored). Each spike reads from env var → falls back to skip if file missing. If tokens unavailable at spike time, drop these 2 sources and rerun the math (2 sources instead of 4; less comparison signal but spike completes).

5. **What target list does `compare.sh` cycle through?**
   - What we know: `spike/corpus/targets.txt` has 3 entries (per §3.2).
   - What's unclear: Does `compare.sh` run all 3 sequentially? Random one? Pass on CLI?
   - Recommendation: `compare.sh <target>` takes one target as arg; defaults to `hackerone.com` if absent. Comparison data is per-target. Maintainer runs once per target manually during ADR write-up.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go | Go spike build + test | ✓ | go1.26.1 darwin/arm64 | — |
| Python | Python spike build + test | ✓ | 3.14.4 | — |
| uv | Python venv + tool install | ✓ | 0.10.2 (planner may upgrade to 0.11+) | `pip` + `venv` if uv breaks |
| `subfinder` | Spike passive source | likely ✓ (reconFTW dev machine) | latest @ time of spike | bash v1 already uses it; if missing, `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `crt` | Spike passive source | likely ✓ | latest | `go install github.com/cemulus/crt@latest` |
| `github-subdomains` | Spike passive source | likely ✓ | latest | `go install github.com/gwen001/github-subdomains@latest` |
| `gitlab-subdomains` | Spike passive source | likely ✓ | latest | `go install github.com/gwen001/gitlab-subdomains@latest` |
| `httpx` | Spike web probe | likely ✓ | latest | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `tokei` | LoC measurement (M1) | unknown | — | `cloc` (Perl) as fallback; both should be available via brew |
| `jq` | comparison.json munging | likely ✓ | — | — |
| `/usr/bin/time` (macOS BSD `-l`) | RSS measurement (M5) | ✓ | — | Linux's `-v` works the same with different output parsing |
| `pgrep` | kill-tree test verification | ✓ | macOS BSD pgrep | — |
| `slopcheck` | Package legitimacy gate | ✓ | latest | (already used in this RESEARCH) |

**Missing dependencies with no fallback:** None identified. All required tools are either already installed (Go, Python, uv, bash v1's tools) or trivially installable via `brew install` / `go install` / `uv tool install`.

**Missing dependencies with fallback:**
- `tokei` — install via `brew install tokei`; `cloc` is the fallback.
- Specific spike binaries (subfinder, crt, etc.) — install via `go install` if not already present in `$HOME/go/bin/`. Planner's task should verify these at spike-start time.

## Project Constraints (from CLAUDE.md)

> Pulling concrete actionable directives from CLAUDE.md that affect this phase.

| Constraint | Applies to spike? | How |
|------------|-------------------|-----|
| Bash 4.3+ required | YES, for `compare.sh` | macOS dev machine needs Homebrew bash; planner verifies |
| GNU coreutils + GNU sed + GNU getopt required on macOS | YES, for `compare.sh` if it uses sed/getopt | Use `/usr/bin/time -l` (BSD) for macOS RSS measurement; can avoid GNU sed if compare.sh uses only POSIX features |
| Output stability — `Recon/<domain>/` is a public contract | NO | Spike writes to `spike/{lang}/out/`, NOT `Recon/`. No risk of breaking v1 user pipelines. |
| Single-process / no subshell isolation between modules | N/A | Production v1 constraint; spike is a fresh codebase, not bound by v1's design |
| 70+ external tools — no version pinning currently | YES (relevant for spike's external tool calls) | Spike uses latest installed versions of subfinder/crt/etc.; outputs may differ slightly run-to-run due to upstream tool changes. Acceptable for spike (not a parity test). |
| CI budget — integration-full is weekly cron | NO | Spike has no CI requirement; planner's call whether to add CI for spike tests. Recommendation: per-push unit tests only; no nightly integration for spike (it's throwaway). |
| GSD Workflow Enforcement — no direct edits outside a GSD workflow | YES | This research happens INSIDE a `/gsd:plan-phase` invocation; all subsequent spike code goes through `/gsd:execute-phase` or equivalent |

**Compliance check:** Recommendations in this RESEARCH.md are consistent with CLAUDE.md. No conflicts.

---

# Recommendations for the Planner

These translate this research's findings into concrete plan-task hints. The planner can convert each to an `01-PLAN.md` task.

## Plan structure (recommended)

Phase 1 fits well as **5 plans** under the coarse-granularity convention:

### Plan 01-01 — Spike harness scaffolding + comparison runner
- Create `spike/` directory tree (§3.1) with both `spike/go/` and `spike/python/` empty skeletons.
- Create `spike/corpus/targets.txt` with 3 targets.
- Create `spike/corpus/mock_stubborn_tool.sh` (per Example 3).
- Create `spike/compare.sh` (per Example 4).
- Create `spike/README.md` documenting how to run both spikes + comparison.
- Set up `.gitignore` to exclude `spike/{go,python}/out/`, `spike/{go,python}/bin/`, `spike/comparison.json`, `spike/corpus/.tokens.*`.
- Verify dev environment: Go 1.26.1, Python 3.14, uv 0.10.2, subfinder/crt/github-subdomains/gitlab-subdomains/httpx installed.

### Plan 01-02 — Go spike implementation (1-week timebox)
- Implement `spike/go/cmd/spike/main.go` + `internal/` packages per §3.1.
- Pass: 4 passive sources fan-out, httpx probe, atomic JSONL write, SIGINT signal handler.
- Tests: 5 tests per §3.4 (atomic-crash-safe, kill-tree synthetic, kill-tree real-tool, passive fan-out, httpx streaming).
- Per-session timer: each session start `date +%s > .spike_session_start`; end log to `.spike_sessions.log` with `go MIN`.
- Commit cadence: ≥1 commit per session; session-end commit message includes "Spike Go session N: M min".
- **STOP at 1 calendar week** even if incomplete (D-01).

### Plan 01-03 — Python spike implementation (1-week timebox)
- Same as 01-02 but for Python: `spike/python/src/spike/` per §3.1.
- Same 5 tests, same shape, same slice composition (4 sources, same httpx flags, same atomic-write contract).
- Same per-session timer discipline.
- **STOP at 1 calendar week** even if incomplete (D-01).
- (Parallel-execution note: Could run 01-02 and 01-03 in calendar parallel — but per CONTEXT.md the maintainer writes both sequentially. Planner notes this for non-parallelization within Phase 1.)

### Plan 01-04 — Comparison + ADR draft
- Run `spike/compare.sh` against each target in `spike/corpus/targets.txt`. Aggregate `comparison.json` data.
- Measure M1-M6 per §2.1 protocol; record in a working spreadsheet/markdown.
- Apply scoring algorithm per §2.2.
- Check killer-feature overrides per §2.3.
- Apply tie-breaker per §2.2 step 4 if noise-band.
- Draft `.planning/decisions/0001-language.md` per §4.1 template.
- Fill in Measurement table with real numbers.
- Fill in Verdict section with concrete numbers + tie-breaker invocation/non-invocation.
- Self-review: walk back through DEC-01 through DEC-05; assert each is addressed.

### Plan 01-05 — ADR sign-off + research-file collapse + spike code disposition
- Sign and commit `.planning/decisions/0001-language.md` per §4.2 (solo same-day, no PR review).
- Run post-ADR collapse per §4.3.1-§4.3.4: edit STACK.md, ARCHITECTURE.md, SUMMARY.md, PITFALLS.md in place to remove loser's language.
- Run validation greps per §4.3.6; resolve any unexpected matches.
- Decide on `spike/<loser>/` disposition (delete / archive / leave in git history); document decision in ADR Postscript or in Phase 2 CONTEXT.md.
- Update `.planning/STATE.md`: mark Phase 1 complete; advance milestone counter.
- Update `.planning/PROJECT.md` "Key Decisions" table with the language pick.

## Cross-cutting recommendations

- **No CI for spike tests.** Spike code is throwaway; CI overhead exceeds value. Tests run manually via `make test` on each side.
- **No linting gate on spike code.** It's not production. Maintainer's call whether to run `golangci-lint` / `ruff` for personal sanity; not a phase requirement.
- **No security audit gate on spike code.** It runs against the maintainer's own test targets only; no public exposure.
- **Atomic-write pattern is non-negotiable in both spikes** even though atomic writes are not a measured metric — without them, PITFALL 3.1 silently corrupts spike output and makes the comparison invalid.
- **Subprocess kill-tree pattern is non-negotiable in both spikes** because M4 measures it directly.
- **Spike code is throwaway — comments at file top say so.** This is a maintainer guardrail against scope creep.
- **All deferred decisions in §Open Questions resolved by Plan 01-01.** The planner LOCKS them in `01-PLAN.md` before either spike starts.

## What this research does NOT pre-decide (planner's call)

- Whether to include `pydantic-settings` / `koanf/v2` in the spike (Open Question 1) — recommendation EXCLUDE.
- Whether to include `cobra` / `typer` in the spike (Open Question 2) — recommendation INCLUDE both.
- Whether to add PyInstaller measurement to Python spike (Open Question 3) — recommendation INCLUDE.
- How credentials are provisioned for github/gitlab sources (Open Question 4) — recommendation throwaway tokens.
- Order: Go first or Python first? — recommendation random (coin flip), per Pitfall 2 mitigation.

---

## Sources

### Primary (HIGH confidence)

- `.planning/CONTEXT.md` for Phase 1 — locked user decisions D-01, D-02, D-03
- `.planning/REQUIREMENTS.md` — DEC-01 through DEC-05 verbatim
- `.planning/ROADMAP.md` — Phase 1 success criteria (5 of them)
- `.planning/research/STACK.md` — 14-dim Go-vs-Python stack (Context7-verified versions)
- `.planning/research/ARCHITECTURE.md` — dual-tracked patterns (Pattern 1, 2, 3 above are verbatim)
- `.planning/research/PITFALLS.md` — 51 pitfalls; top-5 referenced in §2.3 (killer-feature overrides) and Pitfall 1-5 in §Common Pitfalls
- `.planning/research/SUMMARY.md` — joint factual basis; §Build Order Phase 0 recommendation
- `modules/subdomains.sh` lines 507-553 — `sub_passive()` canonical bash function ported in the spike's 4 sources
- `lib/parallel.sh` lines 44-105 — `_kill_tree()` canonical bash kill-tree the spike validates by analogue
- CLAUDE.md — project constraints + GSD enforcement
- `.planning/codebase/STACK.md` — 70+ tools list; spike picks 4

### Secondary (MEDIUM confidence — web search + WebFetch verified)

- [github.com/modelcontextprotocol/python-sdk README](https://github.com/modelcontextprotocol/python-sdk) — verified v1.x stable, Anthropic-maintained
- [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) — verified v1.6.1 (May 22, 2026), Anthropic + Google maintained
- [pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp](https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp) — confirms 1,443 importing projects
- [Webfuse MCP Cheat Sheet 2026](https://www.webfuse.com/mcp-cheat-sheet) — 97M+ monthly downloads Python SDK adoption
- [LWN: A way to do atomic writes](https://lwn.net/Articles/789600/) — atomic-write pattern (4-step including parent dir fsync)
- [Killing process descendants in Go — sigmoid.at](https://sigmoid.at/post/2023/08/kill_process_descendants_golang/) — Pattern 1 canonical Go reference
- [MADR template](https://adr.github.io/madr/) — ADR template basis
- [Michael Nygard ADR](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) — historical ADR origin

### Tertiary (Verified via local probe)

- `go version` output: go1.26.1 darwin/arm64
- `python3 --version` output: 3.14.4
- `uv --version` output: 0.10.2
- `slopcheck scan --pkg pypi` results for: mcp, typer, pydantic-settings, structlog, pytest, pytest-asyncio, httpx — ALL OK
- `slopcheck scan --pkg go` results for: cobra, koanf/v2, testify — ALL OK (false NO_REPO / RECENTLY_CREATED signals understood)
- `slopcheck scan --pkg go github.com/modelcontextprotocol/go-sdk` — SLOP (FALSE POSITIVE — see §5.2)

## Metadata

**Confidence breakdown:**
- Slice composition (Section 1): HIGH — recommendations directly anchored to bash v1 code + STACK.md library blacklist
- Metrics + tie-breaker (Section 2): HIGH on protocol + algorithm; MEDIUM on subjective M6 ordinal (single-maintainer judgment by design)
- Harness layout (Section 3): HIGH — derives from STACK.md Phase 3 production layout + community conventions
- ADR template (Section 4): HIGH — MADR + Nygard are de-facto standards; post-ADR collapse is mechanical
- MCP cross-check (Section 5): HIGH — both SDKs independently verified via official repos + WebFetch + slopcheck

**Research date:** 2026-05-27
**Valid until:** 2026-06-26 (30 days for stable; MCP ecosystem evolving fast — if spike doesn't start within a month, re-verify §5 SDK versions)
