# Phase 3: Foundation Kernel - Context

**Gathered:** 2026-05-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship the v2.0 Go kernel — the dependency core that every Phase 4-12 module port builds against. Concretely: typed error hierarchy, structured logger with type-level secret tagging + sink-level redaction, layered config loader (8-source precedence), atomic JSONL output tree (`workspaces/<target-id>/`), SQLite checkpoint store, bounded scheduler with `failure_policy` dispatch, tool registry with kill-tree-safe `LocalBackend`, `AppContext` wiring, cobra CLI binary with all 15 v2 subcommands surfaced (3 working / 12 stubbed) + v1 deprecated aliases, test mocks (`MockBackend` / `MockCheckpoint` / `MockOutputTree`), and the CI gate enforced from day 1.

**Scope (FOUND-01 .. FOUND-16 + XCUT-02, XCUT-04, XCUT-07, XCUT-09 — 20 REQ-IDs total):** Errors → Logger → Config → OutputTree → Checkpoint → Scheduler → RateLimiter → ToolRegistry → LocalBackend → Lint rule (raw subprocess ban) → Notifier interface + Slack/Telegram/Discord log-sink stubs → Task interface + Registry → UI (dot-fill port) → CLI binary wiring → Test mocks → CI pipeline. Plus cross-cutting: binary size budget (XCUT-02 — Go stripped <50MB), CI policy (XCUT-04 — race + lint + ≥75% branch coverage on lib), logging hygiene CI gate (XCUT-07 — sentinel-value test), observability (XCUT-09 — heartbeat cadence).

**What's NOT in this phase** (belongs elsewhere):
- Real Task implementations (subdomains/web/vulns/osint) — Phase 4-7
- `AxiomBackend` real implementation — Phase 4 (subdomains + Axiom)
- Migrator (`reconftw migrate`) implementation — Phase 11; Phase 3 only stubs the subcommand
- Installer (`reconftw install`) implementation — Phase 11; Phase 3 only stubs the subcommand
- MCP server (`reconftw mcp`) — Phase 8; Phase 3 only stubs the subcommand
- Monitor loop + Reporting + Real notification dispatchers — Phase 10
- TOML schema design (locked in ADR 0002 §2); Phase 3 implements the loader against the locked schema
- Output tree shape (locked in ADR 0002 §3); Phase 3 implements `OutputTree` + `AtomicWriter` per the spec
- Interface signatures (locked in ADR 0002 §5 — BINDING); Phase 3 implements them
- Error class hierarchy (locked in ADR 0002 §6 — BINDING); Phase 3 implements it
- Compat symlink writer (locked in ADR 0002 §4); Phase 3 implements the writer skeleton, real symlink farm lifecycle ties in Phase 12 cutover

</domain>

<decisions>
## Implementation Decisions

### CLI Subcommand Stub Scope

- **D-01:** **All 15 v2 subcommands surfaced in Phase 3 binary.** Every subcommand listed in ADR 0002 §8.1 (`recon`, `all`, `passive`, `subs`, `web`, `vulns`, `osint`, `zen`, `deep`, `monitor`, `report`, `mcp`, `migrate`, `install`, `health-check`) is registered on `rootCmd` and visible in `reconftw --help` from day 1 of Phase 3 binary. Their descriptions match ADR §8.1. Phase 4-12 implementers swap in real `RunE` handlers; the surface contract is locked here. Rationale: gives v2 binary users + v1 users a coherent view of the future shape immediately; phase plans 4-12 reduce to "fill in the stub" rather than "design + add a new subcommand"; surfaces the CLI grammar locked by ADR §8 before any module ports start. Cost: 12 stub `RunE` functions in Phase 3.

- **D-02:** **Stub `RunE` returns phase-pointer message + exit 64 (EX_USAGE).** Stub format: `"\`reconftw <subcommand>\` is not yet implemented — ships in Phase N (<Phase Name>). See .planning/ROADMAP.md for status."`. Exit code: 64 (`sysexits.h` EX_USAGE — caller scripts can branch on it). The subcommand's `--help` continues to work fully (cobra builds it from `Use` / `Short` / `Long` / `Flags()`); only the action path returns the stub error. Rationale: exit 64 makes the "not implemented" state machine-detectable for CI / scripted users; humans get the phase pointer; `--help` is free with cobra (no extra work). Implementation: a Phase 3 helper `func stubNotImplemented(cmd *cobra.Command, phase string, phaseName string) error` returns the formatted error; each module subcommand's `RunE` calls it.

- **D-03:** **All v1 deprecated aliases wired in Phase 3 — both long and short flags.** Per ADR §8.3, registered on `rootCmd.PersistentFlags()` with `cobra.MarkDeprecated()`. Coverage:
  - Long-flag aliases for subcommands: `--recon`, `--all`, `--passive`, `--subdomains`, `--web`, `--vulns`, `--osint`, `--monitor`, `--health-check`.
  - Short-flag aliases for subcommands: `-r` (recon), `-a` (all), `-p` (passive), `-s` (subs), `-w` (web), `-n` (osint — note: not `-o`; `-o` reserved for `--output` per ADR §8.2), `-z` (zen), `-y` (deep). No `-v`/`--vulns` (cobra collision with `--verbose`).
  - Global v1 short-flag aliases: `-d` (deprecated → `--target`), `-l` (deprecated → `--list`), `-v` (deprecated → `--axiom`; conflict resolution per ADR §8.3 names it `vps`/`-v`).
  - Each deprecated flag, when used, prints cobra's default deprecation warning to stderr exactly once, sets the equivalent `CLI_*` override variable, then dispatches to the corresponding v2 subcommand (which in Phase 3 returns its stub message). Rationale: completes the CLI grammar per ADR §8 in Phase 3 so v1 users running `reconftw -r --target X` see a coherent migration message immediately; MODE-09 unit test can be written and run in Phase 3 instead of waiting for Phase 9. The deprecation mechanism is BINDING per ADR §8.4 — removal at v2.2.0.

- **D-04:** **`reconftw version` and `reconftw health-check` ship fully working in Phase 3** (not stubbed). Their machinery (LocalBackend, ToolRegistry, version string from `runtime/debug.ReadBuildInfo`) is Phase 3 deliverable territory, so they can ship complete.
  - `reconftw version` — prints binary version (semantic from ldflags `-X main.version`), commit SHA (`runtime/debug.ReadBuildInfo` → `vcs.revision`), build date (ldflags `-X main.buildDate`), Go version, target platform. Exit 0.
  - `reconftw health-check` — runs `LocalBackend.HealthCheck(ctx)` (always true in Phase 3 since LocalBackend is local subprocess) + iterates `ToolRegistry.Default()` calling `exec.LookPath` for each registered tool (registry is empty in Phase 3 — passes trivially; Phase 4-7 add tools and they show up automatically) + parses `reconftw.toml` from the config loader's 8-source chain and reports parse-time / validation errors. Output: dot-fill format per `lib/ui.sh` port (`[OK  ] tool.name .......... reachable` per registered tool; `[OK  ] config.parse .......... 0.012s`). Exit 0 if all checks pass; 1 if any check fails.
  Rationale: a Phase 3 binary that can self-check is dramatically more useful for Phase 4 development — `reconftw health-check` after `reconftw install` (when Phase 11 ships) gives the smoke test for free; CI integration tests in Phase 3 can use `reconftw health-check` as the kernel sanity gate; v2 users get a familiar v1 command (`--health-check` was a v1 flag).

### Claude's Discretion (defer to researcher + planner)

These gray areas were NOT discussed in detail — planner/researcher resolve with sensible defaults grounded in ADR 0002, REQUIREMENTS.md FOUND-01..16 + XCUT-02/04/07/09, the spike code at `spike/go/`, and the codebase maps:

- **`reconftw run` vs ADR §8 inconsistency** — ROADMAP success criterion 1 references `reconftw run` but ADR §8.1 doesn't list a `run` subcommand. ADR §8 is canonical (BINDING per D-05 of `02-CONTEXT.md`). Planner picks resolution in PLAN.md: (a) treat ROADMAP "run" as shorthand for "any subcommand invocation"; (b) add a `run` subcommand as a Phase-3-only kernel-demo command that runs an empty Task DAG and writes the manifest — would constitute a non-breaking addition per ADR §0 D-07; or (c) interpret success criterion 1 as `reconftw all --dry-run --target <mock>`. Default suggestion: (a) — least scope expansion; success criterion satisfied by any working subcommand that writes a manifest.

- **Plan decomposition strategy** — Phase 3 has 20 REQ-IDs and ~16 build steps. Precedent: Phase 1 had 5 plans, Phase 2 had 7. Coarse-medium options for the planner:
  - (a) ~5-6 plans grouped by ARCH-NN domain: (errors + logger) / (config) / (output + checkpoint) / (scheduler + backend + tools + lint rule) / (appctx + cli + ui + notifier) / (mocks + ci + tests.lock).
  - (b) ~8-10 plans per FOUND-NN cluster (one plan per ~2 FOUND-NN).
  - (c) Single mega-plan (matches Phase 2 plan 02-04 style for tightly-coupled work).
  Default suggestion: (a) — matches Phase 2's 7-plan cadence and gives natural wave boundaries for parallel execution within the phase. The kernel build order from ADR §1.2 + §10.3 (logger BEFORE config) constrains plan dependencies: errors+logger must complete before config plan starts.

- **Spike code disposition** — Phase 1 D-03 collapsed research files but explicitly punted spike code disposition. `spike/python/` (37MB Python loser) and `spike/go/` (3MB Go winner) are both still on `rewrite/v2`. Options for the planner:
  - (a) Delete `spike/python/` immediately at Phase 3 plan-01 start (loser cleanup per D-03 spirit); decide `spike/go/` separately.
  - (b) Keep `spike/go/` as live reference until Phase 4 ports first real module, then delete.
  - (c) Archive both spike trees to a git tag (`spike/v1`) and delete from working tree.
  - (d) Keep `spike/go/` permanently as a `docs/example-slice/` educational artifact (with README marking it non-production), delete `spike/python/`.
  Default suggestion: (a)+(b) — delete `spike/python/` in Phase 3 plan-01 cleanup commit; keep `spike/go/` as live reference until Phase 4 first port. The spike code informs Phase 3 implementations (`proc.go` → `LocalBackend`, `atomic.go` → `OutputTree.AtomicWriter`, `passive.go` → `errgroup` Scheduler pattern) — losing it before Phase 4 ports cuts the reference link before it's been replicated.

- **End-of-Phase-3 demo shape (success criterion 1 fulfillment depth)** — Two options grounded in ADR §1.1 component map and FOUND-15 (test mocks):
  - (a) Bare kernel — `reconftw <subcommand> --target <mock>` writes empty `manifest.json` only (no `artefacts/*` writes); Scheduler runs empty Task DAG.
  - (b) Hardcoded-stub Task — `internal/modules/demo/noop.go` registers `noop.demo` Task via `init()`; running it through the full pipeline writes a fixture line to `artefacts/demo.jsonl` proving Scheduler + Backend + Tree + Checkpoint cooperate end-to-end. Phase 4 first port replaces `noop.demo` registration with `subdomains.passive`.
  Default suggestion: (b) — the demo Task is a regression test in production code paths that the FOUND-15 mocks alone don't cover; it also gives Phase 4 the canonical "how do I register a Task" reference; cost is ~50 LoC of demo code that's deleted in Phase 4 plan-01.

- **AxiomBackend coverage in Phase 3** — `Backend` interface is BINDING per ADR §5.2; `LocalBackend` is required by FOUND-09. `AxiomBackend` depth in Phase 3:
  - (a) None — Phase 4 (Subdomains E2E + Axiom Integration) builds it alongside the Axiom integration. Only `LocalBackend` implements `Backend` in Phase 3.
  - (b) Compile-only stub — `internal/core/backend/axiom.go` exists with all 4 methods returning `ErrAxiomNotImplemented` (a `*AxiomFailure` value per ADR §6); `HealthCheck` always returns the same error. The Scheduler's `Backend` factory still defaults to `LocalBackend`; AxiomBackend is selectable but immediately errors. Lint rule for raw subprocess (FOUND-10) catches anything trying to bypass.
  - (c) Skeleton — `axiom.go` wires fleet `launch`/`shutdown`/`exec` to placeholder shell-outs that print "not yet implemented" but the failover wrapper (AXIOM-06) shape is testable.
  Default suggestion: (b) — gives Phase 3 a clean "Backend has two implementations, one is a stub" contract; FOUND-15 `MockBackend` + (b) gives the test rings three concrete `Backend` implementations to test against; Phase 4 plan-01 swaps the stub for the real `axiom-scan`/`axiom-exec` shell-outs.

- **Tools.lock seeding in Phase 3** — ARCH-NN supply-chain hygiene (XCUT-08) is locked at Phase 11. Phase 3 `ToolRegistry` (FOUND-08) reads from `tools.lock` per ADR §13 (installer). Options:
  - (a) Empty `tools.lock` in Phase 3; Phase 11 ships the populated manifest with 70+ tools.
  - (b) Seed with 5-10 tools used by Phase 4 (`subfinder`, `httpx`, `crt`, `dnsx`, `puredns`, `gotator`, `anew`, `asnmap`, `s3scanner`, `subzy`) so Phase 4 plan-01 starts with a registered registry.
  - (c) Phase 3 ships a full 70-tool `tools.lock` (mostly with `version: "unpinned"` placeholders); Phase 11 swaps `unpinned` for real version pins.
  Default suggestion: (b) — Phase 3 ships an empty registry mechanism + a minimal `tools.lock` covering the 5-10 tools Phase 4 needs; this lets Phase 4 plan-01 start by adding Task implementations rather than fighting the registry; Phase 11 owns the full inventory + SHA-256 verification per INST-02..04.

- **Notifier stub depth (FOUND-11)** — FOUND-11 says "Notifier interface + log sink + Slack/Telegram/Discord stubs; all message bodies pass through redactor before send". Depth options:
  - (a) `LogSink` only (writes notification to slog at info level) + Slack/Telegram/Discord stubs return `nil` without sending. Production wiring in Phase 10.
  - (b) `LogSink` + a `FileSink` writing notifications to `workspaces/<target>/notifications.jsonl` + Slack/Telegram/Discord stubs return `nil`. Phase 10 wires real webhooks.
  - (c) Phase 3 implements real Slack/Telegram/Discord HTTP clients but they're opt-in via config; default config has all three disabled.
  Default suggestion: (a) — minimal Phase 3 surface; FOUND-11 says "stubs"; XCUT-07 redaction CI gate runs against `LogSink` which is enough to verify the redactor is wired correctly; Phase 10 ships real dispatchers.

- **CI matrix scope in Phase 3** — XCUT-04 says "CI policy: race detector mandatory on every Go test run; strict lint; integration-full split: unit+smoke per push, full-arch per nightly, real-tool integration weekly". XPLAT-05 (CI matrix on every supported platform) is Phase 11. Phase 3 CI scope:
  - (a) Single-platform CI (ubuntu-latest, amd64) — unit + integration + smoke rings per ADR §9.3 sample yaml. Phase 11 adds the cross-platform matrix.
  - (b) Phase 3 ships ubuntu-latest + macos-latest (the two common dev platforms) for unit + integration; Phase 11 adds RHEL/Arch/Alpine + arm64.
  Default suggestion: (a) — matches ADR §9.3 sample; lowest CI bill in Phase 3; Phase 11 owns the full matrix per XPLAT-05.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements (the contract)
- `.planning/ROADMAP.md` §"Phase 3: Foundation Kernel" — Goal, dependencies, FOUND-01..16 + XCUT-02/04/07/09 mapping, 5 success criteria. THE source of "what done means".
- `.planning/REQUIREMENTS.md` §"Foundation / Scaffolding (Deliverable #3)" — FOUND-01 through FOUND-16 with locked content for each kernel component.
- `.planning/REQUIREMENTS.md` §"Cross-Cutting Quality Requirements" — XCUT-02 (binary size <50MB stripped, memory <2GB RSS), XCUT-04 (CI policy), XCUT-07 (logging hygiene CI gate), XCUT-09 (heartbeat cadence).
- `.planning/PROJECT.md` §"Current Milestone: v2.0" + §"Key Decisions" — milestone context, the 10 locked decisions from milestone init.

### Architecture (the BINDING contract — every Phase 3 implementation cites a section of ADR 0002)
- `.planning/decisions/0002-architecture-v2.md` — **THE source of truth**. Phase 3 implementers read this end-to-end. Status: Accepted, signed 2026-05-28. After sign-off these contracts are BINDING per D-05; breaking changes require an inline amendment block per D-06.
  - **§1 Overview & System Diagram** — mermaid system diagram, recommended project structure (`cmd/reconftw/`, `internal/core/{errors,log,config,task,scheduler,backend,output,checkpoint,appctx,notifier,ui}`), contract map.
  - **§2 TOML Configuration Schema** — full v2-native + `[legacy]` aliases for all ~290-310 v1 flags; per-key validation rules. Phase 3 `internal/config` implements the loader.
  - **§3 Output Tree Layout** — `workspaces/<target-id>/` shape, JSONL artefacts, `AtomicWriter` pattern. Phase 3 `internal/output` implements.
  - **§4 Compat Symlink Layer** — `CompatWriter` via `LifecycleAware.OnEnd()`. Phase 3 implements writer skeleton.
  - **§5 Interface Signatures** — `Task` (6 methods), `Backend` (4 methods), `AppContext` (9 fields). BINDING. Phase 3 implements in `internal/core/{task,backend,appctx}`.
  - **§6 Error Class Hierarchy** — 7-class typed errors with `Is()` sentinel bridge. Phase 3 implements in `internal/core/errors`.
  - **§7 Failure Policy Model** — `failure_policy = "best_effort" | "fail_fast"` per module group; `errgroup.WithContext` for fail-fast. Phase 3 `internal/scheduler` implements.
  - **§8 CLI Surface** — 15 subcommands, v1 deprecated aliases via `cobra.MarkDeprecated()`. **D-01/D-02/D-03/D-04 above cite this section as the canonical CLI inventory.**
  - **§9 Test Ring Policy** — 4-ring policy (unit/integration/smoke/property-based); §9.3 names Phase 3 Wave 0 requirements (`MockBackend`/`MockCheckpoint`/`MockOutputTree` packages in `internal/core/testutil/`); §9.3 yaml is the CI pipeline starter.
  - **§10 Logging Policy & Secret Redaction** — Two-layer defense: `Secret` type (`LogValuer`) + `RedactingHandler`. §10.3 specifies CRITICAL initialization order: logger → config load → secret registration → AppContext.New. §10.4 specifies XCUT-07 CI gate.
- `.planning/decisions/verify-0002.sh` — Phase 2 pre-sign verification gate; reusable as a Phase 3 sanity check post-implementation.

### Language gate (Phase 1 deliverable)
- `.planning/decisions/0001-language.md` — ADR 0001 (Status: Accepted, signed 2026-05-28). Go locked; all Phase 3 code is Go.
- `.planning/phases/01-language-adr-spike/01-04-SUMMARY.md` — Spike measurements + verdict; Phase 3 inherits the spike measurements as the size budget baseline for XCUT-02 (binary <50MB) and memory ceiling.

### Prior phase context (decisions carried forward)
- `.planning/phases/02-architecture-v2-design/02-CONTEXT.md` — Phase 2 decisions: D-05 contracts BINDING; D-09 TOML schema 1:1 coverage of v1; D-12 per-key validation rules locked in Phase 2 (Phase 3 implements them); D-14 pre-sign gate is reusable; D-16 STATE.md updates only.
- `.planning/phases/01-language-adr-spike/01-CONTEXT.md` — Phase 1 decisions: D-01 tight timebox discipline (Phase 3 inherits spike scope creep is a known PITFALL); D-03 research-file collapse to Go-only has happened.

### Research synthesis (factual base for Phase 3 implementations)
- `.planning/research/SUMMARY.md` — §"Stack Snapshot" gives the locked stack (cobra v1.9.1 / koanf v2 + go-toml v2 / log/slog / errgroup + semaphore.Weighted / os/exec + Setpgid + WaitDelay / net/http + retryablehttp / testing + testify + goleak / golangci-lint v2.12.2 / goreleaser / modernc.org/sqlite). §"Architecture: Top Cross-Cutting Patterns" lists patterns Phase 3 implements.
- `.planning/research/ARCHITECTURE.md` — §1 System Overview, §2 Module Model (Task + Scheduler), §3 Scheduler/Concurrency, §4 Checkpoint Engine, §5 Config System (koanf 8-source), §6 Tool Wrapper (Backend), §7 Output Tree (`AtomicWriter`), §8 Logging (slog two-layer redaction), §9 Error model (7-class), §10 Testing (4 rings), §11 Plugin Registry, §12 Observability (heartbeat for XCUT-09), §13 Packaging (goreleaser + ldflags `-s -w`), §15 Open Questions.
- `.planning/research/STACK.md` — Library picks for each dimension; library blacklist (logrus, viper, mattn/go-sqlite3, http.DefaultClient, cmd.Process.Kill alone, hand-rolled retry, TUI frameworks) — Phase 3 implementations MUST NOT use these.
- `.planning/research/PITFALLS.md` — 51 pitfalls. Top-5 drive Phase 3 contracts: §1.2 process-group escape (FOUND-09 LocalBackend Setpgid + cmd.Cancel + WaitDelay + group-SIGKILL goroutine per spike `proc.go`); §3.1 non-atomic checkpoint writes (FOUND-04 `AtomicWriter`); §2 tool version drift (FOUND-08 ToolRegistry version detection); §4 secret leak in logs (FOUND-02 + XCUT-07 CI gate); §5 custom user config lost (FOUND-03 8-source precedence + Phase 11 migrator).

### Bash reference implementation (what is being ported / what Phase 3 contracts against)
- `.planning/codebase/ARCHITECTURE.md` — Current bash orchestration patterns. Phase 3 ports (not reinvents): `start_func`/`end_func` lifecycle → `Task.Run` + `LifecycleAware`; `parallel_funcs` throttling → `errgroup.SetLimit(N)`; `run_command` wrapper → `Backend.Exec`/`Stream`; checkpoint sentinels → SQLite store; ERR trap → Go panic recovery + structured error events.
- `.planning/codebase/STRUCTURE.md` — v1 module breakdown; informs `internal/modules/` boundaries (Phase 4-7 fill in).
- `.planning/codebase/STACK.md` — 70+ external tools v2 continues to orchestrate; informs `tools.lock` shape (Phase 3 minimal seed, Phase 11 full inventory).
- `.planning/codebase/CONCERNS.md` — Known v1 issues; Phase 3 contracts MUST NOT re-introduce them. Specifically: global state (rejected per ADR §5.3), torn writes (atomic writer mandatory), kill-tree escape (`Setpgid` + group SIGKILL mandatory), secret leak (two-layer redaction mandatory).
- `lib/parallel.sh:_kill_tree()` (line 55) — v1 kill-tree (`pgrep -P` walk). Phase 3 `LocalBackend.Exec`/`Stream` uses OS primitives directly (`Setpgid: true` + `syscall.Kill(-pgid, SIGTERM)` + WaitDelay + group-SIGKILL goroutine per spike `proc.go`).
- `lib/parallel.sh:_throttle_jobs` + `parallel_funcs` (lines 200-340) — v1 throttling (`wait -n`). Phase 3 Scheduler uses `errgroup.SetLimit(PARALLEL_MAX_JOBS)`.
- `modules/core.sh:start_func`/`end_func` — v1 lifecycle wrapper. Phase 3 `Task.Run` returns `Result`; Scheduler writes checkpoint atomically.
- `modules/utils.sh:run_command` — v1 universal tool gate. Phase 3 `Backend.Exec`/`Stream` is the v2 successor.
- `lib/ui.sh` — v1 dot-fill format (`[OK  ] name .......... 12s`). Phase 3 `internal/core/ui` ports verbatim per ADR §10 / `OUTPUT_VERBOSITY=0/1/2` / `PARALLEL_LOG_MODE summary|tail|full` semantics.
- `lib/validation.sh` — v1 input sanitizers. Phase 3 reuses the security posture: `validate_domain` regex `^[a-zA-Z0-9.-]+$` mirrored in Go (proven in spike `cmd/spike/main.go` line 29).
- `lib/common.sh:redact_secrets()` + `register_secret()` — v1 secret redaction. Phase 3 `Redactor.Register`/`Redact` per ADR §10.2 is the direct Go equivalent.
- `reconftw.cfg` — Full v1 flag inventory; Phase 3 config loader must accept every flag listed (TOML form per ADR §2 — D-09 1:1 coverage + D-10 `[legacy]` aliases).
- `reconftw.sh` — v1 getopt block; Phase 3 cobra root command and flag set must cover the v1 grammar per ADR §8.3.

### Spike artifacts (proven Go patterns ready for Phase 3 productionization)
- `spike/go/cmd/spike/main.go` — Cobra CLI bootstrap pattern (lines 31-83); `signal.NotifyContext` for SIGINT/SIGTERM handling; the binary's overall main.go shape. **Phase 3 `cmd/reconftw/main.go` derives from this** + ADR §10.3 initialization order (logger → config → secret-register → AppContext.Boot → cobra.Execute).
- `spike/go/internal/proc/proc.go` — **The reference LocalBackend implementation**. `Setpgid: true` + `cmd.WaitDelay = 5s` + `cmd.Cancel` callback issuing `syscall.Kill(-pid, SIGTERM)` + supplementary goroutine issuing `syscall.Kill(-pgid, SIGKILL)` after `WaitDelay + 500ms` to reap stubborn grandchildren (Go's stdlib `WaitDelay` only kills direct child — known issue documented in proc.go header). Phase 3 `internal/core/backend/local.go` directly adapts this; the kill-tree integration test (FOUND-09 / §9.2 ring 2) ports the spike's `TestSIGINTKillsAllChildrenWithin10s` pattern.
- `spike/go/internal/output/atomic.go` — **The reference `AtomicWriter` implementation**. 4-step pattern: tempfile in same directory → fsync → rename → parent-dir fsync (line 65-75 contains the often-forgotten parent-dir fsync). Phase 3 `internal/output/atomic.go` adapts directly; FOUND-04 SIGKILL-between-rename-and-fsync test ports the spike's TestSIGKILLLeavesOriginalIntact pattern.
- `spike/go/internal/passive/passive.go` — **The reference errgroup fan-out pattern** (lines 60-67: `g.SetLimit(4)` + `g.Go(func() error { ... })`). Phase 3 Scheduler uses this primitive; `internal/modules/demo/noop.go` (if D-default-end-of-phase-demo (b) chosen) registers via `init()` mirroring this code shape.
- `spike/go/go.mod` — Reference module path (`github.com/six2dez/reconftw/spike/go`) + Go version (`1.26.1`). Phase 3 production module is at repo root `github.com/six2dez/reconftw` (`go.mod` already committed).
- `spike/go/Makefile` — Build target reference (`go build -ldflags="-s -w" -trimpath -o bin/spike ./cmd/spike`). Phase 3 production Makefile adapts the `-ldflags` for binary-size compliance (XCUT-02 <50MB stripped).

### Existing root scaffold (committed in Phase 2)
- `go.mod` (repo root, committed) — Production module path `github.com/six2dez/reconftw`, Go 1.23. Phase 3 may bump to Go 1.24+ per stack pick (research/SUMMARY.md says "1.24+ target 1.26").
- `interfaces_check/main.go` (committed) — Phase 2 D-14 pre-sign verification scaffold. Mirrors ADR §5 interface snippets with placeholder types. Phase 3 disposition: KEEP as-is until real `internal/core/{task,backend,appctx}` are implemented, then either delete (replaced by `go vet ./...` on real packages) or convert to a docs-only example. Planner decides.

### Project conventions (style + commit discipline)
- `CLAUDE.md` — Project commit conventions (no Claude co-author footer per `memory/feedback_commits.md` user memory); workflow gates (GSD enforcement via `/gsd-execute-phase` for planned work).
- `.planning/codebase/CONVENTIONS.md` — Naming patterns; v2 Go code follows idiomatic Go (CamelCase, package-name-prefixed types) but TOML keys mirror v1 `snake_case` where they survive as `[legacy]` aliases (per ADR §2 D-10).
- `.planning/codebase/TESTING.md` — Reference for test parity (XCUT-03: feature-parity coverage of v1's 351 bats scenarios mapped to v2 tests).

### Out-of-scope reminders
- `internal/store/sqlc/` (untracked, gitignored) — From `reconftw-web/` experimentation; PROJECT.md "Out of Scope" §"GUI / web dashboard" explicitly excludes this from v2.0. Phase 3 implementations do NOT touch `internal/store/sqlc/`; Phase 3's `internal/checkpoint/` is a separate package using `modernc.org/sqlite` directly per ADR §3 / research/STACK.md.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets (proven Go patterns ready to productionize)

- **`spike/go/internal/proc/proc.go`** — LocalBackend reference (kill-tree-safe subprocess). The header comment documents the WaitDelay-only-kills-direct-child gotcha and the supplementary group-SIGKILL goroutine workaround; Phase 3 `internal/core/backend/local.go` adapts this verbatim. Pattern proven in spike SIGINT integration test (DEC-03 metric "kill-tree correctness under interrupt" — Go passed).
- **`spike/go/internal/output/atomic.go`** — `AtomicWriter` reference. 4-step pattern with parent-dir fsync (step 4). Phase 3 `internal/output/atomic.go` adapts; FOUND-04 integration test ports the spike's SIGKILL-between-rename-and-fsync assertion.
- **`spike/go/internal/passive/passive.go`** — errgroup fan-out reference (`g.SetLimit(4)` + `g.Go(...)`). Phase 3 Scheduler builds atop this primitive (with `failure_policy` dispatch per ADR §7 wrapped around it).
- **`spike/go/cmd/spike/main.go`** — Cobra CLI bootstrap reference (lines 31-83). `signal.NotifyContext` SIGINT/SIGTERM pattern is exactly what Phase 3 `cmd/reconftw/main.go` needs. Phase 3 adds the ADR §10.3 init order: logger first, config second, secret-register third, AppContext.Boot fourth, cobra.Execute last.
- **`interfaces_check/main.go`** (root) — Phase 2 verification scaffold with placeholder interfaces matching ADR §5. Phase 3 implementations in `internal/core/{task,backend,appctx}` MUST match the signatures verified here; Phase 3 can use `interfaces_check/main.go` as a delta-detector during the early plans.
- **`go.mod`** (root, committed) — Production module `github.com/six2dez/reconftw`. Phase 3 adds dependencies per research/STACK.md library picks.

### Established Patterns (v1 patterns the kernel MUST port or explicitly reject)

- **Global config + sourced modules (`reconftw.cfg` sourced into a single shell process)** — REJECT. ADR §5.3 mandates AppContext passed by pointer; NO package-level globals. Phase 3 lint rule (FOUND-10 extension): also forbid package-level mutable globals in `internal/` outside the singletons defined in ADR §5 (`task.Default`, etc.).
- **Bash function checkpoints (`touch "$called_fn_dir/.${fn}"`)** — REPLACE with SQLite checkpoint store. ADR §3 specifies `checkpoints.db`. Phase 3 `internal/checkpoint/` uses `modernc.org/sqlite` (pure-Go, no CGO — preserves single-binary promise per research/SUMMARY.md library pick).
- **Subprocess "fire-and-merge" for passive sources** — KEEP. `errgroup` fan-out (spike `passive.go`) is the v2 equivalent; ADR §7 wraps it with `failure_policy` per module group.
- **shellcheck + shfmt CI gates** — REPLACE with `go vet` + `golangci-lint v2.12.2`. ADR §9 / §10 mandate; Phase 3 ships the `.golangci.yml` config.
- **`OUTPUT_VERBOSITY=0/1/2` runtime knob** — KEEP. v2 honors the same 0/1/2 semantics via slog level mapping (per ADR §10 + `--quiet/--verbose` flags per ADR §8.2).
- **`PARALLEL_LOG_MODE summary|tail|full`** — KEEP. UI module (`internal/core/ui`) ports the three modes verbatim from `lib/ui.sh`.
- **`--source-only` test entry** — REPLACE with Go's native test-binary model (`go test ./...`); no parallel concept in v2.
- **bash `redact_secrets()` + `register_secret()`** — REPLACE with `Redactor.Register`/`Redact` + `Secret` type (two-layer per ADR §10).
- **bash `validate_domain` regex** — KEEP as the canonical input-validation regex; Phase 3 reuses `^[a-zA-Z0-9.-]+$` (proven in spike `main.go` line 29).
- **bash `start_func`/`end_func` per-function start times (parallel-safe)** — Replace with `Task.Run` returning `Result{Duration: ...}`; Scheduler logs at the boundary.

### Integration Points (where Phase 3 contracts will be consumed)

- **Phase 4 (Subdomains E2E + Axiom)** — First consumer of FOUND-08 ToolRegistry, FOUND-09 LocalBackend.Stream (long-running tools like puredns), FOUND-05 Checkpoint (subs.passive → checkpoint write), FOUND-04 OutputTree.Append (subdomains.jsonl), FOUND-06 Scheduler.failure_policy = "fail_fast" for subs module. Phase 4 plan-01 MUST cite the exact §5 interface signatures and §6 error types Phase 3 ships.
- **Phase 5-7 (Web / Vulns / OSINT ports)** — Consume the same FOUND-NN contracts. failure_policy = "best_effort" per ADR §7 for these module groups. The ToolRegistry seeded in Phase 3 (per the planner's tools.lock decision) registers additional tools per phase.
- **Phase 8 (MCP server)** — Consumes ARCH-06 `Backend.Stream()` channel for SSE multiplexing. Phase 3 ships the Stream() shape per spike `proc.go` line 56 (`StdoutPipe` + bufio.Scanner streaming with 1MiB/10MiB buffer per RESEARCH.md §Pattern 3); Phase 8 wraps it for MCP SSE.
- **Phase 9 (Composite Modes)** — Consumes FOUND-12 Task.DependsOn DAG and ADR §7 failure_policy composition. Phase 3 ships the DAG primitives; Phase 9 composes the cross-module DAGs. CLI surface per D-01/D-03 means Phase 9's MODE-09 work is mostly testing (since aliases are already wired in Phase 3).
- **Phase 10 (Monitor + Reporting + Notifications)** — Consumes the Notifier interface (FOUND-11) for real Slack/Telegram/Discord; the OutputTree for findings dedup (incremental diff); the Scheduler for monitor loop scheduling.
- **Phase 11 (Installer + Cross-Platform + Docker)** — Consumes the `tools.lock` shape (Phase 3 seeds 5-10 per Claude-discretion default; Phase 11 populates 70+); ships the `reconftw install` real implementation (Phase 3 stubs it per D-01/D-02). XPLAT-05 cross-platform CI matrix in Phase 11 extends Phase 3's single-platform CI per Claude-discretion default.
- **Phase 12 (Cutover + Migration)** — Consumes ADR §4 `CompatWriter` (Phase 3 implements the writer; Phase 12 owns the 6-month lifecycle and cutover criterion). The migrator (CUT-01..06) reads ADR §2 TOML schema as its target shape; Phase 3 ships the loader, Phase 11 ships the migrator.

</code_context>

<specifics>
## Specific Ideas

- **CLI grammar locks in Phase 3, not Phase 9.** D-01 + D-03 together mean ADR §8 is fully realized as a working CLI grammar in Phase 3 — 15 subcommands surfaced, all v1 deprecated aliases wired with `cobra.MarkDeprecated()`. This is a deliberate scope expansion vs minimal interpretation: it pushes the "shape" forward so Phase 4-12 implementers can focus on filling stubs rather than designing new subcommand surfaces. Cost: ~12 stub `RunE` functions + ~9 long-flag + ~10 short-flag aliases registered in Phase 3 plan that ships the cobra root command.

- **`reconftw health-check` is the Phase 3 kernel sanity gate.** D-04 makes health-check real in Phase 3. This gives the Phase 3 → Phase 4 transition a concrete acceptance test: "does `reconftw health-check` exit 0 with no registered tools?" Phase 4 plan-01 first test: "does `reconftw health-check` show the newly-registered subfinder?" The command also formalizes FOUND-08 ToolRegistry's "warns on missing-but-required, errors on missing-and-critical" semantics in user-visible output.

- **Stub message format makes phase plans discoverable.** D-02's phase-pointer message (`"ships in Phase N (<Phase Name>). See .planning/ROADMAP.md for status."`) gives users a self-documenting binary: anyone exploring `reconftw` learns the project structure by trying subcommands. Phase 3 implementation can use a constant lookup table (`map[string]struct{Phase int; Name string}{...}`) seeded from ROADMAP.md — a Phase 3 plan can include a `go generate` directive that re-parses ROADMAP.md to keep the table in sync (but planner discretion whether to ship that).

- **Phase 2 verification scaffold (`interfaces_check/main.go`) is a delta detector for Phase 3.** As Phase 3 implements `internal/core/{task,backend,appctx}`, the `interfaces_check/main.go` placeholders should be updated to import the real packages and verify the signatures match. If `go build ./interfaces_check/...` fails after a Phase 3 implementation lands, the implementation drifted from ADR §5 — that's a BINDING-violation signal requiring either fix-the-impl or an ADR §12 amendment. Planner decides whether this is automated as a Phase 3 CI check or a manual review gate.

- **The spike code is reference, not foundation.** Phase 3 implementations DO NOT import from `spike/go/`. The spike has its own go.mod and is hermetic per Phase 1 design. Phase 3 copies/adapts proven patterns (mostly: kill-tree, atomic write, errgroup fan-out, cobra bootstrap) into `internal/core/` with production-grade error handling + tests + ADR §6 typed errors instead of spike's `fmt.Errorf` strings. The lift from spike to production is ~2-3x LoC growth per pattern due to test coverage + typed errors + structured logging.

</specifics>

<deferred>
## Deferred Ideas

- **`reconftw run` vs ADR §8 inconsistency** — ROADMAP success criterion 1 mentions `reconftw run`; ADR §8.1 doesn't list a `run` subcommand. ADR §8 is canonical (BINDING). Planner picks resolution in `03-PLAN.md`: treat as ROADMAP shorthand for "any subcommand invocation" (default), OR add `run` as a Phase-3-only kernel-demo command (non-breaking addition per ADR §0 D-07), OR interpret as `reconftw all --dry-run`. Default: shorthand interpretation; the binary's exit-0 manifest-write requirement is satisfied by any working subcommand (e.g., the noop.demo Task if planner picks demo-shape option (b)).

- **Plan decomposition strategy** — Phase 3 has 20 REQ-IDs / ~16 build steps. Precedent: Phase 1 had 5 plans, Phase 2 had 7. Planner picks: ~5-6 plans grouped by ARCH-NN domain (recommended) vs ~8-10 per FOUND-NN cluster vs single mega-plan. The kernel build order from ADR §1.2 + §10.3 (logger BEFORE config) constrains plan dependencies. Recommend planner consider wave structure: plan-01 (errors + logger + Secret + Redactor + scaffold `internal/core/` tree + first CI commit) — must complete before everything else; plan-02 (config loader + validation rules); plan-03 (output tree + atomic writer + checkpoint store); plan-04 (scheduler + backend + local backend + tool registry + lint rule); plan-05 (appctx + cli + ui + notifier stubs + version + health-check); plan-06 (test mocks + integration smoke + tools.lock seed + Phase 3 acceptance test).

- **Spike code disposition** — Phase 1 D-03 punted to planner. `spike/python/` (37MB Python loser) and `spike/go/` (3MB Go winner). Recommend planner: (a) delete `spike/python/` in Phase 3 plan-01 cleanup commit (loser, no reference value once Go ADR signed) + (b) keep `spike/go/` as live reference until Phase 4 ports first real module, then delete `spike/go/`. Alternative (d): keep `spike/go/` permanently as a `docs/example-slice/` educational artifact (with README marking it non-production). Spike code informs Phase 3 implementations (`proc.go` → `LocalBackend`, `atomic.go` → `OutputTree.AtomicWriter`, `passive.go` → `errgroup` Scheduler) so losing it before Phase 4 ports cuts the reference link before replication.

- **End-of-Phase-3 demo shape** — Two options: (a) bare kernel writes empty `manifest.json` only; (b) hardcoded-stub `noop.demo` Task in `internal/modules/demo/` proves Scheduler + Backend + Tree + Checkpoint end-to-end with fixture line in `artefacts/demo.jsonl`. Recommend planner option (b) — demo Task is a regression test in production code paths the FOUND-15 mocks alone don't cover; gives Phase 4 the canonical "how to register a Task" reference; Phase 4 plan-01 deletes the demo registration.

- **AxiomBackend coverage in Phase 3** — `Backend` interface BINDING per ADR §5.2. Options: (a) None — Phase 4 owns; (b) compile-only stub returning `*AxiomFailure` with `ErrAxiomNotImplemented`; (c) skeleton with placeholder shell-outs. Recommend (b) — gives Phase 3 a "Backend has two implementations, one is a stub" contract; FOUND-15 MockBackend + (b) gives test rings three concrete `Backend` implementations.

- **Tools.lock seeding in Phase 3** — Options: (a) empty; (b) seed 5-10 tools needed by Phase 4 subdomains module (`subfinder`, `httpx`, `crt`, `dnsx`, `puredns`, `gotator`, `anew`, `asnmap`, `s3scanner`, `subzy`); (c) full 70-tool seed with `version: "unpinned"` placeholders. Recommend (b) — Phase 4 plan-01 starts with a working registry instead of fighting it.

- **Notifier stub depth (FOUND-11)** — Options: (a) LogSink only + Slack/Telegram/Discord return nil; (b) LogSink + FileSink writing to `workspaces/<target>/notifications.jsonl`; (c) Phase 3 implements real HTTP clients opt-in via config. Recommend (a) — FOUND-11 says "stubs"; XCUT-07 redaction CI gate runs against LogSink.

- **CI matrix scope in Phase 3** — Options: (a) single-platform (ubuntu-latest amd64) per ADR §9.3 yaml; (b) ubuntu-latest + macos-latest. Recommend (a) — matches ADR §9.3 sample; XPLAT-05 cross-platform matrix is Phase 11's deliverable.

- **`interfaces_check/main.go` disposition** — Phase 2 D-14 verification scaffold; obsolete once `internal/core/{task,backend,appctx}` ship. Planner decides: keep as-is (delta detector), delete (replaced by go vet ./...), or convert to docs-only example. Recommend keep until end of Phase 3, then delete in Phase 4 plan-01.

- **Performance baseline timing for XCUT-01** — XCUT-01 says "v2 throughput within 10% of bash v1 on canonical benchmark". STATE.md notes "baseline est. Phase 3, validated per-module phase". Planner picks: synthetic Scheduler+AtomicWriter throughput micro-benchmark in Phase 3 (testable now), OR defer the real bash-v1-comparison baseline to Phase 4 (when subdomains pipeline exists end-to-end). Recommend deferring real baseline to Phase 4 closing; Phase 3 ships micro-benchmarks for the kernel hot paths only.

- **Public announcement of Phase 3 binary release** — Optional; not a Phase 3 deliverable. Phase 12 cutover handles user-facing comms.

</deferred>

---

*Phase: 3-foundation-kernel*
*Context gathered: 2026-05-28*
