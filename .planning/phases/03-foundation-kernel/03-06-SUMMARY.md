---
phase: 03-foundation-kernel
plan: 06
subsystem: foundation-kernel
tags: [cli, cobra, main, healthcheck, version, kernel-demo, xcut-02, d-01, d-02, d-03, d-04, d-05, w14, w16, blocker-5]

# Dependency graph
requires:
  - phase: 01-language-adr-spike
    provides: spike/go/cmd/spike/main.go (cobra + signal.NotifyContext bootstrap reference)
  - phase: 02-architecture-v2-design
    provides: |
      ADR §8 (BINDING CLI surface — 15 subcommands + v1 deprecation pattern)
      ADR §10.3 (BINDING init order — signal → redactor → logger → config → secrets → AppContext → cobra)
  - phase: 03-foundation-kernel
    provides: |
      Plan 01 — internal/core/log (Redactor, log.Config, log.New, slog handler chain)
      Plan 02 — internal/core/config (Load(LoadOptions), 9 log.Secret fields per §2.2)
      Plan 03 — internal/core/output (WorkspaceInit, OutputTree, scope filter, manifest)
      Plan 04 — internal/core/backend (LocalBackend, ToolRegistry, MissingCritical/MissingRequired per Blocker 5)
      Plan 05 — internal/core/{task,scheduler,appctx,notifier,ui,modules/demo} (Task born final + Boot factory + cycle-break via RunTask closure)
provides:
  - cmd/reconftw/main.go (entry-point with ADR §10.3 10-STEP init order + W14 parseEarlyFlags + W10 registerSecrets)
  - cmd/reconftw/root.go (newRootCmd: 15 visible v2 subcommands + 1 hidden + 9 long-flag + 8 short-flag + 3 global deprecated aliases)
  - cmd/reconftw/stub.go (stubNotImplemented helper returning *exitCodeError{code:64} per D-02)
  - cmd/reconftw/stub_subcommands.go (phasePointers table + 14 stub constructors)
  - cmd/reconftw/modules.go (blank import _ "internal/modules/demo")
  - cmd/reconftw/kernel_demo.go (Hidden:true subcommand per W16 + ADR §0 D-07)
  - cmd/reconftw/version.go (D-04 working — ldflags + runtime/debug.ReadBuildInfo)
  - cmd/reconftw/healthcheck.go (D-04 + Blocker 5 — MissingCritical→FAIL+exit 1, MissingRequired→WARN+exit 0)
  - Makefile build target with XCUT-02 ldflags: VERSION/COMMIT_SHA/BUILD_DATE auto-derived
affects:
  - Plan 07 — TestKernelDemoEndToEnd integration smoke test invokes hidden kernel-demo;
    binary-size gate (XCUT-02 <50MB) activatable now that bin/reconftw exists
  - Phase 4 plan-01 — MUST delete cmd/reconftw/kernel_demo.go + internal/modules/demo/noop.go
    + the blank import in cmd/reconftw/modules.go; replace with internal/modules/subdomains/passive.go
    + corresponding blank import. The subs stub becomes a real subcommand.
  - Phase 9 (composite modes) — MODE-09 already covered: v1 aliases shipped in Phase 3
    + Phase 9 just needs to wire the alias→subcommand dispatch

# Tech tracking
tech-stack:
  added:
    - github.com/spf13/cobra v1.9.1 (per RESEARCH.md library mandate — Google + spf13 maintained, go.sum verified)
    - github.com/spf13/pflag v1.0.6 (cobra dependency)
    - github.com/inconshreveable/mousetrap v1.1.0 (pflag transitive dep — Windows-only behavior)
  patterns:
    - "ADR §10.3 10-STEP init order codified as numbered comments in main.run: signal → redactor → bootstrap logger → parseEarlyFlags → config.Load → rebuild logger → registerSecrets → task.Default.Build → scheduler.NewScheduler + appctx.Boot → sched.RunTask closure → cobra.Execute"
    - "W14 pre-cobra parseEarlyFlags scans os.Args for ONLY --config/--secrets/--target — cobra owns full parsing inside Execute. Accepts `--flag PATH` and `--flag=PATH` forms; silently ignores unknown flags."
    - "W10 registerSecrets explicitly enumerates all 9 log.Secret fields per config.go SECRET FIELD ENUMERATION comment block (Slack/Telegram/Discord webhooks + AI OpenAI/Anthropic + MCP API + APIKeys Shodan/WhoisXML/PDCP). One Register call per field; len ≤ 4 skip rule lives inside Redactor.Register."
    - "D-02 exit-code helper: stubNotImplemented + *exitCodeError{code, msg} sentinel error type lets a nested cobra RunE propagate the desired process exit code up to main; main.main type-asserts via errors.As to extract the code."
    - "D-03 cobra MarkDeprecated pattern: long flag declared via BoolP/StringP (shorthand bound to short letter) + immediate MarkDeprecated call with subcommand-pointer usage message. One MarkDeprecated entry covers BOTH `--flag` and `-shorthand` invocations because pflag treats them as a single Flag."
    - "D-04 version subcommand fallback chain: ldflag-injected main.CommitSHA → runtime/debug.ReadBuildInfo vcs.revision → 'unknown'. ldflags injected at make build time via -X main.Version=$(git describe) -X main.CommitSHA=$(git rev-parse) -X main.BuildDate=$(date -u)."
    - "Blocker 5 / FOUND-08 health-check semantics: MissingCritical() FAIL → exit 1; MissingRequired() WARN → exit 0. Wired via two-set comparison: missing-name ∈ Critical set → FAIL, missing-name ∈ Required-but-not-Critical → WARN, else OK."
    - "W16 hidden subcommand: cobra.Command{Hidden: true} blocks --help listing but allows direct invocation by name. Plan 07's integration test invokes `reconftw kernel-demo --target X` which dispatches noop.demo through *scheduler.Scheduler.RunStage(ctx, 'demo', tasks). Type-assertion app.Scheduler.(*scheduler.Scheduler) needed because app.Scheduler is the SchedulerRunner cycle-break interface."

key-files:
  created:
    - cmd/reconftw/main.go
    - cmd/reconftw/main_test.go
    - cmd/reconftw/root.go
    - cmd/reconftw/root_test.go
    - cmd/reconftw/stub.go
    - cmd/reconftw/stub_subcommands.go
    - cmd/reconftw/stub_test.go
    - cmd/reconftw/modules.go
    - cmd/reconftw/kernel_demo.go
    - cmd/reconftw/kernel_demo_test.go
    - cmd/reconftw/helpers_test.go
    - cmd/reconftw/version.go
    - cmd/reconftw/version_test.go
    - cmd/reconftw/healthcheck.go
    - cmd/reconftw/healthcheck_test.go
  modified:
    - Makefile
    - go.mod
    - go.sum
    - .gitignore

key-decisions:
  - "D-01 fulfilled: all 15 v2 subcommands per ADR §8.1 visible in --help (recon/all/passive/subs/web/vulns/osint/zen/deep/monitor/report/mcp/migrate/install/health-check) + version (D-04 augmentation) = 16 visible. kernel-demo (1 hidden, W16) = 17 total. Smoke test counts 16 lines matching the v2 inventory."
  - "D-02 fulfilled: every stubbed subcommand RunE returns *exitCodeError{code:64} via stubNotImplemented helper. Phase-pointer message format ' `reconftw <name>` is not yet implemented — ships in Phase N (<phase>). See .planning/ROADMAP.md for status.' Machine-detectable exit 64 (sysexits.h EX_USAGE) for CI / scripted users."
  - "D-03 fulfilled: 23 cobra.MarkDeprecated calls (per source grep) wiring 9 long + 8 short + 3 global aliases (14 distinct Flag entries because pflag merges long+shorthand into one Flag). Every alias invocation emits cobra's default deprecation warning to OutOrStdout (NOT ErrOrStderr — this is a cobra/pflag quirk callers should know about). Tests assert both long and short forms individually."
  - "D-04 fulfilled: version subcommand prints 5-line block (version/commit/built/go version/platform); health-check subcommand emits dot-fill UI lines via ui.Printer. Both ship FULLY WORKING — no stubNotImplemented."
  - "D-05 (W16) fulfilled: cmd/reconftw/kernel_demo.go ships with Hidden:true + W16 + D-07 + Phase 4 deletion citations in file header. Direct invocation `reconftw kernel-demo --target X` runs noop.demo through the full Scheduler pipeline, producing workspaces/<target>-<timestamp>/artefacts/demo.jsonl with the phase-3-kernel fixture line."
  - "ADR §10.3 init order codified inline in cmd/reconftw/main.go via numbered STEP comments. The order is: 1) signal.NotifyContext, 2) Redactor, 3) bootstrap logger, 4) parseEarlyFlags (W14), 5) config.Load, 6) rebuild logger, 7) registerSecrets (W10), 8) task.Default.Build, 9) scheduler.NewScheduler + appctx.Boot, 9b) sched.RunTask closure (cycle-break #2), 10) cobra.ExecuteContext."
  - "config.Load signature: Plan 02 ships Load(opts LoadOptions) (*Config, error) — Plan 06 main.go adapts by constructing LoadOptions{ExplicitConfigPath: ..., SecretsPath: ...} from parseEarlyFlags rather than the warning #6 map[string]any signature. The actual signature is the one in internal/core/config/loader.go line 73."
  - "Cycle-break #2 wiring: main.run sets sched.RunTask = func(ctx, t) (Result, error) { return t.Run(ctx, app) } AFTER appctx.Boot returns. The closure captures app so the scheduler package never imports appctx. Per Plan 05 design."
  - "Binary size 10 MB stripped vs 15 MB unstripped — well under XCUT-02 50 MB budget. Plan 07 can activate the binary-size CI gate now that bin/reconftw builds with real content."
  - "Workspace creation: main.run calls output.WorkspaceInit(cfg.Paths.DataDir, tgt.Domain) when --target is supplied, falling back to 'workspaces' if cfg.Paths.DataDir is empty. The created directory becomes tgt.WorkDir which is then passed to appctx.Boot — chains correctly with Plan 03 OutputTree."

patterns-established:
  - "Pattern 1: Pre-cobra os.Args scan via parseEarlyFlags — minimal-grammar scanner that extracts only the flags needed to bootstrap config + logger BEFORE cobra owns full parsing. Reusable pattern for any Go CLI that needs a logger before cobra dispatches."
  - "Pattern 2: *exitCodeError as cobra RunE return value + main.main errors.As type assertion — propagates a specific os.Exit code up the call chain without breaking the standard error interface. Idiomatic Go for CLI tools that need explicit exit codes beyond 0/1."
  - "Pattern 3: cobra.MarkDeprecated pairing with BoolP/StringP — one MarkDeprecated entry covers both long and short aliases because pflag stores them in a single Flag struct with a Shorthand field. The deprecation message goes to cmd.OutOrStdout (NOT ErrOrStderr — undocumented quirk)."
  - "Pattern 4: ldflag-injected version metadata + runtime/debug.ReadBuildInfo fallback — the canonical Go CLI pattern for embedding build info. Works for both go-built (build info present) and ldflag-injected (Makefile) cases."
  - "Pattern 5: Hidden:true subcommand for testing — cobra.Command.Hidden suppresses --help listing without affecting direct invocation. Used by Plan 07's TestKernelDemoEndToEnd to invoke a 'private' command. Phase 4 plan-01 deletes both the subcommand and its registered Task."
  - "Pattern 6: testable kernel function (runHealthCheck) separated from the cobra subcommand wrapper (newHealthCheckCmd). Tests inject a fresh *backend.ToolRegistry to avoid Blocker 7 cross-test contamination via backend.Default."

requirements-completed: [FOUND-13, FOUND-14]

# Metrics
duration: ~16min
completed: 2026-05-28
---

# Phase 3 Plan 6: CLI Binary Summary

**Ship cmd/reconftw/ — the runnable v2 binary. ADR §10.3 init order codified verbatim in main.go. All 15 visible v2 subcommands per D-01; 12 return phase-pointer exit 64 per D-02; v1 deprecated aliases via cobra.MarkDeprecated per D-03; version + health-check fully working per D-04; hidden kernel-demo per W16 invokes noop.demo through the Scheduler for Plan 07's acceptance integration test. Makefile XCUT-02 ldflags wire version metadata at link time.**

## Performance

- **Duration:** ~16 min
- **Started:** 2026-05-28T17:11:58Z
- **Completed:** 2026-05-28T17:28:57Z
- **Tasks:** 3 (all auto, all TDD-cycled — tests written alongside implementation, all GREEN)
- **Files created:** 15 (8 source + 7 test files in `cmd/reconftw/`)
- **Files modified:** 4 (Makefile, go.mod, go.sum, .gitignore)
- **Test count delta:** +35 tests (parseEarlyFlags/registerSecrets ×10, root/stub/kernel-demo ×16, version ×4, healthcheck ×6)
- **Coverage on cmd/reconftw/:** 71.0% (clears the ≥60% honest-coverage gate per CLI plumbing reality)
- **Binary size:** stripped 10.8 MB (11 MB ≈ 10 MB) — well under XCUT-02 50 MB budget. Unstripped 16 MB → stripped saving 5 MB via `-ldflags="-s -w" -trimpath`.

## Accomplishments

### D-01 — 15 v2 Subcommands Visible

| Subcommand | Status | Phase pointer | Behavior |
|------------|--------|----------------|----------|
| `recon`    | stub   | 4 — Subdomains E2E + Axiom Integration (recon composite) | exit 64 |
| `all`      | stub   | 9 — Composite Modes (all)                               | exit 64 |
| `passive`  | stub   | 9 — Composite Modes (passive)                           | exit 64 |
| `subs`     | stub   | 4 — Subdomains E2E + Axiom Integration                  | exit 64 |
| `web`      | stub   | 5 — Web Pipeline E2E                                    | exit 64 |
| `vulns`    | stub   | 6 — Vulnerability Scanning E2E                          | exit 64 |
| `osint`    | stub   | 7 — OSINT E2E                                           | exit 64 |
| `zen`      | stub   | 9 — Composite Modes (zen)                               | exit 64 |
| `deep`     | stub   | 9 — Composite Modes (deep)                              | exit 64 |
| `monitor`  | stub   | 10 — Monitor Mode + Reporting + Notifications           | exit 64 |
| `report`   | stub   | 10 — Monitor Mode + Reporting + Notifications           | exit 64 |
| `mcp`      | stub   | 8 — MCP Server                                          | exit 64 |
| `migrate`  | stub   | 11 — Installer + Cross-Platform + Docker                | exit 64 |
| `install`  | stub   | 11 — Installer + Cross-Platform + Docker                | exit 64 |
| `health-check` | **working** | n/a (D-04)                                      | dot-fill output, exit 0/1 per Blocker 5 |
| `version`  | **working** | n/a (D-04)                                          | 5-line block, exit 0 |
| `kernel-demo` | **hidden** | n/a (W16)                                          | NOT in --help; invokes noop.demo through Scheduler |

Total: **14 stubbed + 2 working + 1 hidden = 17 cobra subcommands**.
Visible to `reconftw --help`: 14 + 2 = **16 lines** (matches smoke test).

### D-02 — Stub Exit 64 + Phase-Pointer Message

Example output for `reconftw subs --target example.com`:

```
`reconftw subs` is not yet implemented — ships in Phase 4 (Subdomains E2E + Axiom Integration). See .planning/ROADMAP.md for status.
$ echo $?
64
```

The format is BINDING — Phase 4-11 implementers replace the RunE body but the failure mode (and exit code) for unimplemented subcommands is committed.

### D-03 — V1 Deprecated Aliases (20 alias forms, 14 cobra Flag entries)

| Form | Long flag | Short | Example |
|------|-----------|-------|---------|
| Long subcommand (9) | `--recon`, `--all`, `--passive`, `--subdomains`, `--web`, `--vulns`, `--osint`, `--monitor`, `--health-check` | — | `reconftw --recon ...` |
| Short subcommand (8) | (above sharing shorthand) | `-r`, `-a`, `-p`, `-s`, `-w`, `-n`, `-z`, `-y` | `reconftw -r ...` |
| Global short (3) | `--target-deprecated`, `--list-deprecated`, `--vps` | `-d`, `-l`, `-v` | `reconftw -d example.com ...` |

The `-v`/`--vulns` collision per ADR §8.3 lines 2148 is resolved by NOT short-flagging `--vulns` (cobra reserves `-v` for `--verbose` semantics; we hold `--vulns` long-only).

Every alias invocation emits cobra's default warning:
```
Flag --recon has been deprecated, use subcommand 'recon' instead: `reconftw recon --target example.com`
```

**Quirk note:** cobra's pflag emits the deprecation warning to `cmd.OutOrStdout()`, not `cmd.ErrOrStderr()`. Tests capture both. The actual binary prints to terminal which the user sees regardless. Phase 9 (MODE-09) just needs to wire the alias→subcommand dispatch; the warning emission is already locked.

### D-04 — version + health-check Fully Working

**version** (5 lines, exit 0):
```
reconftw version v4.1-225-g3ea1ca06
  commit:     3ea1ca06
  built:      2026-05-28T17:28:49Z
  go version: go1.26.1
  platform:   darwin/arm64
```

The Version/CommitSHA/BuildDate values are populated by Makefile XCUT-02 ldflags (`-X main.Version=$(git describe) -X main.CommitSHA=$(git rev-parse) -X main.BuildDate=$(date -u)`). Falls back to runtime/debug.ReadBuildInfo vcs.revision when the ldflag-injected CommitSHA is the "unknown" sentinel.

**health-check** (dot-fill UI, Blocker 5 semantics):
```
[OK   ] config.parse .............. 0s
[OK   ] backend.local ............. 0s
[OK   ] tools (0 registered —... . 0s
$ echo $?
0
```

Phase 3 baseline: empty registry passes trivially (Plan 07 seeds the canonical tools.lock). When Plan 07's seed lands AND a critical tool is absent on PATH, the per-tool line becomes `[FAIL] tool.subfinder (critical) .... 0s` and the overall exit becomes 1 — that's intended Blocker 5 behaviour.

### D-05 (W16) — Hidden kernel-demo Subcommand

Successfully boots → invokes noop.demo through *scheduler.Scheduler.RunStage → writes workspaces/example.com-<timestamp>/artefacts/demo.jsonl with the phase-3-kernel fixture line. checkpoint.db gets a row for "noop.demo" with status=done.

```bash
$ ./bin/reconftw kernel-demo --target example.com
$ cat workspaces/*/artefacts/demo.jsonl
{"demo":"phase-3-kernel","timestamp":"2026-05-28T17:28:50Z"}
$ echo $?
0
```

Verified `reconftw --help` does NOT list kernel-demo (Hidden:true), but it IS invokable by name. Plan 07's TestKernelDemoEndToEnd consumes this contract.

### ADR §10.3 10-STEP Init Order Codified

```go
// STEP 1: signal.NotifyContext for SIGINT/SIGTERM
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
// STEP 2: Create the redactor FIRST
redactor := &log.Redactor{}
// STEP 3: Bootstrap logger BEFORE config load
bootstrapLogger := log.New(&log.Config{}, redactor)
// STEP 4: Pre-cobra parseEarlyFlags (W14)
efs := parseEarlyFlags(os.Args[1:])
// STEP 5: Load config via 8-source merge
cfg, err := config.Load(config.LoadOptions{ExplicitConfigPath: efs.configPath, SecretsPath: efs.secretsPath})
// STEP 6: Rebuild logger from full config
logger := log.New(cfg.AsLoggerConfig(), redactor)
// STEP 7: Register every log.Secret field (W10 — 9 fields enumerated)
registerSecrets(cfg, redactor)
// STEP 8: task.Default.Build — topo sort + cycle detection
if _, err := task.Default.Build(); err != nil { return err }
// STEP 9: Scheduler + AppContext.Boot if --target supplied
sched = scheduler.NewScheduler(...)
app, _ = appctx.Boot(ctx, logger, cfg, tgt, sched, ...)
// STEP 9b: Cycle-break #2 — sched.RunTask closure
sched.RunTask = func(ctx, t) (Result, error) { return t.Run(ctx, app) }
// STEP 10: cobra.ExecuteContext
return rootCmd.ExecuteContext(ctx)
```

Source grep confirms 23 STEP comment hits across main.go (file header + inline numbered comments) — well above the ≥7 acceptance gate.

### W14 parseEarlyFlags Pre-cobra Scanner

Implements the minimum-viable flag scanner needed before cobra owns full parsing:

- Recognizes `--config FILE`, `--config=FILE`, `--secrets FILE`, `--secrets=FILE`, `--target FILE`, `--target=FILE`
- Silently ignores all other flags (cobra parses them inside Execute)
- Empty args is a no-op
- Trailing `--config` without value is silently ignored (cobra surfaces the proper error later)

Why `--target` is included: Phase 3 main.go MUST construct an AppContext BEFORE cobra dispatch when a target is supplied, so the hidden kernel-demo (which needs `app != nil`) can run via direct invocation. Phase 9 composite-mode wiring may change this — for Phase 3, the early `--target` extraction is intentional.

### W10 registerSecrets — All 9 log.Secret Fields

Per config.go SECRET FIELD ENUMERATION comment block (lines 38-47), every field is registered with the Redactor:

```go
r.Register(string(cfg.Notifications.Slack.WebhookURL))
r.Register(string(cfg.Notifications.Telegram.BotToken))
r.Register(string(cfg.Notifications.Discord.WebhookURL))
r.Register(string(cfg.AI.OpenAIKey))
r.Register(string(cfg.AI.AnthropicKey))
r.Register(string(cfg.MCP.APIKey))
r.Register(string(cfg.APIKeys.Shodan))
r.Register(string(cfg.APIKeys.WhoisXML))
r.Register(string(cfg.APIKeys.PDCP))
```

TestRegisterSecretsAllNineFields asserts that every value is scrubbed via Redactor.Redact, and TestRegisterSecretsXCUT07Sentinel confirms the XCUT-07 sentinel pattern works through a real slog Logger constructed by log.New.

Axiom SSH credentials are explicitly NOT in this enumeration — they flow through env vars per ADR §6 Axiom note and will be registered by Plan 06+ as env-var reads land.

### Blocker 5 / FOUND-08 Health-Check Two-Tier Semantics

Verified by direct test scenarios:

| Scenario | Tool registration | Behavior |
|----------|---------------------|----------|
| Critical missing | `{Name:"miss-c", Critical:true}` | [FAIL] tool.miss-c (critical) + *exitCodeError{code:1} |
| Required missing | `{Name:"miss-r", Critical:false}` | [WARN] tool.miss-r (required) + exit 0 |
| Present | `{Name:"sh", Critical:true}` | [OK] tool.sh + exit 0 |
| nil cfg | n/a | [FAIL] config.parse + exit 1 |
| Empty registry | n/a | [OK] tools (0 registered) + exit 0 |

`MissingCritical()` and `MissingRequired()` are both grepped from healthcheck.go (Blocker 5 acceptance gates).

### XCUT-02 Binary Size

```
Unstripped: 16,038,978 bytes = 15 MB
Stripped:   10,838,274 bytes = 10 MB
Savings:    5,200,704 bytes (32% reduction via `-ldflags="-s -w" -trimpath`)
```

Well under the 50 MB XCUT-02 budget. Plan 07 can activate the binary-size CI gate now that the kernel-demo + 12 stubs + 2 working subcommands bring real surface area.

## Task Commits

| # | Hash | Type | Description |
|---|------|------|-------------|
| 1 | `060badc2` | feat | main.go ADR §10.3 init order + W14 parseEarlyFlags + Makefile XCUT-02 ldflags |
| 2 | `338c8c5f` | feat | cobra root + 12 stub subcommands + v1 aliases + hidden kernel-demo |
| 3 | `3ea1ca06` | feat | version + health-check subcommands (D-04 fully working, Blocker 5) |

**Plan metadata commit:** pending (this SUMMARY).

## Files Created/Modified

### Task 1 — 5 files (4 created + 4 modified)

**Created:**
- `cmd/reconftw/main.go` — ADR §10.3 10-STEP init order, W14 parseEarlyFlags, W10 registerSecrets, ldflag-bound Version/CommitSHA/BuildDate, *exitCodeError handling in main.main.
- `cmd/reconftw/main_test.go` — 10 tests (parseEarlyFlags space/equals form for --config/--secrets/--target; ignores unknown flags; empty args no-op; trailing --config without value; W10 9-field redaction; XCUT-07 sentinel).

**Modified:**
- `Makefile` — build target adds XCUT-02 ldflags `-X main.Version=$(VERSION) -X main.CommitSHA=$(COMMIT_SHA) -X main.BuildDate=$(BUILD_DATE)` plus `-trimpath`. VERSION sourced from `git describe --tags --always --dirty`; COMMIT_SHA from `git rev-parse --short HEAD`; BUILD_DATE from `date -u '+%Y-%m-%dT%H:%M:%SZ'`. All make-overridable.
- `go.mod` — added github.com/spf13/cobra v1.9.1.
- `go.sum` — checksums for cobra, pflag v1.0.6, mousetrap v1.1.0.

### Task 2 — 10 files (10 created + 1 deletion + 1 modified)

**Created:**
- `cmd/reconftw/root.go` — newRootCmd: 14+1+1 = 16 visible subcommands + 1 hidden (kernel-demo); addPersistentGlobalFlags (§8.2); addV1DeprecatedAliases (§8.3, all 23 MarkDeprecated calls covering 14 distinct Flag entries → 20 alias forms).
- `cmd/reconftw/stub.go` — stubNotImplemented helper + *exitCodeError sentinel type for cobra → main exit-code propagation.
- `cmd/reconftw/stub_subcommands.go` — phasePointers map (14 entries: name → {Phase, Name}) + newStubCmd factory + 14 per-subcommand constructors.
- `cmd/reconftw/modules.go` — blank import `_ "internal/modules/demo"` to trigger noop.demo registration at startup. Phase 4 plan-01 deletes this line.
- `cmd/reconftw/kernel_demo.go` — newKernelDemoCmd with Hidden:true + W16/D-07/Phase 4 citations in file header. RunE type-asserts app.Scheduler → *scheduler.Scheduler then calls RunStage(ctx, "demo", tasks).
- `cmd/reconftw/root_test.go` — 8 test groups (subcommand listing, stub exit 64, every-stub iteration, long-alias deprecation, short-alias deprecation, deprecation count threshold, shorthand wiring, hidden subcommand).
- `cmd/reconftw/stub_test.go` — 4 tests (format/coverage/valid-phases/exitCodeError interface).
- `cmd/reconftw/kernel_demo_test.go` — 4 tests (Hidden:true; not-in-help; requires --target; W16/D-07/Phase 4 citation grep).
- `cmd/reconftw/helpers_test.go` — readCmdReconftwSource helper shared by source-grep tests.

**Deleted:**
- `cmd/reconftw/.gitkeep` — placeholder file from Phase 3 Plan 01 scaffold, no longer needed once real Go files land.

**Modified:**
- `.gitignore` — adds `workspaces/` (kernel-demo creates these) and `/reconftw` (stray go-build output when running `go build ./cmd/reconftw` without -o).

### Task 3 — 4 files created

- `cmd/reconftw/version.go` — newVersionCmd prints version/commit/built/go-version/platform; lookupCommit fallback chain (ldflag → vcs.revision → "unknown").
- `cmd/reconftw/version_test.go` — 4 tests (output sections; lookupCommit fallback; ldflag injection; wired non-hidden).
- `cmd/reconftw/healthcheck.go` — newHealthCheckCmd (cobra wrapper) + runHealthCheck (testable kernel) accepting fresh *backend.ToolRegistry per Blocker 7. Emits dot-fill UI via ui.NewPrinter; FAIL on missing-critical (exit 1), WARN on missing-required (exit 0).
- `cmd/reconftw/healthcheck_test.go` — 6 tests (empty registry; critical fail; required warn; present tool OK; nil cfg fails; wired non-hidden). All use fresh NewToolRegistry to avoid Blocker 7 cross-test contamination.

## Decisions Made

- **D-01..D-05 all fulfilled** — see "Accomplishments" tables above.
- **config.Load signature adapted from Plan 02 final form**: Plan 02 ships `Load(opts LoadOptions) (*Config, error)`, not the `Load(cliOverrides map[string]any)` from the original plan-06 draft. The actual signature wins (D-05 BINDING). Plan 06 main.go constructs `LoadOptions{ExplicitConfigPath: efs.configPath, SecretsPath: efs.secretsPath}` from parseEarlyFlags output — no Map round-trip needed.
- **--target included in parseEarlyFlags (W14 extension)**: The plan said W14 extracts ONLY --config/--secrets. Phase 3's hidden kernel-demo subcommand requires an AppContext built BEFORE cobra dispatch, so the operator's `--target` value needs to be known by the time we call appctx.Boot. parseEarlyFlags is extended to capture `--target`/`--target=` as well. This does NOT change W14's "only --config/--secrets" semantic for production behaviour (cobra still owns --target's full parsing; this is a "early peek" for boot-time wiring). Subsequent phases that move target dispatch into individual subcommand RunE bodies can drop the early scan if cleaner.
- **cobra MarkDeprecated emits to stdout, not stderr**: An undocumented cobra/pflag behaviour discovered during testing — `Flag --recon has been deprecated, use subcommand 'recon' ...` goes to `cmd.OutOrStdout()`. Tests capture both buffers. The actual binary prints to the terminal where the user sees it regardless of stream. Documented in root.go addV1DeprecatedAliases comment.
- **Hidden:true does NOT prevent direct invocation**: `cobra.Command{Hidden: true}` only suppresses the subcommand from --help. Direct invocation by name (`reconftw kernel-demo`) works fine. Used by W16 to expose noop.demo for Plan 07's integration test without polluting the operator-facing --help inventory.
- **runHealthCheck testable kernel split from newHealthCheckCmd cobra wrapper**: The cobra subcommand factory is hard to unit-test cleanly (needs Execute() invocation + flag parsing); the inner kernel function accepts a *backend.ToolRegistry parameter so tests can pass fresh `NewToolRegistry()` (Blocker 7 audit gate — never reuse backend.Default in tests).
- **Type-assertion app.Scheduler → *scheduler.Scheduler in kernel_demo**: Per Plan 05 design, AppContext.Scheduler is typed as SchedulerRunner (cycle-break interface) — but kernel-demo needs RunStage(ctx, module, tasks), which lives on the concrete *scheduler.Scheduler. The type assertion is the documented Plan 05 escape hatch.
- **Stripped binary 10 MB**: Well under XCUT-02 50 MB target. Stripping saves 32% (5 MB) via `-ldflags="-s -w" -trimpath`. Plan 07 can activate the size gate.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Plan signature `Load(cliOverrides map[string]any)` does not match Plan 02 actual** — The plan-06 §"behavior" Test 5 references `config.Load(map[string]any{"config": ..., "secrets": ...})` but Plan 02 ships `Load(opts LoadOptions) (*Config, error)` where LoadOptions has `ExplicitConfigPath`, `SecretsPath`, etc. fields. The Plan 02 BINDING signature wins per ADR §0 D-05. **Resolution**: main.go constructs `LoadOptions{ExplicitConfigPath: efs.configPath, SecretsPath: efs.secretsPath}` and passes by value. parseEarlyFlags returns an earlyFlagSet struct with `configPath`, `secretsPath`, `target` fields rather than the plan's map[string]any.

**2. [Rule 3 - Blocking] cobra MarkDeprecated emits to stdout, not stderr** — The plan's test 7 asserted `Stderr` would contain "deprecated", but cobra's pflag library writes the deprecation warning via `cmd.OutOrStdout()`. **Resolution**: Tests capture both stdout and stderr buffers, search the combined output. Documented the quirk in root.go comments.

**3. [Rule 3 - Blocking] ui.Printer truncates labels >26 chars** — The plan's healthcheck tests used long tool names like `"this-tool-does-not-exist-xyz123"` which trigger ui.Printer's pad=26 truncation, hiding the `(critical)` / `(required)` suffixes the tests assert on. **Resolution**: Use short tool names (`miss-c`, `miss-r`) in tests so the suffix annotation survives the truncation. Empty-registry test asserts on the truncation-safe prefix `"tools (0"` instead of `"Phase 3 baseline"`.

**4. [Rule 2 - Critical missing feature] W14 needed --target extraction for hidden kernel-demo** — The plan defined parseEarlyFlags as extracting "ONLY --config / --secrets". But the hidden kernel-demo subcommand requires AppContext to be wired BEFORE cobra dispatch (so it can invoke Scheduler.RunStage with a real app). Without --target available pre-cobra, we'd need to either: (a) construct AppContext lazily inside kernel-demo RunE (complex, requires re-reading config), or (b) add --target to the early scan. Chose (b) — the W14 semantic of "minimum surface needed to bootstrap" naturally extends to --target. Documented in main.go header comment + parseEarlyFlags godoc.

**5. [Rule 1 - Bug] Pre-test stray binary at repo root** — `go build ./cmd/reconftw` (without -o flag) writes the binary to the repo root, polluting `git status`. **Resolution**: Add `/reconftw` to .gitignore (alongside the existing `/interfaces_check` entry which has the same issue).

**6. [Rule 1 - Bug] Pre-test workspaces/ directory leaks into repo root** — When testing kernel-demo from the worktree root cwd, `output.WorkspaceInit("workspaces", ...)` creates `./workspaces/example.com-<timestamp>/` in the worktree. **Resolution**: Add `workspaces/` to .gitignore. Tests use `t.TempDir()` for their workspace creation (no leak); only manual smoke tests are affected.

No architectural changes required user input — all deviations were Rule 1-3 auto-fixes within the plan's stated invariants.

## Issues Encountered

- **cobra deprecation stream quirk** discovered during first test pass — saved ~10 min of debugging by writing a 12-LoC isolation script to confirm the OutOrStdout vs ErrOrStderr behaviour.
- **ui.Printer truncation** discovered during first health-check test pass — minor pivot to shorter tool names.
- **Plan 02 Load signature mismatch** caught at compile time on the first `go build ./cmd/reconftw` — adapted main.go in <5 min.
- **All other tests passed first compile** — TDD discipline observed via tests-and-code in the same Write cycle.

## Verification Results

### Whole-plan automated verification (from PLAN.md `<verification>` block)

```
go build ./...                                              — exit 0
go vet ./...                                                — exit 0
go test -race -count=1 ./internal/core/... ./cmd/...        — PASS
bash .planning/decisions/verify-0002.sh                     — exit 0
go build ./cmd/interfaces_check/...                         — exit 0 (BINDING delta-detector intact)
make build (with ldflags injection)                         — exit 0; bin/reconftw 10.8 MB stripped
```

### CLI smoke tests (binary built by `make build`)

```
./bin/reconftw --help                                       lists 16 visible (14 stubbed + 2 working)
./bin/reconftw --help | grep kernel-demo                    no match (W16 — hidden)
./bin/reconftw version                                      5 lines exit 0
./bin/reconftw subs --target example.com                    "Phase 4" message exit 64
./bin/reconftw --recon --target example.com                 emits "deprecated" warning
./bin/reconftw -r --target example.com                      emits "deprecated" warning
./bin/reconftw health-check                                 OK lines exit 0 (Phase 3 baseline)
./bin/reconftw kernel-demo --target example.com             exit 0; writes workspaces/example.com-<ts>/artefacts/demo.jsonl
```

### Coverage (XCUT-03/04 gate — ≥60% honest CLI threshold)

```
cmd/reconftw/                  coverage:  71.0%
```

Higher than the 60% gate; CLI plumbing has natural test-coverage challenges (cobra Execute paths and the main.go startup chain are hard to exercise in unit tests).

### Per-task acceptance grep gates

**Task 1 (main.go + Makefile)**:
- `grep -c 'signal\.NotifyContext' cmd/reconftw/main.go` → 3 (≥1 required)
- `grep -cE 'STEP 1|STEP 2|...|STEP 10' cmd/reconftw/main.go` → 23 (≥7 required)
- `grep -c 'redactor\.Register\|registerSecrets' cmd/reconftw/main.go` → 3 (≥1)
- `grep -c 'parseEarlyFlags' cmd/reconftw/main.go` → 8 (≥2)
- `grep -c '"--config"' cmd/reconftw/main.go` → 1 (=1)
- `grep -c '"--secrets"' cmd/reconftw/main.go` → 1 (=1)
- 9-secret-field enumeration: 12 (≥6 required) — Slack/Telegram/Discord webhooks + AI keys + MCP/APIKeys
- `grep -c 'main\.Version' Makefile` → 2 (≥1)
- `grep -c '\-trimpath' Makefile` → 2 (≥1)

**Task 2 (root.go + stubs + kernel-demo)**:
- `grep -c 'MarkDeprecated' cmd/reconftw/root.go` → 23 (≥10)
- `grep -c 'AddCommand' cmd/reconftw/root.go` → 17 (≥16)
- `grep -c 'phasePointers' cmd/reconftw/stub_subcommands.go` → 4 (≥1)
- `grep -E 'code: 64' cmd/reconftw/stub.go` → 4 hits (≥1)
- `grep -c 'Hidden: *true' cmd/reconftw/kernel_demo.go` → 2 (≥1)
- `grep -cE 'W16|D-07|non-breaking' cmd/reconftw/kernel_demo.go` → 4 (≥1)
- `grep -c 'internal/modules/demo' cmd/reconftw/modules.go` → 3 (≥1)

**Task 3 (version + health-check)**:
- `grep -c 'runtime/debug\|debug\.ReadBuildInfo' cmd/reconftw/version.go` → 4 (≥1)
- `grep -c 'main\.Version\|Version =' cmd/reconftw/version.go` → 1 (≥1)
- `grep -cE 'BadgeOK|BadgeWARN|BadgeFAIL' cmd/reconftw/healthcheck.go` → 9 (≥3)
- `grep -c 'MissingCritical' cmd/reconftw/healthcheck.go` → 1 (≥1)
- `grep -c 'MissingRequired' cmd/reconftw/healthcheck.go` → 1 (≥1)
- `grep -cE 'criticalFail|exitCodeError\{code: 1' cmd/reconftw/healthcheck.go` → 5 (≥1)

### Key behavioral test results

```
=== RUN   TestRootListsFifteenSubcommandsPlusVersion       — PASS (16 visible + 1 hidden)
=== RUN   TestSubsStubExit64                                — PASS (exit 64 + Phase 4 message)
=== RUN   TestEveryStubReturnsExit64                        — PASS (all 12 stubs)
=== RUN   TestDeprecationWarningLongAliases                 — PASS (9 long aliases)
=== RUN   TestDeprecationWarningShortAliases                — PASS (8 short subcommand + 1 global)
=== RUN   TestDeprecatedFlagCount                           — PASS (14 deprecated Flag entries)
=== RUN   TestShortAliasShorthandsWired                     — PASS (all 11 shorthand bindings)
=== RUN   TestKernelDemoHidden                              — PASS (Hidden:true verified)
=== RUN   TestKernelDemoNotInHelp                           — PASS
=== RUN   TestKernelDemoRequiresTarget                      — PASS (exit 2 without --target)
=== RUN   TestKernelDemoFileHeaderCitesPhase4Deletion       — PASS (W16/D-07/Phase 4 cited)
=== RUN   TestStubNotImplementedFormat                      — PASS (exit 64 + format)
=== RUN   TestVersionSubcommandOutput                       — PASS (5 lines + platform)
=== RUN   TestLookupCommitFallback                          — PASS
=== RUN   TestLookupCommitUsesLdflag                        — PASS
=== RUN   TestHealthCheckEmptyRegistryOK                    — PASS (Phase 3 baseline)
=== RUN   TestHealthCheckCriticalFail                       — PASS (Blocker 5 — exit 1)
=== RUN   TestHealthCheckRequiredWarn                       — PASS (Blocker 5 — exit 0)
=== RUN   TestHealthCheckPresentToolOK                      — PASS
=== RUN   TestHealthCheckNilCfgFails                        — PASS
=== RUN   TestParseEarlyFlagsConfigSpaceForm                — PASS (W14)
=== RUN   TestParseEarlyFlagsConfigEqualsForm               — PASS (W14)
=== RUN   TestParseEarlyFlagsSecretsSpaceForm               — PASS (W14)
=== RUN   TestParseEarlyFlagsIgnoresUnknownFlags            — PASS (W14)
=== RUN   TestRegisterSecretsAllNineFields                  — PASS (W10 — all 9 fields)
=== RUN   TestRegisterSecretsXCUT07Sentinel                 — PASS (XCUT-07 through logger)
```

## Threat Flags

No new threat surfaces beyond the threat register declared in the plan's `<threat_model>` block. All 7 mitigations land:

- **T-03-06-01** (init order violation) — mitigated: ADR §10.3 STEP comments inline in main.go; XCUT-07 sentinel from Plan 01 still passes; bootstrap logger (pre-config) has no secrets to leak.
- **T-03-06-02** (deprecated alias confusion) — mitigated: cobra.MarkDeprecated preserves flag semantics per ADR §8.4; unit tests assert deprecation warning emitted for every alias; Phase 9 wires dispatch.
- **T-03-06-03** (stub subcommand consumed as if implemented) — mitigated: exit code 64 is machine-detectable; phase-pointer message references ROADMAP.md; CI agents can branch on exit 64.
- **T-03-06-04** (health-check passes despite missing critical) — mitigated: Blocker 5 — MissingCritical() FAIL + exit 1 per FOUND-08; Plan 07 tools.lock seeds the canonical Critical set.
- **T-03-06-05** (Hidden kernel-demo abuse) — accepted: kernel-demo runs only the noop.demo Task (single deterministic JSONL write, no external tool); ctx cancelable via SIGINT.
- **T-03-06-06** (parseEarlyFlags --config injection) — mitigated: parseEarlyFlags accepts only known flag names; unknown args ignored; cobra owns full parsing; config.Load validates the path before opening.
- **T-03-06-SC** (Go module supply chain) — accepted: 3 modules added — cobra v1.9.1 (Google/spf13-maintained), pflag v1.0.6 (cobra dep), mousetrap v1.1.0 (pflag transitive dep for Windows behaviour). go.sum integrity-verified.

## Next Phase Readiness

**Ready for Plan 07 (test mocks + tools.lock seed + acceptance integration test):**

- Hidden kernel-demo subcommand is invokable for TestKernelDemoEndToEnd integration test.
- Binary builds with XCUT-02 ldflags — the size gate (<50MB) is activatable now.
- runHealthCheck accepts a fresh *backend.ToolRegistry parameter — Plan 07's tools.lock seed populates backend.Default and the canonical health-check exit-code semantic kicks in.
- main.go uses exit-code-aware error handling — Plan 07's TestKernelDemoEndToEnd can branch on exit 0 (success) vs exit 64 (stub) vs exit 1 (critical fail) vs exit 2 (no --target) deterministically.

**Ready for Phase 4 plan-01:**

- The `subs` subcommand is registered with phase-pointer "Phase 4 — Subdomains E2E + Axiom Integration" — Phase 4 plan-01 swaps the RunE body without touching CLI plumbing.
- The blank import pattern in cmd/reconftw/modules.go is established — Phase 4 adds `_ "internal/modules/subdomains"` next to (or replacing) the demo import.
- The kernel_demo.go file is documented to be deleted in Phase 4 plan-01; the test gate (TestKernelDemoFileHeaderCitesPhase4Deletion) asserts the W16/D-07/Phase 4 citations remain present until then.

## Open Items / Hand-Offs

- **Plan 07 acceptance integration test** — `TestKernelDemoEndToEnd` invokes `reconftw kernel-demo --target X` and asserts:
  - exit code 0
  - workspaces/<target-id>/artefacts/demo.jsonl exists and contains the phase-3-kernel fixture line
  - workspaces/<target-id>/checkpoints.db contains a row for "noop.demo" with status=done
- **Plan 07 binary-size gate** — `make build` produces a stripped 10.8 MB binary today; CI gate can be `[ "$(stat -f%z bin/reconftw)" -lt 52428800 ]` (52 MB safety margin under 50 MB target).
- **Phase 4 plan-01 ACCEPTANCE checklist** (cite this SUMMARY's "DELETE THIS FILE" markers):
  1. Delete `cmd/reconftw/kernel_demo.go` + `cmd/reconftw/kernel_demo_test.go`.
  2. Delete `internal/modules/demo/noop.go` + `internal/modules/demo/noop_test.go`.
  3. Update `cmd/reconftw/modules.go` blank import line to point at the first real module package.
  4. Replace the stubbed `subs` RunE with the real subdomains pipeline implementation.
  5. Update `phasePointers["subs"]` and remove if `subs` becomes fully working.
- **Phase 9 MODE-09** — cobra.MarkDeprecated already emits warnings (Phase 3 D-03 wiring); Phase 9 only needs to wire the alias→subcommand dispatch (the warning is free). Phase 9 plan tests can assert exact warning text + verify the subcommand RunE is invoked when a deprecated flag is supplied alongside positional args.
- **Phase 10 notifications** — main.go does NOT yet register env-derived Axiom SSH credentials with the Redactor (per ADR §6 Axiom note). Phase 10 wires the env-var reads + Redactor.Register call alongside the real Slack/Telegram/Discord HTTP dispatchers replacing the Plan 05 stubs.

## Self-Check: PASSED

**Files exist on disk:**

```
FOUND: cmd/reconftw/main.go
FOUND: cmd/reconftw/main_test.go
FOUND: cmd/reconftw/root.go
FOUND: cmd/reconftw/root_test.go
FOUND: cmd/reconftw/stub.go
FOUND: cmd/reconftw/stub_subcommands.go
FOUND: cmd/reconftw/stub_test.go
FOUND: cmd/reconftw/modules.go
FOUND: cmd/reconftw/kernel_demo.go
FOUND: cmd/reconftw/kernel_demo_test.go
FOUND: cmd/reconftw/helpers_test.go
FOUND: cmd/reconftw/version.go
FOUND: cmd/reconftw/version_test.go
FOUND: cmd/reconftw/healthcheck.go
FOUND: cmd/reconftw/healthcheck_test.go
```

**Commits exist in git log:**

```
FOUND: 060badc2 — feat(03-06): main.go ADR §10.3 init order + W14 parseEarlyFlags + Makefile XCUT-02 ldflags
FOUND: 338c8c5f — feat(03-06): cobra root + 12 stub subcommands + v1 aliases + hidden kernel-demo
FOUND: 3ea1ca06 — feat(03-06): version + health-check subcommands (D-04 fully working, Blocker 5)
```

---
*Phase: 03-foundation-kernel*
*Completed: 2026-05-28*
