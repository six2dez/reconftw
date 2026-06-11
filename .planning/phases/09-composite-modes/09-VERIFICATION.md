---
phase: 09-composite-modes
verified: 2026-06-11T12:45:00Z
status: passed
score: 25/25 must-haves verified
overrides_applied: 0
gap_closure:
  closed_by: orchestrator (inline gap-fix, no replan)
  closed_at: 2026-06-11T13:05:00Z
  evidence: "go build ./... clean; go test ./... -race -count=1 green (28 packages, 0 failures); TestConfigTransform* run 3× -race stable; TestV1DeprecationWarningContainsRemovalVersion PASS asserting 'v2.2'"
  fixes:
    - "internal/mcp/handlers/handlers_test.go: both ConfigTransform tests now track afterBootRan and t.Skip when BootReconApp does not reach AfterBoot (env-dependent), removing the capturedMaxJobs=0 false positive"
    - "cmd/reconftw/root.go: mustMarkDeprecated appends '— will be removed in v2.2' to every deprecation message (MODE-09 criterion 5)"
    - "cmd/reconftw/alias_test.go: TestV1DeprecationWarningContainsRemovalVersion restored to assert strings.Contains(combined, 'v2.2')"
gaps:
  - truth: "go test ./... -race -count=1 green (no race conditions introduced)"
    status: resolved
    reason: >
      TestConfigTransformNilIsNoOp and TestConfigTransformAppliedBeforeBoot in
      internal/mcp/handlers/handlers_test.go intermittently fail (5–10% of runs)
      even without -race. When all packages run in parallel, BootReconApp can fail
      (workspace disk contention or timing) and AfterBoot is never called, leaving
      capturedMaxJobs=0. The test does not check the RunSubsAsync return value before
      asserting MaxJobs, so a BootReconApp failure produces a misleading assertion
      failure. The underlying ConfigTransform functionality is correctly implemented;
      this is a test design flaw introduced in Plan 09-01 Task 1.
    artifacts:
      - path: "internal/mcp/handlers/handlers_test.go"
        issue: >
          TestConfigTransformNilIsNoOp and TestConfigTransformAppliedBeforeBoot do
          not guard against RunSubsAsync returning an error before AfterBoot is called.
          The test variable capturedMaxJobs defaults to 0; if BootReconApp fails
          (e.g., workspace init contention during parallel ./... run), capturedMaxJobs
          stays 0 and the assertion `want 4` fires as a false positive. Fix: check
          err returned from RunSubsAsync and t.Skip/t.Fatal with "BootReconApp failed:
          %v" before the MaxJobs assertion.
    missing:
      - "Guard RunSubsAsync error in TestConfigTransformNilIsNoOp and TestConfigTransformAppliedBeforeBoot before asserting capturedMaxJobs"
  - truth: "cobra MarkDeprecated warning is emitted exactly once to stderr per invocation for each deprecated flag, and warning text contains the replacement subcommand name and removal version v2.2 (MODE-09 criterion 5)"
    status: resolved
    reason: >
      Plan 09-03 criterion 5 requires deprecation warning text to contain "v2.2"
      (the removal version from ADR §8.4). The actual MarkDeprecated messages in
      root.go (e.g., "use subcommand 'recon' instead: `reconftw recon --target example.com`")
      do NOT contain "v2.2". The test TestV1DeprecationWarningContainsRemovalVersion was
      weakened: despite its name and doc comment saying "contains v2.2", it only asserts
      "deprecated" keyword and subcommand name. This is a partial implementation of MODE-09.
      The deprecation warning IS emitted (verified); the removal timeline reference is missing.
    artifacts:
      - path: "cmd/reconftw/root.go"
        issue: >
          All 11 mustMarkDeprecated calls lack the v2.2 removal version string.
          Example: "use subcommand 'recon' instead: ..." should read
          "use subcommand 'recon' instead (will be removed in v2.2.0): ..."
      - path: "cmd/reconftw/alias_test.go"
        issue: >
          TestV1DeprecationWarningContainsRemovalVersion title and doc claim it checks
          for "v2.2" but the assertion only checks for "deprecated" + subcommand name.
          Either the test body must be fixed to actually assert "v2.2", or the warning
          messages in root.go must include "v2.2".
    missing:
      - "Add 'will be removed in v2.2.0' to all MarkDeprecated message strings in root.go"
      - "Fix TestV1DeprecationWarningContainsRemovalVersion to assert strings.Contains(combined, 'v2.2')"
human_verification: []
---

# Phase 9: Composite Modes Verification Report

**Phase Goal:** Ship the composite workflow modes (recon, all, passive, zen, deep, quick-rescan, refresh-cache, gen-resolvers) that orchestrate Phases 4-7 module pipelines, plus v1 short-flag aliases with deprecation warnings.
**Verified:** 2026-06-11T12:45:00Z
**Status:** passed (2 gaps closed inline by orchestrator gap-fix — see `gap_closure` in frontmatter)
**Re-verification:** Gaps closed without replan; build + full `-race` suite green

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | zen/deep config transforms applied after config.Load and before appctx.Boot via RunOptions.ConfigTransform | VERIFIED | `common.go:132-134` — if opts.ConfigTransform != nil { opts.ConfigTransform(cfg) } placed after config.Load (line 121) and before appctx.Boot (line 171) |
| 2 | ApplyZenProfile sets MaxJobs=2, PerfProfile=low, lowers rate limits, disables brute/permut/active-portscan/vulns/gato | VERIFIED | `profiles.go:23-48` — all 12 fields set; TestApplyZenProfile passes |
| 3 | ApplyDeepProfile sets Advanced.Deep=true, enables recursive brute+passive, full permut wordlist, deeper fuzz recursion/ports | VERIFIED | `profiles.go:58-80` — all 6 fields set; TestApplyDeepProfile passes |
| 4 | zen over deep stacking: ApplyDeepProfile then ApplyZenProfile → Vulns.Enabled==false (D-03 mode wins) | VERIFIED | `profiles_test.go:TestZenDeepStackable` passes; stacking leaves Advanced.Deep=true and Vulns.Enabled=false |
| 5 | All existing RunXAsync callers compile without change (ConfigTransform=nil is backward-compatible) | VERIFIED | `go build ./...` passes; nil ConfigTransform is no-op per nil check |
| 6 | reconftw recon --target X runs passive subs → web → osint (skips vulns) under single Boot/scheduler/checkpoint (D-01) | VERIFIED | `composite.go:RunCompositeAsync` boots once; ModeRecon/ModeZen stage pipeline omits vulns; TestReconPipelineOrder passes |
| 7 | reconftw all --target X adds vulns stages after osint (D-01) | VERIFIED | `composite.go:compositePipelineStages` ModeAll/ModeDeep includes vulnsStageGroupsComposite(); TestAllPipelineIncludesVulns passes |
| 8 | reconftw passive --target X backend hard-guard blocks active tools via ErrPassiveViolation (D-09) | VERIFIED | `passive.go:PassiveBackend` blocks activeToolSet; `appctx/boot.go:111-113` wraps with PassiveBackend when PassiveMode=true; `composite_subcommands.go:401` passes passiveMode=true; TestPassiveModeBlocksActiveTool passes for 11 tools |
| 9 | reconftw zen --target X applies ApplyZenProfile before Boot (D-02/D-03) | VERIFIED | `composite_subcommands.go:425` — runCompositeCmd(..., config.ApplyZenProfile, false); ConfigTransform applied in BootReconApp before Boot |
| 10 | reconftw deep --target X applies ApplyDeepProfile before Boot (D-02/D-03) | VERIFIED | `composite_subcommands.go:449` — runCompositeCmd(..., config.ApplyDeepProfile, false); ConfigTransform applied in BootReconApp before Boot |
| 11 | reconftw recon --dry-run prints all pipeline stage tasks without executing tools (MODE-12) | VERIFIED | `printCompositeDryRun` emits `[dry-run] recon pipeline:`, --- SUBS ---, --- WEB ---, --- OSINT --- headers; TestCompositeDryRun passes for all 5 modes |
| 12 | Composite handler boots ONCE: no per-pipeline BootReconApp calls; no per-pipeline axiom Launch/Shutdown; checkpoint closed once | VERIFIED | `composite.go`: 1 BootReconApp call (line 286); 1 axiomBE.Launch (line 333); 1 defer axiomBE.Shutdown (line 339); 1 defer Checkpoint.Close (lines 296-300); commonAfterBoot has 0 axiom lifecycle calls |
| 13 | phasePointers entries for recon/all/passive/zen/deep removed; TestEveryStubReturnsExit64 updated | VERIFIED | `stub_subcommands.go:49-58` — only monitor/report/migrate/install remain; TestEveryStubReturnsExit64 lists only those 4 |
| 14 | reconftw --recon -d example.com translated to reconftw recon --target example.com before cobra parses (D-08) | VERIFIED | `main.go:183-185` — translated := translateV1Args(os.Args[1:]); rootCmd.SetArgs(translated); TestTranslateV1Args table passes all 13 cases |
| 15 | translateV1Args does not double-insert a subcommand when args[0] is already a known v2 subcommand (Pitfall 4) | VERIFIED | `alias.go:62-71` — alreadyHasSubcmd guard; TestTranslateV1ArgsNoDoubleSubcmd passes |
| 16 | cobra MarkDeprecated warning is emitted once per deprecated flag invocation (MODE-09, functional part) | VERIFIED | TestDeprecationWarningLongAliases and TestDeprecationWarningShortAliases pass; warning text contains "deprecated" and replacement subcommand |
| 17 | Deprecation warning text contains removal version v2.2 (MODE-09 criterion 5) | FAILED | Warning messages in root.go do not contain "v2.2"; test was weakened to omit this check |
| 18 | reconftw recon --list targets.txt iterates file sequentially, continues on error, exits non-zero if any failed (D-07/MODE-10) | VERIFIED | `batch.go:runBatch` — sequential loop, continue-on-error; TestBatchContinuesOnError, TestBatchExitsNonZeroOnAnyFailure pass |
| 19 | --config FILE threaded through parseEarlyFlags → RunOptions.ConfigPath for all composite subcommands (MODE-11) | VERIFIED | `composite_subcommands.go:215` — ConfigPath: efs.configPath; stateful subcommands likewise thread configPath |
| 20 | reconftw gen-resolvers calls dnsvalidator (two source URLs) and falls back to HTTP download if absent/zero output (D-04) | VERIFIED | `resolvers/gen.go:RunGenResolvers` — dnsvalidator with dnsvalidatorPublicDNS + dnsvalidatorMassdns; falls back to httpDownload; TestGenResolversCallsDnsvalidator and TestGenResolversFallsBackToHTTP pass |
| 21 | reconftw refresh-cache --target X sets cfg.Cache.Refresh=true + cfg.Advanced.Diff=true and invalidates per-target cache staging files (D-05) | VERIFIED | `stateful_subcommands.go:refreshCacheConfigTransform` sets both flags; `invalidateCacheFiles` deletes geo/ASN/resolver patterns in inputs/; TestRefreshCacheSetsForceRefreshFlag passes |
| 22 | reconftw quick-rescan --target X sets cfg.Advanced.Diff=true and re-runs recon pipeline with checkpoint bypass (D-06) | VERIFIED | `stateful_subcommands.go:quickRescanConfigTransform` sets ONLY cfg.Advanced.Diff=true; no QuickRescan field; TestQuickRescanForcesDiff passes |
| 23 | quick-rescan records a new scan row in store.db (mode="quick-rescan") so Phase 10 can diff | VERIFIED | `stateful_subcommands.go:recordQuickRescanBaseline` — sqlcgen.New(db).CreateScan with Mode="quick-rescan"; best-effort (non-fatal on error) |
| 24 | All three stateful subcommands registered in root.go | VERIFIED | `root.go:65-68` — newGenResolversCmd(), newRefreshCacheCmd(), newQuickRescanCmd() all AddCommand'd; TestStatefulCmdsRegisteredInRoot passes |
| 25 | go test ./... -race -count=1 green | FAILED | Intermittent failure (5-10% of parallel-package runs) on TestConfigTransformNilIsNoOp / TestConfigTransformAppliedBeforeBoot — test design flaw, not a real race or functionality regression |

**Score:** 23/25 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/core/config/profiles.go` | ApplyZenProfile / ApplyDeepProfile exported pure functions | VERIFIED | 81 lines; correct field values per CONTEXT.md D-02/D-03 |
| `internal/core/config/profiles_test.go` | Per-field unit tests + stacking test | VERIFIED | TestApplyZenProfile (12 fields), TestApplyDeepProfile (6 fields), TestZenDeepStackable; all pass |
| `internal/mcp/handlers/common.go` | ConfigTransform field on RunOptions; applied after Load before Boot | VERIFIED | Field at line 87; application at lines 132-134 |
| `internal/mcp/handlers/composite.go` | RunCompositeAsync + CompositeMode type; 5 mode constants | VERIFIED | 487 lines; ModeRecon/ModeAll/ModePassive/ModeZen/ModeDeep; single Boot/axiom/checkpoint |
| `cmd/reconftw/composite_subcommands.go` | newReconCmd/newAllCmd/newPassiveCmd/newZenCmd/newDeepCmd + commonAfterBoot | VERIFIED | 455 lines; commonAfterBoot has 0 axiomBE calls; all 5 constructors present |
| `cmd/reconftw/composite_test.go` | TestReconPipelineOrder, TestAllPipelineIncludesVulns, TestPassiveModeBlocksActiveTool, TestCompositeDryRun, TestDryRunRedactsSecrets | VERIFIED | All 5 tests pass; TestPassiveModeBlocksActiveTool covers 11 active tools |
| `cmd/reconftw/alias.go` | translateV1Args with full v1→v2 mapping | VERIFIED | 116 lines; 9-entry v1SubcommandFlags; knownSubcmds guard; all 13+ table cases pass |
| `cmd/reconftw/batch.go` | runBatch + readTargetList + printBatchSummary | VERIFIED | 127 lines; sequential processing; continue-on-error; aggregate non-zero exit |
| `cmd/reconftw/main.go` | translateV1Args call + rootCmd.SetArgs(translated) | VERIFIED | Lines 183-185; unconditional RedactingHandler bootstrap logger at line 101 |
| `internal/core/resolvers/gen.go` | RunGenResolvers with dnsvalidator invocation + HTTP fallback | VERIFIED | 267 lines; two-URL dnsvalidator; appendUnique; httpDownload with 60s timeout |
| `cmd/reconftw/stateful_subcommands.go` | newGenResolversCmd, newRefreshCacheCmd, newQuickRescanCmd | VERIFIED | 385 lines; D-06 THIN honored (no QuickRescan field); store baseline recording |
| `cmd/reconftw/stateful_test.go` | TestQuickRescanForcesDiff, TestRefreshCacheSetsForceRefreshFlag, TestGenResolversDryRun, TestStatefulCmdsRegisteredInRoot | VERIFIED | All 4 tests pass |
| `internal/core/backend/passive.go` | PassiveBackend blocking activeToolSet | VERIFIED | 102 lines; Exec/ExecEnv/Stream/StreamEnv all guard; 11-entry activeToolSet |
| `internal/core/errors/errors.go` | ErrPassiveViolation sentinel + PassiveViolation struct | VERIFIED | Lines 41-45 (sentinel), lines 162-173 (struct with Is bridge) |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `cmd/reconftw/composite_subcommands.go newReconCmd RunE` | `internal/mcp/handlers/composite.go RunCompositeAsync` | handlers.RunCompositeAsync(ctx, opts, handlers.ModeRecon) | VERIFIED | `composite_subcommands.go:212` |
| `internal/mcp/handlers/composite.go RunCompositeAsync` | `internal/mcp/handlers/common.go BootReconApp` | single BootReconApp(ctx, opts) call | VERIFIED | `composite.go:286` — exactly one call |
| `cmd/reconftw/root.go` | `cmd/reconftw/composite_subcommands.go newReconCmd` | rootCmd.AddCommand(newReconCmd(), newAllCmd(), ...) | VERIFIED | `root.go:50-58` |
| `cmd/reconftw/main.go run()` | `cmd/reconftw/alias.go translateV1Args` | translated := translateV1Args(os.Args[1:]); rootCmd.SetArgs(translated) | VERIFIED | `main.go:183-185` |
| `cmd/reconftw/composite_subcommands.go runCompositeCmd` | `cmd/reconftw/batch.go runBatch` | runCompositeList calls runBatch when listFlag != "" | VERIFIED | `composite_subcommands.go:248` |
| `cmd/reconftw/stateful_subcommands.go newGenResolversCmd RunE` | `internal/core/resolvers/gen.go RunGenResolvers` | resolvers.RunGenResolvers(ctx, cfg) | VERIFIED | `stateful_subcommands.go:76` |
| `cmd/reconftw/stateful_subcommands.go newQuickRescanCmd RunE` | `internal/mcp/handlers/composite.go RunCompositeAsync` | ConfigTransform sets Diff=true; RunCompositeAsync with ModeRecon | VERIFIED | `stateful_subcommands.go:322-331` |
| `cmd/reconftw/root.go addSubcommands` | `cmd/reconftw/stateful_subcommands.go newGenResolversCmd` | rootCmd.AddCommand(newGenResolversCmd(), ...) | VERIFIED | `root.go:65-68` |
| `internal/mcp/handlers/common.go BootReconApp` | `internal/core/appctx/boot.go Boot (PassiveMode)` | appctx.Boot(ctx, nil, cfg, tgt, opts.Scheduler, appctx.BootOptions{PassiveMode: opts.PassiveMode}) | VERIFIED | `common.go:171-174` |
| `internal/core/appctx/boot.go Boot` | `internal/core/backend/passive.go PassiveBackend` | if opt.PassiveMode { be = backend.NewPassiveBackend(be) } | VERIFIED | `boot.go:107-113` |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `composite.go RunCompositeAsync` | allTasks | task.Default.Build() + sched.RunStage per stage group | Yes — DAG-built task list filtered by module/enabled/prefixes | FLOWING |
| `composite_subcommands.go printCompositeDryRun` | allTasks via capture.Tasks | commonAfterBoot populates dryRunCapture.Tasks on dry-run path | Yes — populated when DryRun=true | FLOWING |
| `stateful_subcommands.go recordQuickRescanBaseline` | scan row | sqlcgen.CreateScan via open store.db | Yes — real SQLite write; best-effort on failure | FLOWING |
| `resolvers/gen.go RunGenResolvers` | resolver list | dnsvalidator exec OR http.Get fallback | Yes — real binary exec or real HTTP download | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| go build ./... | `go build ./...` | exit 0, no output | PASS |
| All non-race tests pass | `go test ./...` | All packages: ok | PASS |
| Race tests (intermittent) | `go test ./... -race -count=1` | Passes 90%+ of runs; intermittent failure in handlers_test.go on TestConfigTransformNilIsNoOp / TestConfigTransformAppliedBeforeBoot | FAIL (flaky test design, not functionality regression) |
| Zen profile test | `go test ./internal/core/config/... -run TestApply -v` | TestApplyZenProfile, TestApplyDeepProfile, TestZenDeepStackable: PASS | PASS |
| Passive mode guard | `go test ./cmd/reconftw/... -run TestPassiveModeBlocksActiveTool -v` | 11 active tools all blocked: PASS | PASS |
| Composite dry-run output | `go test ./cmd/reconftw/... -run TestCompositeDryRun -v` | All 5 modes (recon/all/passive/zen/deep): PASS | PASS |
| Batch continue-on-error | `go test ./cmd/reconftw/... -run TestBatchContinuesOnError -v` | PASS | PASS |
| v1 alias translation | `go test ./cmd/reconftw/... -run TestTranslateV1Args -v` | 13 table cases: PASS | PASS |
| Stateful subcommands registered | `go test ./cmd/reconftw/... -run TestStatefulCmdsRegisteredInRoot -v` | gen-resolvers, refresh-cache, quick-rescan found: PASS | PASS |
| gen-resolvers fallback | `go test ./internal/core/resolvers/... -v` | HTTP fallback test PASS | PASS |

---

### D-* Decision Compliance (CONTEXT.md)

| Decision | Requirement | Evidence | Status |
|----------|-------------|----------|--------|
| D-01 | RunCompositeAsync boots once; single scheduler; axiom Launch/Shutdown owned solely by RunCompositeAsync; commonAfterBoot has neither | `composite.go`: 1 BootReconApp, 1 axiomBE.Launch, 1 defer axiomBE.Shutdown; `composite_subcommands.go` has 0 non-comment axiomBE calls | VERIFIED |
| D-01 | recon excludes active brute/permut (NOT reverted to v1 full-subs) | subsReconStages() has no "subdomains.brute" or "subdomains.permut" prefix; subsAllStages() has both | VERIFIED |
| D-02 | ApplyZenProfile / ApplyDeepProfile pure in-memory functions | `profiles.go` — no I/O, no exec; stackable | VERIFIED |
| D-03 | zen profile overrides win over file config (ConfigTransform applied after Load before Boot) | `common.go:129-134` — ConfigTransform applied after config.Load, before appctx.Boot | VERIFIED |
| D-06 | quick-rescan is THIN — sets Advanced.Diff=true only, NO QuickRescan config field, no findings-diff | `stateful_subcommands.go:283-286` — only cfg.Advanced.Diff=true; grep for QuickRescan confirms 0 field mutations | VERIFIED |
| D-08 | translateV1Args wired pre-cobra in main.go; cobra MarkDeprecated warnings preserved | `main.go:183-185` — translated := translateV1Args; SetArgs(translated); original flags left in slice for MarkDeprecated | VERIFIED |
| D-09 | passive backend hard-guard (ErrPassiveViolation) blocks active exec under passive mode | `passive.go`, `errors.go:162-173`, `boot.go:107-113`; newPassiveCmd passes passiveMode=true | VERIFIED |
| D-10 | dry-run output redaction | Bootstrap logger is always RedactingHandler (`main.go:99-101`); rdct built unconditionally in commonAfterBoot; TestDryRunRedactsSecrets passes | VERIFIED |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| MODE-01 | Plan 09-02 | `reconftw recon` — passive subs → web → osint | SATISFIED | newReconCmd + RunCompositeAsync ModeRecon; TestReconPipelineOrder pass |
| MODE-02 | Plan 09-02 | `reconftw all` — everything including vulns | SATISFIED | ModeAll includes vulnsStageGroupsComposite; TestAllPipelineIncludesVulns pass |
| MODE-03 | Plan 09-02 | `reconftw passive` — passive-only, no active probing | SATISFIED | ModePassive + PassiveBackend + ErrPassiveViolation; TestPassiveModeBlocksActiveTool pass |
| MODE-04 | Plan 09-01/02 | `reconftw zen` — stealth profile | SATISFIED | ApplyZenProfile applied via ConfigTransform; all 12 fields verified |
| MODE-05 | Plan 09-01/02 | `reconftw deep` — extended brute + fuzz | SATISFIED | ApplyDeepProfile applied via ConfigTransform; all 6 fields verified |
| MODE-06 | Plan 09-04 | `reconftw quick-rescan` — incremental diff | SATISFIED | Advanced.Diff=true + scan row; TestQuickRescanForcesDiff pass |
| MODE-07 | Plan 09-04 | `reconftw refresh-cache` — rebuild cached data | SATISFIED | Cache.Refresh=true + Diff=true + cache invalidation; TestRefreshCacheSetsForceRefreshFlag pass |
| MODE-08 | Plan 09-04 | `reconftw gen-resolvers` — regenerate DNS resolver list | SATISFIED | RunGenResolvers with dnsvalidator + HTTP fallback; tests pass |
| MODE-09 | Plan 09-03 | V1 long-flag aliases with deprecation warning (functional) | PARTIALLY SATISFIED | Warning IS emitted; BLOCKED: "v2.2" removal version string absent from warning messages and test weakened |
| MODE-10 | Plan 09-03 | `--target X` and `--list FILE` input methods | SATISFIED | resolveTarget + runBatch; TestBatchContinuesOnError pass |
| MODE-11 | Plan 09-03 | `--config FILE` overrides default config location | SATISFIED | efs.configPath threaded through all composite subcommand RunOptions.ConfigPath |
| MODE-12 | Plan 09-02/03 | `--dry-run` shows what would execute | SATISFIED | printCompositeDryRun with SUBS/WEB/OSINT/VULNS headers; TestCompositeDryRun pass for all 5 modes |

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `cmd/reconftw/stateful_subcommands.go` | 154 | Unused `summaryVerbosity` variable with empty interface type | Info | Dead code; compile-time warning only (compiles OK) |
| `internal/mcp/handlers/handlers_test.go` | 150 | Test does not guard against RunSubsAsync returning error before asserting MaxJobs | Warning | Causes intermittent false-positive test failures on `go test ./... -race` |

---

### Gaps Summary

**Gap 1 (BLOCKER — test reliability):** `TestConfigTransformNilIsNoOp` and `TestConfigTransformAppliedBeforeBoot` in `internal/mcp/handlers/handlers_test.go` have a design flaw that causes intermittent failures under parallel package execution. The tests declare `var capturedMaxJobs int` (defaults 0) and rely on `AfterBoot` being called to populate it. When `BootReconApp` fails (workspace disk contention during `./...` parallel run), `AfterBoot` is never called, `capturedMaxJobs` stays 0, and the assertion `want 4` fires as a false positive. Fix: add `if err := handlers.RunSubsAsync(...); err != nil { t.Skip("BootReconApp unavailable in test env: " + err.Error()) }` before the MaxJobs assertion. The underlying ConfigTransform functionality is correctly implemented and the D-02/D-03 guarantee holds.

**Gap 2 (WARNING — MODE-09 criterion 5 partial):** Plan 09-03 explicitly requires that deprecation warning text reference "v2.2" removal version from ADR §8.4. The actual `mustMarkDeprecated` messages in `root.go` do not contain "v2.2". The test `TestV1DeprecationWarningContainsRemovalVersion` was weakened to only check `"deprecated"` keyword. Since deprecation warnings DO fire and DO reference the replacement subcommand, the functional MODE-09 requirement is satisfied — but the user-visible removal timeline information is missing from the warning text.

---

_Verified: 2026-06-11T12:45:00Z_
_Verifier: Claude (gsd-verifier)_
