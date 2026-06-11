# Phase 9: Composite Modes - Context

**Gathered:** 2026-06-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire the composite workflow subcommands that **orchestrate the already-ported
Phase 4-7 module pipelines** — plus dispatch the v1 deprecated flag aliases and
finish the universal CLI surface. This phase composes existing handlers; it
introduces **no new recon capabilities**.

**In scope (MODE-01…MODE-12):**
- Composite modes: `recon`, `all`, `passive`, `zen`, `deep` (currently stubbed at exit 64)
- Stateful modes: `quick-rescan` (thin), `refresh-cache` (full), `gen-resolvers` (full)
- V1 deprecated flag dispatch: `--recon`/`--all`/`--passive`/`--subdomains`/`--web`/`--vulns`/`--osint`
  long flags + `-r`/`-s`/`-p`/`-a`/`-w`/`-n`/`-z`/`-y` short flags + `-d`/`-l`/`-v` globals,
  each translated to the equivalent v2 subcommand invocation (warning still emitted)
- Universal surface: `--target X` (single), `--list FILE` (batch), `--config FILE`, `--dry-run`

**Composite pipeline definitions (ALREADY LOCKED — carried forward, not re-decided):**
These are fixed by ADR 0002 §8.1 and the stub short-descriptions in
`cmd/reconftw/stub_subcommands.go`:
- `recon`   = passive subs → web probe → web analysis → OSINT (**skips vulns**)
- `all`     = recon + active subs + brute + permut + **vulns**
- `passive` = passive-only sources, **no active probing of the target**
- `zen`     = minimal-noise: passive + safe probes (stealth profile)
- `deep`    = all + recursive subdomain enum + advanced/extended fuzz & permutations

**Out of scope (defer to Phase 10):** the monitor loop, incremental re-run engine,
findings-diff computation, and the full reporting suite. `quick-rescan`'s
"new artefacts only" diff REPORTING depends on the Phase 10 diff engine (see Deferred).

</domain>

<decisions>
## Implementation Decisions

### Composite orchestration model
- **D-01:** **Boot-once composite handler.** Refactor each existing `RunXAsync`
  (`internal/mcp/handlers/{subs,web,vulns,osint}.go`) into a `Boot` step + a
  reusable **"run-stages-on-an-already-booted-app"** seam. A new composite handler
  (e.g. `RunReconAsync`/`RunCompositeAsync`) boots **ONCE** and runs the stage
  groups (subs → web → osint, +vulns for `all`) under a **single** AppContext,
  **single** scheduler (so `PARALLEL_MAX_JOBS` is honored across the whole run,
  not reset per sub-pipeline), single workspace, single checkpoint timeline, and a
  **unified end-of-run summary**. Chosen over sequentially re-calling each
  `RunXAsync` (which would re-load config N×, create a fresh scheduler per pipeline,
  and emit N separate summaries).
- **Constraint for planner:** the stage-execution logic currently inlined in each
  `runXCmd`/`RunXAsync` (the `afterBoot` progress wiring + per-stage `RunStage`
  loop) must be extracted so it runs against a pre-booted `AppBoot`. Preserve each
  pipeline's existing stage ordering and best_effort policy verbatim
  (subs: 5 stages; web: best_effort waves D-W12; vulns: best_effort D-V7;
  osint: github-repos pre-stage → main stage, D-O10).

### zen / deep config derivation
- **D-02:** **In-memory override functions**, applied after config load and
  before `Boot`: `applyZenProfile(cfg)` lowers rate limits + sets opsec/stealth
  flags + `perf_profile=low` + disables noisy active sources; `applyDeepProfile(cfg)`
  sets `Advanced.Deep=true` and raises `DeepLimit`/`DeepLimit2`/permutation caps.
  Pure, composable (deep+zen stack cleanly), unit-testable; **no new TOML preset
  surface** added to the loader. Chosen over named TOML preset layers and over a
  PerfProfile-only mapping (the latter under-delivers MODE-04 because stealth ≠
  just low throughput).
- **D-03:** **Mode overrides win over file config.** zen/deep transforms layer
  **above** the resolved file config — `--zen` forces stealth regardless of an
  explicit high `rate_limit` in the user's `reconftw.toml`. Stealth is a
  guarantee, not a default. (Only an explicit per-invocation CLI flag for a
  specific knob, if one exists, may override the mode.)

### Stateful modes scope
- **D-04:** **`gen-resolvers` — full.** Standalone (no target): run `dnsvalidator`
  to regenerate the DNS resolver list, mirroring v1 `resolvers_update`
  (`modules/axiom.sh`). Self-contained.
- **D-05:** **`refresh-cache` — full.** Invalidate + rebuild the DNS/ASN/geo cached
  data for a target. Self-contained within Phase 9 (does not need the diff engine).
- **D-06:** **`quick-rescan` — thin.** Ships as a composite that re-runs `recon`
  with **checkpoint-skip / force-refresh** semantics on changed inputs. The
  "report new artefacts only" findings-**diff** behavior **defers to Phase 10's
  diff engine** — Phase 9 does NOT build a second diff implementation. (Cross-phase
  dependency — see Deferred.)

### Batch + v1 alias dispatch + passive guarantee
- **D-07:** **`--list` batch = sequential, isolated workspace per target,
  continue-on-error.** Process targets one at a time (each gets
  `workspaces/<target>/` with its own Boot + scheduler per D-01); a per-target
  failure logs and the batch continues; the process exits non-zero if **any**
  target failed, with a per-target summary table at the end. No cross-target
  concurrency (consistent with the single-operator design constraint).
- **D-08:** **V1 alias dispatch = pre-cobra arg translation.** Extend the existing
  pre-cobra `parseEarlyFlags` layer (`cmd/reconftw/`) to **rewrite** deprecated
  forms into v2 invocations BEFORE cobra parses: `--recon -d X` → `recon --target X`;
  `-d`→`--target`, `-l`→`--list`, `-v`→`--axiom`; short subcommand flags
  (`-r`/`-s`/`-p`/`-a`/`-w`/`-n`/`-z`/`-y`) → their subcommand. Cobra's existing
  `MarkDeprecated` still emits the one-time stderr warning (don't remove it). This
  finishes the dispatch that `root.go:addV1DeprecatedAliases` explicitly left as
  "Phase 9 wires the dispatch".
- **D-09:** **Passive = backend-level hard-guard, not composition alone.** In
  addition to selecting passive-only task subsets, install a guard (mode flag
  threaded to the backend) that **hard-blocks any active/network exec against the
  target** while `mode=passive`. This makes the success-criteria network-test
  provably pass and prevents a misclassified task from silently probing the target.

### XCUT-07 redaction on non-live-UI paths (folded todo)
- **D-10:** Phase 9 **guarantees secret redaction on the `--dry-run` / `--quiet` /
  piped paths.** `--dry-run` prints subprocess invocations whose args can contain
  secrets; the L2 logger redactor must not be inert on these paths. Build the
  redacting handler **unconditionally** in `Boot` (wrap whatever sink is chosen —
  live UI, plain stderr, or file) so `register_secret` works on every output path,
  and add a test asserting a registered secret is scrubbed on the non-liveUI path.

### Claude's Discretion
- Exact name/signature of the extracted stage-runner seam and composite handler.
- Exact set of cfg fields each of `applyZenProfile`/`applyDeepProfile` touches
  (research v1 stealth/deep presets + current config defaults to pick the list).
- Composite unified-summary format and how the per-stage progress UI composes
  across pipelines.
- `refresh-cache` cache-key/storage mechanism and which cache entries it covers.
- Per-target batch summary table format and exit-code aggregation details.

### Folded Todos
- **`xcut07-l2-redactor-noop-noninteractive`** (`.planning/todos/pending/`) —
  Problem: the L2 logger redactor (`registerSecret`) is a silent no-op whenever
  `Boot` falls back to plain `slog.Default()` (piped/`--quiet`/`--dry-run`/file
  paths), so registered secrets aren't scrubbed from log lines. Fits Phase 9
  because composite `--dry-run` prints tool invocations that can carry secrets in
  args (XCUT-07). Captured as D-10.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Architecture & CLI contract
- `.planning/decisions/0002-architecture.md` §8 (§8.1 subcommand inventory,
  §8.2 persistent global flags, §8.3 v1 alias deprecation pattern, §8.4 removal
  timeline v2.2.0) — the BINDING CLI surface contract this phase completes.
- `.planning/phases/03-foundation-kernel/03-CONTEXT.md` — D-01 (all 15 subcommands
  visible), D-02 (stub exit 64), D-03 (alias warnings) — the scaffolding Phase 9 replaces.

### Existing handlers + CLI plumbing (the code to refactor)
- `cmd/reconftw/root.go` — root command tree, `addPersistentGlobalFlags`,
  `addV1DeprecatedAliases` (note the inline comment marking Phase 9 dispatch work).
- `cmd/reconftw/stub_subcommands.go` — stubbed `recon`/`all`/`passive`/`zen`/`deep`
  (+ the real `subs`/`web`/`vulns`/`osint` `runXCmd` bodies + dry-run printers to mirror).
- `internal/mcp/handlers/common.go` — `RunOptions`, `AppBoot`, `BootReconApp`
  (the seam to split into boot + run-stages).
- `internal/mcp/handlers/{subs,web,vulns,osint}.go` — `RunXAsync` stage loops to extract.

### Prior-phase pipeline decisions (per-pipeline stage order/policy to preserve)
- `.planning/phases/04-subdomains-e2e-axiom-integration/04-CONTEXT.md` — subs stages + axiom failover.
- `.planning/phases/05-web-pipeline-e2e/05-CONTEXT.md` — web best_effort waves (D-W12).
- `.planning/phases/06-vulnerability-scanning-e2e/06-CONTEXT.md` — vulns best_effort (D-V7), master gate.
- `.planning/phases/07-osint-e2e/07-CONTEXT.md` — osint D-O1/D-O8/D-O9/D-O10 ordering.

### Stateful-mode v1 parity
- `modules/axiom.sh` (`resolvers_update`) — gen-resolvers parity reference (dnsvalidator).
- `modules/modes.sh` (`recon`, `all`, `zen_menu`) + `reconftw.sh` (`--zen`/`--deep` handling) —
  v1 composite/stealth/deep behavior to inform the override-function field lists.

### Folded todo
- `.planning/todos/pending/xcut07-l2-redactor-noop-noninteractive.md` — XCUT-07 fix direction (D-10).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `handlers.BootReconApp` + `RunOptions`/`AppBoot` (`internal/mcp/handlers/common.go`):
  the single boot path shared by CLI + MCP. Splitting it into boot vs run-stages is
  the core enabler for D-01 and keeps MCP-02 (CLI/MCP same code path) intact.
- The four `runXCmd` bodies in `stub_subcommands.go` already share an identical
  `afterBoot` shape (scheduler-limits update, dry-run capture, run.log routing,
  axiom launch/shutdown, per-task progress wiring) — this is the duplication the
  composite refactor should consolidate.
- Per-pipeline `printXDryRun` + `printXSummary` helpers exist and can be composed
  for the unified composite dry-run / summary.
- `config.PerfProfile` (low/balanced/max), `config.Advanced.Deep/DeepLimit/DeepLimit2`
  already exist — zen/deep transforms build on these, no schema additions needed for the core knobs.

### Established Patterns
- **Per-scan scheduler, shared Limiter** (memory: scheduler per-scan landmine):
  `scheduler.Scheduler` holds per-scan mutable fields (RunTask/Checkpoint/Hash) —
  NEVER share one across concurrent sessions. The boot-once composite owns ONE
  per-run scheduler for the whole composite; the global ceiling stays enforced by
  the shared `Limiter`. Batch (D-07) is sequential, so each target's scheduler is
  independent.
- Stage spec pattern: `{name, prefixes}` + `filterByModuleAndEnabled(tasks, module, cfg, prefixes)`
  drives both live execution and dry-run printing — reuse for composite stage groups.
- v1-alias warnings via `cobra.MarkDeprecated` are already wired; D-08 only adds the
  arg-rewrite, it must NOT remove the warning emission.

### Integration Points
- **Axiom failover + gato kill-switch (composite-only hazard):** per the folded
  todo's related-info, env-requiring `gato` runs increment the Failover kill-switch
  counter — this "matters only in composite modes." When `recon`/`all` run OSINT
  with `--axiom`, a gato auth failure could trip axiom failover for the rest of the
  composite. Planner/researcher should verify the composite doesn't let one OSINT
  tool's env failure disable axiom for subs/web stages unintentionally.
- `internal/store` (state.db, `scan_observation` tables) is the baseline store
  `quick-rescan` will eventually diff against — Phase 9 quick-rescan only force-refreshes;
  Phase 10 consumes the store for the actual diff.

</code_context>

<specifics>
## Specific Ideas

- The composite pipeline definitions are taken verbatim from the existing stub
  short-descriptions and ADR 0002 §8.1 — recon deliberately **excludes** active
  subdomain brute/permut (that lives in `all`/`deep`), a conscious v2 redefinition
  vs v1's `recon` which ran full subs. Do not "fix" this back to v1 behavior.
- `--zen` means "be quiet, period" — stealth is enforced over user config (D-03).

</specifics>

<deferred>
## Deferred Ideas

- **Findings-diff engine / "new artefacts only" reporting** → Phase 10
  (MON-*/REPORT-*). `quick-rescan` (D-06) re-runs with force-refresh now; the diff
  computation + delta reporting is a Phase 10 dependency. Phase 10 MUST reuse the
  store baseline (`internal/store` scan_observation) rather than inventing a parallel one.
- **Monitor loop / incremental re-run engine** → Phase 10 (explicitly out of scope here).

### Reviewed Todos (not folded)
None — only the one matched todo (`xcut07-l2-redactor-noop-noninteractive`) was
surfaced, and it was folded (D-10).

</deferred>

---

*Phase: 9-Composite Modes*
*Context gathered: 2026-06-11*
