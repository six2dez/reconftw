# Phase 2: Architecture v2 Design - Context

**Gathered:** 2026-05-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Lock every contract the rest of v2.0 depends on — TOML config schema, output tree layout, interfaces (Task / Backend / AppContext), error class hierarchy, CLI surface, test ring policy, failure-isolation policy, logging policy — in a signed Architecture Decision Record at `.planning/decisions/0002-architecture-v2.md`. Sign-off ratifies the contracts that Phase 3 (Foundation Kernel) and every subsequent phase will build against. After this phase, the design is binding: changes require an inline amendment block.

**What's in scope (ARCH-01 .. ARCH-12):** TOML schema (full v1 parity), output tree shape + compat-symlink layer, `Task` / `Backend` / `AppContext` interface signatures, 7-class error hierarchy, `failure_policy` model, CLI subcommand surface + deprecated v1 aliases, 4-ring test policy, logging policy with type-level secret tagging.

**What's NOT in this phase** (belongs elsewhere):
- Foundation scaffolding — kernel implementation (Phase 3)
- Module ports — subdomains / web / vulns / osint pipelines (Phase 4-7)
- Installer / migrator implementation (Phase 11)
- Cutover criteria + compat-symlink deletion timeline (Phase 12)

</domain>

<decisions>
## Implementation Decisions

### Doc Shape & Length

- **D-01:** **Single mega-ADR** — everything in `.planning/decisions/0002-architecture-v2.md`. One file = one source of truth. Phase 3+ implementers read ONE doc to know the v2 contracts. Expected length: ~80-150 pages including Go snippets, TOML samples, and diagrams.
- **D-02:** **Full Go snippets + TOML samples for every contract section.** Each interface section has a working `type X interface { ... }` block with godoc-style comments; each TOML section has a sample with comments; the error catalog has a minimal Go example of each error type. Phase 3 can copy-paste-adapt directly. Rationale: Phase 3 builds ~5× faster with concrete starting points; spec ambiguity is the dominant risk for an architecture handoff between phases.
- **D-03:** **Mermaid + ASCII diagrams.** Mermaid for top-level diagrams (System Overview, AppContext composition, Task→Scheduler→Backend→Tool request flow). ASCII art for inline detail (output tree layout, TOML precedence stack, scheduler throttling diagram). Rationale: GitHub renders Mermaid natively; ASCII works in any pager/text viewer.
- **D-04:** **TL;DR + glossary + reading order at the top of the doc.** Top of ADR has: (1) 1-paragraph TL;DR of every locked decision, (2) glossary of new terms (`AppContext`, `Backend`, `Task`, `Tool`, `failure_policy`, `Secret`, `ToolError`, etc.) with one-line definitions, (3) suggested reading order ("if implementing Phase 3, read §2-4 first"). Rationale: makes the doc usable for someone who joins the project months later; v2.0 is a 12-18 month milestone, future-self orientation is real.

### Contracts Locking Tier

- **D-05:** **Binding** — once `0002-architecture-v2.md` is signed, interface signatures (Task / Backend / AppContext) and the error class hierarchy are FIXED. Phase 3+ deviation requires a formal ADR amendment. Rationale: Phase 4-12 plans can safely cite exact signatures from the ADR without waiting for Phase 3 SUMMARY.md; without binding signatures, every downstream phase becomes blocked on Phase 3 completion.
- **D-06:** **Inline amendment block mechanism.** Amendments append to `0002-architecture-v2.md` itself (same file, same ADR number) with `Amended: 2026-XX-XX | Section: §N | Reason: …` header. Git history is the audit trail. NO new ADR file per amendment. Rationale: "what does Task look like NOW" must be answerable by reading one file; per-amendment ADRs fragment the truth.
- **D-07:** **Breaking changes only trigger the amendment process.** Amendment REQUIRED for: renaming a method, changing a method signature, removing a field, changing a field's type, redefining error semantics. Amendment NOT required for: adding fields to AppContext, adding new methods (non-breaking additions), adding new error types, tightening internal validation. Rationale: minimize paper-trail friction for Phase 3 growth; preserve audit trail only where it matters.
- **D-08:** **Amendment governance matches the original sign-off ceremony.** If signing the original ADR is solo same-day (D-13), amendments are solo same-day. Consistent rule: "changing the ADR uses the same gate as signing it".

### TOML Schema Scope

- **D-09:** **All ~323 v1 reconftw.cfg flags covered 1:1** — every v1 flag has a documented TOML equivalent. Migrator does strict 1:1 mapping. Rationale: zero migration surprises for existing users; this is a recon framework with a real-user install base, and silent flag drops would erode trust. Trade-off accepted: schema gets ~80 nested sections; doc length grows; some niche v1 flags still get a TOML home.
- **D-10:** **v2-native hierarchy PLUS `[legacy]` v1-name aliases.** Schema groups keys by v2 domain (`[subdomains.passive]`, `[web.fuzz]`, `[axiom]`, `[notifications.slack]`, `[advanced.tools.<tool>]`, etc.). Each v1 flag is reachable via the v2-natural location AND via a `[legacy]` table using the original `UPPER_CASE` name (e.g., `legacy.HTTPX_RATELIMIT`). Migrator emits the v2-natural form; aliases stay readable for users who copy-paste old configs. Rationale: clean schema for new users + soft landing for v1 muscle memory.
- **D-11:** **Untranslatable v1 flags: drop with migrator warning.** v1 flags that have no v2 analog (bash-specific globals like `AVAILABLE_CORES`, BSD-vs-GNU coreutils toggles) are NOT in the schema. Migrator detects them in user's v1 cfg, emits a `MIGRATION-WARNINGS.md` entry per dropped flag with the v2 equivalent (e.g., "AVAILABLE_CORES dropped — v2 auto-detects via runtime.NumCPU(); no user action needed."). Rationale: clean schema + paper trail for users.
- **D-12:** **Lock per-key validation rules in Phase 2.** Every key in the schema has its validation rules documented in the ADR: type, range, regex pattern (for paths, URLs, rate limits), required/optional, default value, mutually-exclusive groups. Phase 3 config loader IMPLEMENTS the rules, does NOT invent them. Adds ~10-15 pages to the ADR; Phase 3 has zero ambiguity. Rationale: validation rules are part of the CONTRACT, not the implementation; they affect security (path traversal, URL scheme allowlists, DoS-prevention rate caps) and must be locked alongside the schema.

### Sign-off Ceremony

- **D-13:** **Solo same-day sign-off (same as Phase 1 / D-02 of ADR 0001).** Maintainer writes the ADR, signs same day, commits to `rewrite/v2`. No community pre-review gate. Rationale: single-maintainer project; community review adds 1-2 weeks bikeshed risk; the design is largely derived from `.planning/research/ARCHITECTURE.md` which is the synthesized audit trail; amendments (D-05–D-08) provide a corrective path if the design proves wrong in practice.
- **D-14:** **Pre-sign verification gate.** Before flipping Status from `Proposed` to `Accepted`, executor runs a programmatic check: (a) every ARCH-01..ARCH-12 requirement maps to a populated section in the ADR (grep validation), (b) all TOML sample blocks parse as valid TOML, (c) all Go interface snippets compile (`gofmt -d` clean + standalone build of a generated `interfaces_check/main.go` that imports them), (d) the glossary has an entry for every new term used in interface signatures. Adds ~5 minutes to the ceremony; catches docs-completeness bugs cheaply before sign-off locks the contracts.
- **D-15:** **ADR file location: `.planning/decisions/0002-architecture-v2.md`.** Same convention as Phase 1 (`0001-language.md`). Future ADRs follow the same pattern (`0003-...`, etc.). The `.planning/decisions/` directory becomes the canonical ADR index. NO docs site mirror in Phase 2 scope (deferred — Phase 11 packaging may add one).
- **D-16:** **Sign-off triggers STATE.md + PROJECT.md updates only.** No collapse of `.planning/research/*` files (the language collapse already happened in Phase 1 D-03; architecture research stays as broader context that the ADR cites but doesn't supersede). STATE.md updates Phase 2 status to Complete and records the ADR signature; PROJECT.md adds a Key Decisions row ("2026-XX-XX — v2.0 architecture locked: ADR 0002"). Rationale: the ADR is the source of truth for the contracts; the research files remain the source of truth for the broader synthesized rationale (deeper than the ADR records).

### Claude's Discretion (defer to researcher + planner)

These gray areas were NOT discussed in detail — planner/researcher resolve with sensible defaults grounded in REQUIREMENTS.md ARCH-01 → ARCH-12 and the research files:

- **Compat-symlink fidelity** — Whether the ADR specifies file-by-file mapping for every `Recon/<domain>/X.txt` → `workspaces/<id>/Y.jsonl`, or specifies the principle + 3-5 representative examples. Researcher surfaces the v1 file inventory; planner picks fidelity level based on output-tree complexity surfaced by the research.
- **MCP contract pre-locking** — Whether Phase 2 ADR locks the `Backend.Stream()` shape that MCP (Phase 8) will multiplex, or defers entirely to Phase 8. Researcher should surface the MCP requirements early; planner decides based on cross-phase coupling.
- **AppContext composition style** — Single big struct passed everywhere vs smaller composable contexts (`RunCtx`, `ToolCtx`, `SchedCtx`). Researcher surfaces patterns from `research/ARCHITECTURE.md §2-3`; planner locks signature shape in plan.
- **CLI deprecation timeline measurement** — "2 minor versions" is locked; whether that's measured in calendar time, release count, or both is researcher/planner discretion grounded in the v1 release cadence.
- **Test ring depth per ring** — ARCH-11 names the rings (unit / integration / smoke / property-based); how prescriptive the ADR is about WHICH tests go in WHICH ring is planner's call.
- **Logging redaction pattern specifics** — D-15 of ADR 0001 didn't address this; ARCH-12 requires type-level + sink-level. The exact Go pattern (`Secret` struct + `LogValuer` interface + slog handler chain) is researcher/planner territory.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements (the contract)
- `.planning/ROADMAP.md` §"Phase 2: Architecture v2 Design" — Goal, dependencies, ARCH-01..ARCH-12 mapping, 5 success criteria. THE source of "what done means".
- `.planning/REQUIREMENTS.md` §"Architecture v2 Design (Deliverable #2)" — ARCH-01 through ARCH-12 with locked content for each contract.
- `.planning/PROJECT.md` §"Current Milestone: v2.0" + "Key Decisions" — milestone context, the 10 locked decisions from milestone init (TOML config, workspaces/<target>/ layout, failure_policy, PARALLEL_MAX_JOBS=4, etc.).

### Phase 1 deliverable (the language gate)
- `.planning/decisions/0001-language.md` — ADR 0001 (Status: Accepted, signed 2026-05-28). Language locked as Go. All Phase 2 contracts MUST be expressible in Go (no language-agnostic abstractions).
- `.planning/phases/01-language-adr-spike/01-CONTEXT.md` — Phase 1 decisions that carried forward: D-03 (research-file collapse to Go-only happened; Phase 2 doesn't repeat it).
- `.planning/phases/01-language-adr-spike/01-04-SUMMARY.md` — Spike measurements + verdict; useful for Phase 2 sanity (e.g., AppContext shape evolved during spike — see how `spike/go/cmd/spike/main.go` composes Logger + UI + Output).

### Research synthesis (factual base for ADR)
- `.planning/research/SUMMARY.md` — Synthesized verdict (post-Phase 1 collapse: Go-only). §"Stack Snapshot" gives the locked stack (cobra/koanf/slog/errgroup/modernc-sqlite). §"Architecture: Top Cross-Cutting Patterns" lists patterns the ADR formalizes.
- `.planning/research/ARCHITECTURE.md` — 15 sections covering: System Overview, Module/Component model, Scheduler/Concurrency, Checkpoint Engine, Config System, Tool Wrapper, Output Tree, Logging, Error model, Testing, Plugin Registry, Observability, Packaging, Migration, Open Questions. THE most important input for Phase 2.
- `.planning/research/STACK.md` — Library picks for each of the 14 dimensions (cobra for CLI, koanf for config, slog for logging, errgroup for concurrency, modernc/sqlite for SQLite, etc.) + library blacklist (libs the ADR must NOT recommend).
- `.planning/research/PITFALLS.md` — 51 pitfalls; the top-5 (process-group escape, non-atomic checkpoint writes, tool version drift, secret leak in logs, custom user config lost) drive specific contract requirements: kill-tree-safe Backend, atomic JSONL writer, ToolRegistry warning on drift, type-level Secret + sink redaction, migrator with corpus testing.
- `.planning/research/FEATURES.md` — Reference for compat layer scope (which Recon/<domain>/X files must keep working under the symlink layer).

### Bash reference implementation (what is being contracted against)
- `.planning/codebase/ARCHITECTURE.md` — Current bash orchestration patterns. The ADR's contracts must port (not reinvent): start_func/end_func lifecycle, parallel_funcs throttling, run_command wrapper, axiom failover, checkpoint sentinels.
- `.planning/codebase/STRUCTURE.md` — v1 module breakdown; informs where v2 module boundaries land.
- `.planning/codebase/CONCERNS.md` — Known v1 issues; the ADR's contracts must close these (not re-introduce them).
- `.planning/codebase/STACK.md` — 70+ external tools v2 will continue to orchestrate; informs ToolRegistry shape.
- `reconftw.cfg` (current v1, ~323 flags) — The full inventory of v1 config flags. Every flag here must have a v2 TOML home (D-09) or be on the migrator-warning drop list (D-11).
- `reconftw.sh` (the v1 CLI getopt block) — The full v1 short-flag set + long-option list. Every entry here either becomes a deprecated alias (most) or maps to a v2 subcommand.
- `lib/parallel.sh` (`_kill_tree`, `_throttle_jobs`) — v1 kill-tree + throttling patterns the v2 Backend MUST replicate (Pitfall 1.2 + ARCH-09).
- `lib/validation.sh` (validators) — v1 input sanitization helpers; v2 contracts inherit the security posture (path-traversal rejection, shell-metacharacter rejection in domain/IP/URL inputs).

### Project conventions (style + commit discipline)
- `CLAUDE.md` — Project commit conventions (no Claude co-author footer per `memory/feedback_commits.md`), workflow gates (GSD enforcement).
- `.planning/codebase/CONVENTIONS.md` — Naming patterns; the ADR follows v1 conventions where they make sense (e.g., `snake_case` config flags surviving as `[legacy]` aliases).

### ADR 0002 location (the deliverable)
- `.planning/decisions/0002-architecture-v2.md` — Does not exist yet. Phase 2 creates it. After sign-off (D-13) this file IS the contract.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets (patterns the ADR formalizes from v1)

- **`lib/parallel.sh:_kill_tree()` (line 55)** — v1 kill-tree pattern (process-group + pgrep -P walk). ARCH-06 `Backend` interface must require the equivalent (`Setpgid` + `syscall.Kill(-pid)` per Phase 1 spike `spike/go/internal/proc/proc.go`). Spike already proved the pattern; ADR ratifies it.
- **`lib/parallel.sh:_throttle_jobs` + `parallel_funcs` (lines 200-340)** — v1 throttling pattern with `wait -n` (bash 4.3+). ARCH-09 scheduler shape ports this: `Scheduler.Submit(Task) error` with bounded concurrency via `errgroup.SetLimit(PARALLEL_MAX_JOBS)`. PARALLEL_MAX_JOBS default = 4 (preserved from v1, per PROJECT.md).
- **`modules/core.sh:start_func`/`end_func`** — v1 lifecycle wrapper with logging + checkpoint touch. ARCH-05 `Task` interface formalizes this: `Run(ctx, *AppContext) Result` returns success/skip/failure; checkpoint writing happens at the Scheduler layer (atomic-write semantics, not bash `touch`).
- **`modules/utils.sh:run_command`** — v1 universal tool gate (dry-run, adaptive rate, axiom dispatch). ARCH-06 `Backend.Exec(ctx, *Tool, args)` is the v2 successor. Adaptive rate-limit + dry-run + axiom dispatch survive; the contract is `Backend`, not a free function.
- **`spike/go/internal/proc/proc.go`** — Phase 1 spike kill-tree implementation. Already shipped on `rewrite/v2`. ADR §6 (Tool Wrapper / Backend) can cite this file as the reference implementation Phase 3 inherits/refines.
- **`spike/go/internal/output/atomic.go`** — Phase 1 spike atomic JSONL writer (tempfile + fsync + rename + parent dir fsync). ADR §7 (Output Tree Management) cites this as the canonical AtomicWriter pattern (Pitfall 3.1).
- **`spike/go/internal/passive/passive.go`** — Phase 1 spike `errgroup` fan-out pattern. ADR §3 (Scheduler) cites as the canonical concurrency primitive (vs sync.WaitGroup or channels).
- **`spike/compare.sh`** — Phase 1 spike bash runner. NOT a v2 pattern (Phase 2 does NOT ratify bash patterns going forward), but useful as proof that the spike contracts WORK end-to-end against a real recon target.

### Established Patterns (v1 patterns the ADR must port or explicitly reject)

- **Global config + sourced modules (`reconftw.cfg` sourced into a single shell process)** — REJECT. ADR specifies AppContext-passed-by-pointer; NO package-level globals (ARCH-07).
- **Bash function checkpoints (`touch "$called_fn_dir/.${fn}"`)** — REPLACE with SQLite checkpoint store (ARCH-03 specifies `checkpoints.db`). The replacement is more atomic; the ADR's contract for "what counts as a checkpoint" must be explicit.
- **Subprocess "fire-and-merge" for passive sources** — KEEP. The `errgroup` fan-out in `passive.go` is the v2 equivalent of v1's `parallel_funcs` pattern.
- **shellcheck + shfmt CI gates** — REPLACE with `go vet` + `golangci-lint` (ADR §11 Test Ring Policy specifies).
- **`OUTPUT_VERBOSITY=0/1/2` runtime knob** — KEEP. v2 honors the same 0/1/2 semantics (ADR specifies in the CLI + logging sections).
- **`PARALLEL_LOG_MODE summary|tail|full`** — KEEP. v2 preserves the three modes; ADR ratifies them in §11 (test rings) and §12 (UI).
- **`--source-only` test entry (for bats tests)** — REPLACE with Go's native test-binary model (`go test ./...`); no parallel concept in v2.
- **`run_command` wrapper for dry-run + axiom** — KEEP as `Backend.Exec` semantics; ADR specifies how dry-run mode propagates through AppContext.

### Integration Points (where ADR contracts will be consumed)

- **Phase 3 (Foundation Kernel)** — Consumes the entire ADR. Phase 3 plans cite specific § numbers for each kernel component (logger, scheduler, config loader, AppContext, etc.). Phase 3 is the FIRST consumer; correctness here gates everything downstream.
- **Phase 4-7 (Module ports)** — Cite ARCH-05 (`Task` interface) when writing each module's Task implementations. Cite ARCH-09 (`failure_policy`) for spine vs OSINT/vulns posture.
- **Phase 8 (MCP server)** — Cites ARCH-06 (`Backend.Stream()`) for streaming tool output to MCP clients. Phase 2 left MCP contract pre-locking to Claude's discretion (see decisions); if the planner picks "pre-lock", ARCH-06 grows accordingly.
- **Phase 9 (Composite modes)** — Cites ARCH-05 + ARCH-09 (Task composition + failure_policy interaction).
- **Phase 11 (Installer + migrator)** — Cites ARCH-02 (TOML schema) for the migrator's target shape. The migrator must emit valid v2 TOML per the locked schema.
- **Phase 12 (Cutover)** — Cites the entire ADR as the source-of-truth contract; CUT-11 bug-bug parity tests verify the ported modules conform to the ARCH-05 / ARCH-06 / ARCH-09 contracts.

</code_context>

<specifics>
## Specific Ideas

- **The ADR is the source of historical truth for v2 contracts** (analogous to ADR 0001 for the language choice). All Phase 3+ commits cite the ADR by file path. Amendments use the inline-block convention (D-06); the doc + git history together are the audit trail.
- **TL;DR at the top is non-negotiable** (D-04). Future maintainers who join the project after sign-off should be able to read 1 paragraph and understand every locked decision. The TL;DR section is the doc's "executive summary" and stays under ~30 lines.
- **Pre-sign verification gate is programmatic, not informal** (D-14). The executor runs ARCH-NN coverage grep, TOML parse, Go snippet compile, and glossary completeness checks as a sequence of commands. If any check fails, sign-off does not happen. Cheap and deterministic.
- **Validation rules for security-critical keys are mandatory in Phase 2** (D-12 supports this). Path-traversal rejection on file-path keys, scheme allowlists on URL keys, length caps on user-supplied strings — these MUST be in the schema. Phase 3 config loader implements them; Phase 2 ADR defines them.
- **Schema 1:1 coverage (D-09) is a user-protection decision, not a doc-length decision.** The migrator's correctness is the lever (D-11 ties dropped flags to MIGRATION-WARNINGS.md entries). Every user who has a custom `reconftw.cfg` should be able to migrate without surprise.

</specifics>

<deferred>
## Deferred Ideas

- **Compat-symlink file-by-file mapping fidelity** — Whether the ADR lists every `Recon/<domain>/X` → `workspaces/<id>/Y` pair, or just the principle + a few examples. Researcher surfaces the v1 file inventory in `02-RESEARCH.md`; planner picks fidelity in `02-PLAN.md`.
- **MCP contract pre-locking** — Whether the ADR locks `Backend.Stream()` for Phase 8 MCP server now, or Phase 8 amends later. Planner decision; default = defer (no over-design for a phase 8 phases away).
- **AppContext composition style (single struct vs smaller contexts)** — Researcher surfaces patterns from `research/ARCHITECTURE.md`; planner locks the signature shape during Phase 2 planning.
- **CLI deprecation timeline measurement unit** — "2 minor versions" is the lock; whether measured in calendar time or release count is planner discretion grounded in v1 release cadence (`git log --tags --simplify-by-decoration` informs).
- **Test ring depth (which tests go in which ring)** — ARCH-11 names the rings; the ADR's prescription level per ring is planner's call. Default = high-level policy in the ADR + concrete examples in Phase 3's test-harness plan.
- **Logging redaction pattern specifics (Go `Secret` + `LogValuer` + slog handler chain)** — ARCH-12 names the strategy; the exact code shape is researcher/planner territory.
- **GitHub Discussion / Twitter announcement of ADR 0002 sign-off** — Optional post-cutover (Phase 12) marketing, NOT a Phase 2 deliverable.
- **Docs-site mirror of `.planning/decisions/`** — Deferred to Phase 11 (installer + packaging) if/when reconFTW publishes externally.

</deferred>

---

*Phase: 2-architecture-v2-design*
*Context gathered: 2026-05-28*
