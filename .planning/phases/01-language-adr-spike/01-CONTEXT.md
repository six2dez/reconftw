# Phase 1: Language ADR & Spike - Context

**Gathered:** 2026-05-27
**Status:** Ready for planning

<domain>
## Phase Boundary

Decide Go vs Python for the v2.0 reconFTW core via measurable side-by-side spike: implement an identical recon slice (passive subdomain enum + httpx probe + atomic JSONL writes + SIGINT kill-tree test) in BOTH languages, measure ergonomics + packaging + subprocess-safety + cross-platform, sign the ADR at `.planning/decisions/0001-language.md` before any production code is written, then collapse research files to the chosen language only.

**What's NOT in this phase** (belongs elsewhere):
- Foundation scaffolding (Phase 3)
- TOML schema design / Task/Backend/AppContext interface signatures (Phase 2)
- Production-grade implementation of any module (Phase 4+)

</domain>

<decisions>
## Implementation Decisions

### Timebox

- **D-01:** **Tight timebox — 1 week of calendar time per language** (2 weeks total for both PoCs combined). Hard limit: if either language isn't complete within its 1-week window, STOP and use what was built. The spike is a viability comparison, NOT the implementation. Spike scope creep is a known PITFALL (rewrites grow indefinitely) — discipline at this gate prevents the whole milestone from drifting.
  - **Rationale:** PoC slice (passive subs + httpx + atomic JSONL + kill-tree test) is ~200-600 LoC per language; 1 week per lang is achievable for the maintainer (single-developer). Open-ended/generous timeboxes were rejected for this reason.

### Sign-off

- **D-02:** **Solo same-day sign-off**, no community pre-review. After both spikes are complete (or timeboxes expire), write the ADR including measured numbers + tie-breaker invocation + final verdict, then sign and commit the ADR same day. No GitHub Discussion / PR review gate.
  - **Rationale:** Single-maintainer project; pre-sign community review adds 1-2 weeks bikeshed risk and the project's governance has always been solo. Optionally publish ADR as post-decision GitHub Release note for community visibility (not a gate).

### Post-ADR Cleanup (DEC-05 operationalization)

- **D-03:** **Delete loser language permanently from research files.** After ADR signed:
  - `.planning/research/STACK.md` → edit in place; remove the losing language's table + library blacklist entries; keep only the winning language's stack
  - `.planning/research/ARCHITECTURE.md` → edit in place; remove dual-tracked sections; keep only the winning language's idiomatic patterns
  - `.planning/research/SUMMARY.md` → edit in place; rewrite "Stack Snapshot" + "Architecture: Top Cross-Cutting Patterns" to reference the chosen language only
  - `.planning/research/PITFALLS.md` → edit in place; remove pitfalls specific to the losing language; keep cross-cutting ones
  - **ADR is the single source of historical truth** for the comparison (LoC counts, metrics, decision rationale). Losing-language research content is NOT archived elsewhere.
  - **Rationale:** Clean cut prevents future confusion ("why is Python in STACK if we chose Go?"). The spike code itself in `spike/{loser}/` can be deleted or archived per planner's call — orthogonal to research file collapse.

### Claude's Discretion (defer to researcher + planner)

These gray areas were NOT discussed in detail — planner/researcher resolve with sensible defaults grounded in REQUIREMENTS.md DEC-01 → DEC-05 and the research files:

- **Slice exact composition** — How many passive sources (DEC-02 says 5-10), which specific sources, httpx probe depth (basic vs with tech detection), kill-tree test setup (synthetic slow-mock vs real subfinder+httpx subprocesses). Planner decides during plan-phase; researcher may surface tradeoffs in RESEARCH.md.
- **Comparison metrics weighting + tie-breaker precision** — DEC-03 lists 5 metrics (LoC/hours, packaging, kill-tree, RSS, x-platform); DEC-04 default tie-breaker is "Go if within 25% noise band". Planner defines per-metric rubric + whether any metric is a "killer-feature override" (e.g., kill-tree must work perfectly = mandatory pass) in the plan.
- **Spike harness / repo layout** — `spike/go/` + `spike/python/` parallel directories are implied by DEC-02. Planner designs shared test corpus (target list, expected outputs), comparison runner (Makefile / bash / Python), and whether spike tests port any bats scenarios or are net-new.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & requirements (the contract)
- `.planning/ROADMAP.md` §"Phase 1: Language ADR & Spike" — Goal, dependencies, REQ-ID mapping, 5 success criteria. THE source of "what done means".
- `.planning/REQUIREMENTS.md` §"Decision & ADR (Deliverable #1)" — DEC-01 through DEC-05 with the locked content of the ADR, slice contents, metric list, tie-breaker default, and post-ADR collapse rule.
- `.planning/PROJECT.md` §"Current Milestone: v2.0" + "Key Decisions" — milestone context, the 10 locked decisions from milestone init, why this rewrite at all.

### Research synthesis (factual base for both spikes)
- `.planning/research/SUMMARY.md` — Synthesized verdict; §"Stack Snapshot" gives the two starting stacks; §"Build Order — Phase 0 Language ADR" gives the spike scope recommendation; §"Open Risks" surfaces the "spike inconclusive" failure mode.
- `.planning/research/STACK.md` — Side-by-side Go (cobra/koanf/slog/errgroup/modernc-sqlite) vs Python (typer/pydantic-settings/structlog/asyncio.TaskGroup/sqlite3) library picks with verified May-2026 versions + library blacklist (anti-patterns to avoid in either lang).
- `.planning/research/ARCHITECTURE.md` — Dual-tracked patterns for scheduler, checkpoint, subprocess wrapper, output tree, config layering, logging — both spikes must implement the equivalent code-shape so the comparison is apples-to-apples.
- `.planning/research/PITFALLS.md` — 51 pitfalls; top-5 (process-group escape, non-atomic checkpoint writes, tool version drift, secret leak in logs, custom user config lost) are mandatory test cases for the kill-tree + atomic-write portions of the spike.
- `.planning/research/FEATURES.md` — 70-feature catalog (less critical for Phase 1, but the spike must NOT add anything beyond TS/DIFF — anti-feature creep starts in spikes).

### Bash reference implementation (what is being ported)
- `.planning/codebase/ARCHITECTURE.md` — Current bash orchestration patterns (single-process, source-guard, parallel_funcs, run_command wrapper, start_func/end_func lifecycle, axiom failover wrapper). The spike's design ports a slice of this.
- `.planning/codebase/STACK.md` — 70+ external tools that v2 will continue to orchestrate; the spike uses a 5-10 subset of passive sources.
- `.planning/codebase/STRUCTURE.md` — Module breakdown; `modules/subdomains.sh` is the file being ported in the spike.
- `.planning/codebase/CONCERNS.md` — Known v1 issues the rewrite must NOT re-introduce (top-5 from PITFALLS map here).
- `modules/subdomains.sh:507` (`sub_passive()`) — The canonical bash function the spike's passive-enum flow ports. Read for source list + dedup pattern + checkpoint integration.
- `lib/parallel.sh:55` (`_kill_tree()`) — The bash kill-tree pattern (process-group + pgrep -P walk) the spike's SIGINT test validates by analogue in Go (`Setpgid` + `syscall.Kill(-pid)`) and Python (`start_new_session=True` + `os.killpg`).

### Project conventions (style + commit discipline)
- `.planning/codebase/CONVENTIONS.md` — Naming patterns; the spike code may diverge (it's throwaway) but the eventual production code follows these.
- `.planning/codebase/TESTING.md` — bats test taxonomy; relevant for "feature-parity coverage" criterion in XCUT-03 even though spike tests are not bats.

### No external ADRs yet
- `.planning/decisions/` does not yet exist. Phase 1 creates the first ADR (`0001-language.md`); Phase 2 creates `0002-architecture-v2.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`modules/subdomains.sh:sub_passive()` (line 507)** — Canonical bash function for the spike's passive flow. Lists the v1 passive sources (subfinder, crt, github-subdomains, gitlab-subdomains, urlfinder, hackertarget, …), the fire-and-merge pattern (each tool writes to its own file; `anew` merges + dedupes), and the scope filter call. Spike PoCs should replicate the same fire-and-merge orchestration model (not invent a new one) to keep comparison fair.
- **`lib/parallel.sh:_kill_tree()` (line 55)** — Bash kill-tree implementation using `pgrep -P` recursive walk + `kill -TERM/-KILL` per-PID. The spike's SIGINT kill-tree test asserts the lang's equivalent (process-group kill via `Setpgid` + `kill -PGID` in Go; `start_new_session=True` + `os.killpg` in Python) achieves the same outcome: ALL spawned processes (parent + every descendant) dead within 10s of SIGINT to the parent.
- **`.planning/research/STACK.md` library blacklist** — Tells the spike what NOT to use even in PoC code (e.g., `subprocess.run(timeout=N)` doesn't kill grandchildren; `cmd.Run()` buffers GB in RAM for long-running tools; `requests` for Python new code). Following the blacklist in the spike pays off when porting to production.

### Established Patterns

- **Fire-and-merge for passive sources** — Each passive source writes to its own output file; final merge step dedupes via `anew`-equivalent. Spike should replicate, NOT invent a new pattern (e.g., "all sources stream into a shared channel"). Keeping the pattern shape constant across langs makes the comparison meaningful.
- **Process-group + SIGINT kill-tree** — Mandatory subprocess discipline; the spike's whole purpose at the kill-tree dimension is to prove the lang can do this cleanly. Test must be an integration-style test (real or mock processes spawned) — NOT a unit test mocking the OS.
- **Atomic write at the output boundary** — Bash v1 does NOT do this (CONCERNS.md notes torn writes are a risk); v2 must (PITFALL 3.1). Spike implements `AtomicWriter` per lang (tempfile + fsync + rename + parent dir fsync) and asserts SIGKILL between fsync and rename leaves the original file intact.

### Integration Points

- **No integration with current bash code** — The spike is hermetic. `spike/go/` and `spike/python/` are isolated trees with their own builds/tests; they do NOT call into bash modules or share state. Test corpus (target domain list) can be a flat text file checked into the spike subdirectory.
- **Comparison harness lives outside both langs** — The runner that executes both spikes against the same target and diffs outputs is its own artifact (Makefile + bash script most likely). Lives at `spike/compare.sh` or similar; planner decides.
- **ADR lives at `.planning/decisions/0001-language.md`** — Per DEC-01. The phase's git commits and the ADR file are the only artifacts that persist after Phase 1 closes; spike code may be deleted or archived per planner's call.

</code_context>

<specifics>
## Specific Ideas

- **Tie-breaker MUST be invoked explicitly in the ADR.** The ADR's verdict section says either "metrics within 25% noise band, tie-breaker invoked, choose Go" OR "metrics show clear winner (X by Y%), tie-breaker NOT invoked, choose X" — but never leaves the tie-breaker ambiguous. This makes the decision auditable in 6 months.
- **All 5 DEC-03 metrics MUST be measured for BOTH langs, even if one is "obvious".** Don't skip RSS measurement for Go thinking "Go uses less" — measure it. The ADR is for posterity; assumptions become wrong years later.
- **Kill-tree test is the killer-feature gate** — implicit in this discussion: if either lang fails the kill-tree test (orphaned processes after SIGINT), that lang loses regardless of other metrics. This is too severe to be a 25%-noise-band tradeoff (PITFALL 1.2 is top-impact — ethical/legal exposure from orphan tools attacking targets).
- **Spike code in `spike/{loser}/` after ADR**: NOT covered by the cleanup decision (D-03). Planner decides during Phase 2 planning whether to delete spike trees, archive them, or keep them in git history only.

</specifics>

<deferred>
## Deferred Ideas

- **Slice exact composition decisions** (passive sources count, httpx probe depth, kill-tree test setup) → researcher surfaces in `01-RESEARCH.md`; planner locks in `01-PLAN.md`.
- **Comparison metrics weighting rubric** (per-metric scoring scheme, killer-feature overrides beyond kill-tree) → planner defines in `01-PLAN.md`.
- **Spike harness / repo layout** (`spike/{lang}/` structure, shared test corpus, comparison runner script) → planner designs in `01-PLAN.md`.
- **MCP library availability per language** (concern from SUMMARY.md: Phase 8 depends on MCP library in chosen lang) → researcher cross-checks during Phase 1 spike; if MCP support is materially worse in one lang, that's a tie-breaker signal that may dominate.
- **Public announcement of the ADR decision** → optional GitHub Release note post-cutover (Phase 12), NOT a Phase 1 deliverable.

</deferred>

---

*Phase: 1-language-adr-spike*
*Context gathered: 2026-05-27*
