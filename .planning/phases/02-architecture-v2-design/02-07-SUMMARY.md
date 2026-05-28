---
phase: 02-architecture-v2-design
plan: 07
subsystem: adr-sign-off
tags:
  - adr
  - sign-off
  - architecture
  - locked

dependency_graph:
  requires:
    - 02-01: ADR skeleton + verify-0002.sh + interfaces_check/main.go
    - 02-02: §2 TOML schema populated
    - 02-03: §3 + §4 output tree + compat populated
    - 02-04: §5 + §6 + §7 interfaces + errors + failure_policy populated
    - 02-05: §8 + §9 + §10 CLI + tests + logging populated
    - 02-06: §1 + §11 + §12 + TL;DR + glossary + reading order populated
  provides:
    - .planning/decisions/0002-architecture-v2.md (Status: Accepted; 2735 lines; BINDING for Phase 3+)
    - .planning/STATE.md updates (Phase 2 = Complete, milestone 2/12 = 16%)
    - .planning/PROJECT.md updates (Architecture v2 deliverable checked; Key Decisions row added)
  affects:
    - Phase 3 Foundation Kernel: consumes the entire ADR. Phase 3 plans cite §-numbers for each kernel component.
    - Phase 4-7 Module ports: cite ARCH-05 (Task), ARCH-06 (Backend), ARCH-09 (failure_policy)
    - Phase 8 MCP server: cites ARCH-06 Backend.Stream() shape
    - Phase 11 Installer + migrator: cites ARCH-02 TOML schema as migrator target

tech-stack:
  added: []
  patterns:
    - "ADR amendments: inline block in same file (per D-06), Amended: header format"
    - "Pre-sign verification gate: programmatic 4-check script as the sign-off gate"
    - "ADR template shape: mirror 0001-language.md exactly (frontmatter bullets, Signed block)"

key-files:
  created:
    - .planning/phases/02-architecture-v2-design/02-07-SUMMARY.md (this file)
  modified:
    - .planning/decisions/0002-architecture-v2.md (Status: Proposed → Accepted; Date + spike SHA filled)
    - .planning/STATE.md (Phase 2 = Complete; milestone progress)
    - .planning/PROJECT.md (Architecture v2 checked; Key Decisions row)

key-decisions:
  - "ADR 0002 SIGNED 2026-05-28 — architecture v2 locked"
  - "Pre-sign verification gate: 4 checks all PASS (ARCH-NN, TOML, Go compile, glossary)"
  - "Per D-13: solo same-day sign-off (no community gate, no calendar delay)"
  - "Per D-05: Task/Backend/AppContext signatures + error class shapes BINDING for Phase 3+"
  - "Per D-07: amendments only for breaking changes (rename/remove/type-change); additions free"
  - "Per D-16: sign-off triggers STATE.md + PROJECT.md updates only — no research-file collapse"

patterns-established:
  - "Pre-sign programmatic gate (verify-0002.sh) IS the sign-off contract — failing the gate halts sign-off"
  - "ADR follows 0001 template shape (frontmatter `* Key: Value`, `## Signed` block format, References as plain unordered list)"
  - "Sign-off ceremony decoupled from research-file collapse (Phase 2 does not collapse; only Phase 1's language ADR did)"

requirements-completed:
  - ARCH-01

duration: "~10 minutes (verify gate run + sign-off edits + STATE/PROJECT updates + SUMMARY)"
completed: "2026-05-28"
---

# Phase 2 Plan 7: ADR 0002 Sign-off Ceremony Summary

**ADR 0002 signed and committed — architecture v2 locked. Pre-sign verification gate (4/4 checks) passed before sign-off. Phase 2 closes; Phase 3 Foundation Kernel unblocked.**

## Performance

- **Duration:** ~10 minutes wall clock
- **Tasks:** 3/3 (Task 1: verify gate execution; Task 2: human-verify checkpoint; Task 3: sign-off + STATE.md + PROJECT.md + SUMMARY)
- **Commits:** 3
  - `a963bc82` — `docs(phase-02): sign ADR 0002 — architecture v2 design locked`
  - `a1c7ee25` — `docs(phase-02): mark Phase 2 complete and record ARCH-v2 decision in PROJECT`
  - (this SUMMARY commit — pending)

## Accomplishments

- Ran the pre-sign verification gate (`bash .planning/decisions/verify-0002.sh`) — all 4 checks passed:
  - **Check 1:** ARCH-NN requirement coverage (12/12 — ARCH-01..ARCH-12)
  - **Check 2:** TOML blocks parse via `tomljson` (3/3 — at lines 294, 1032, 1937)
  - **Check 3:** Go interface snippets compile via `go build ./interfaces_check/...` (1/1)
  - **Check 4:** Glossary completeness (13/13 contract terms found)
- Returned human-verify checkpoint with proposed ADR diff preview, commit message, and verdict rationale
- After user approval (delivered via orchestrator continuation), applied the sign-off edit:
  - `Status: Proposed` → `Status: Accepted`
  - `Date:` (empty) → `Date: 2026-05-28`
  - `Date: [to be filled at sign-off]` → `Date: 2026-05-28`
  - Added `Git SHA (spike final): 4a8d8890` line
- Committed signed ADR with the exact commit message specified in the plan
- Updated `.planning/STATE.md`:
  - Phase 2 row: `7/7 | Complete | 2026-05-28`
  - `completed_phases: 1 → 2`
  - `completed_plans: 5 → 12`
  - `percent: 8 → 16`
  - Current focus: Phase 3 Foundation Kernel
  - status: `executing → ready_to_plan`
- Updated `.planning/PROJECT.md`:
  - Architecture v2 deliverable checked off (`[ ] → [x]`)
  - Key Decisions table: new row `2026-05-28 — v2.0 architecture: ADR 0002` (prepended before the language ADR 0001 row)
- Committed STATE.md + PROJECT.md as a separate atomic commit (per plan structure)

## ADR 0002 Final Shape

- **Length:** 2735 lines (up from 7777 bytes / ~200 lines at skeleton)
- **Sections:** 12 numbered (§1–§12) plus TL;DR, Glossary, Reading Order, Consequences (7 positive + 5 negative), References (14 entries)
- **Diagrams:** Mermaid System Overview (§1.1, 12 nodes / 15 edges) + ASCII inline (output tree, TOML precedence)
- **Go snippets:** Full Task/Backend/AppContext interfaces with godoc + BINDING annotations; 7-class error hierarchy with sentinel+struct hybrid; failure_policy → errgroup mapping; cobra CLI with MarkDeprecated; Secret + RedactingHandler + 4-step initialization
- **TOML samples:** 20 top-level sections covering ~290-310 v1 flags 1:1 with `# was UPPER_CASE_FLAG` annotations (332 total inline annotations); `[legacy]` UPPER_CASE alias table; 28-row per-key validation rules with security reasons

## Deviations from Plan

### Deviation 1: Direct orchestrator close-out (not a continuation agent)

- **Found during:** Task 3 (sign-off application after user approval)
- **Issue:** Plan called for a continuation agent to apply the sign-off edit after user approval. Per Phase 1's precedent (D-13 sign-off ceremony) and to avoid re-spawning a subagent for a few file edits, the orchestrator applied the sign-off edit directly in the primary checkout instead of dispatching a continuation agent.
- **Fix:** Direct orchestrator edit + commit + STATE/PROJECT updates. Same final git history shape; no subagent overhead.
- **Verified:** ADR signed, STATE.md + PROJECT.md updated, commit chain correct. `bash verify-0002.sh` re-run after sign-off — still passes all 4 checks.

### Deviation 2 (pre-sign): `tomljson` missing on dev machine

- **Found during:** Initial verify-0002.sh run (pre-checkpoint)
- **Issue:** `tomljson` (from `go install github.com/pelletier/go-toml/v2/cmd/tomljson@latest`) was not installed on the dev machine, causing Check 2 to fail.
- **Fix:** Orchestrator installed `tomljson` to `$HOME/go/bin/tomljson` before re-running the gate; verified PATH includes `$HOME/go/bin`. Note added to verify-0002.sh's §11 ADR documentation (already present from 02-06 Task 1 Part B).
- **Verified:** Re-run gate after install — Check 2 passes (3/3 TOML blocks parse).

### Deviation 3 (pre-sign): Inline triple-backtick token in §11 prose triggered awk fence false-match

- **Found during:** First Check 2 run after `tomljson` install
- **Issue:** §11 prose described the awk extraction using a literal `` ` ```toml ` `` inline backtick token, which the script's `grep '```toml'` matched. The awk then tried to parse the following prose lines as TOML.
- **Fix:** Pre-checkpoint orchestrator edit — replaced `` `Extracts every \` \`\`\`toml \` code block` `` with `Extracts every triple-backtick \`toml\` code block`. Same meaning; no literal triple-backtick + toml token in prose. Committed as `7c7931f2 fix(02): replace literal triple-backtick in §11 prose to avoid awk fence false-match`.
- **Verified:** Re-run gate — Check 2 passes cleanly.

## DEC / ARCH Requirements Self-Review

- **ARCH-01 (signed ADR):** ADR file at `.planning/decisions/0002-architecture-v2.md`, Status: Accepted, signed by six2dez 2026-05-28, committed to `rewrite/v2` at `a963bc82`. ✓
- **ARCH-02 (TOML schema):** §2 fully specified with all 20 top-level sections + per-key validation. ✓ (delivered in 02-02)
- **ARCH-03 (output tree):** §3 fully specified workspaces/<target-id>/ layout + JSONL schemas + manifest.json + checkpoints.db + AtomicWriter. ✓ (delivered in 02-03)
- **ARCH-04 (compat symlink):** §4 fully specified `_compat/` directory + AtomicSymlink Go snippet + lifecycle + 6mo timeline. ✓ (delivered in 02-03)
- **ARCH-05 (Task interface):** §5.1 signed with 6 methods + BINDING. ✓ (delivered in 02-04)
- **ARCH-06 (Backend interface):** §5.2 signed with 4 methods + Stream() shape ready for MCP. ✓ (delivered in 02-04)
- **ARCH-07 (AppContext):** §5.3 signed with single struct shape + 9 fields. ✓ (delivered in 02-04)
- **ARCH-08 (error hierarchy):** §6 with 7 typed errors + sentinel+struct hybrid + Is() bridge. ✓ (delivered in 02-04)
- **ARCH-09 (failure_policy):** §7 with module-group granularity + errgroup mapping + per-module TOML overrides. ✓ (delivered in 02-04)
- **ARCH-10 (CLI surface):** §8 with cobra subcommands + v1 deprecated aliases + MarkDeprecated + v2.2.0 removal. ✓ (delivered in 02-05)
- **ARCH-11 (test rings):** §9 with 4-ring policy + tooling + CI orchestration + concrete examples. ✓ (delivered in 02-05)
- **ARCH-12 (logging policy):** §10 with type-level Secret + sink-level RedactingHandler + initialization order. ✓ (delivered in 02-05)

## Known Stubs

None. The ADR has 0 `[STUB` markers (`grep -c '\[STUB' .planning/decisions/0002-architecture-v2.md` returns 0). All 12 sections + all integration sections are content-complete.

## Issues Encountered

- `tomljson` had to be installed before the verify gate could pass (one-time setup; resolved).
- A prose paragraph in §11 contained a literal triple-backtick + toml token that triggered the awk fence false-match in Check 2; fixed by rephrasing (resolved).
- The orchestrator closed out the plan directly instead of dispatching a continuation agent (deviation; same final outcome).

## Next Phase Readiness

Phase 3 (Foundation Kernel) is unblocked:
- All interface signatures (`Task`, `Backend`, `AppContext`) are BINDING and citable from `.planning/decisions/0002-architecture-v2.md §5`
- The 7-class error hierarchy is defined and citable from §6
- The TOML schema (§2) defines the config loader's target shape
- The output tree (§3) defines the on-disk shape
- `failure_policy` (§7) defines how the scheduler routes errors
- The CLI surface (§8) defines cobra subcommand tree
- The test ring policy (§9) defines the test-harness scaffold
- The logging policy (§10) defines `Secret` + `RedactingHandler` shape

Phase 3 plans should cite specific § numbers when referencing contracts. Amendments to the ADR follow D-06 inline-block format.

---
*Phase: 02-architecture-v2-design*
*Plan: 07*
*Completed: 2026-05-28*
*ADR 0002 commit: `a963bc82`*
*STATE/PROJECT commit: `a1c7ee25`*
