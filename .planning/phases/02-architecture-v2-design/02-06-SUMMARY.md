---
phase: 02-architecture-v2-design
plan: "06"
subsystem: documentation
tags: [architecture, adr, mermaid, glossary, tl-dr, reading-order, consequences]

# Dependency graph
requires:
  - phase: 02-02
    provides: TOML schema (§2), output tree (§3), compat layer (§4)
  - phase: 02-03
    provides: interface signatures (§5), error hierarchy (§6), failure policy (§7)
  - phase: 02-04
    provides: CLI surface (§8), test ring policy (§9)
  - phase: 02-05
    provides: logging policy (§10)
provides:
  - "§1 system overview with Mermaid 12-node architecture diagram and project structure ASCII tree"
  - "§11 pre-sign verification gate documentation (4-check script prose)"
  - "§12 amendment log with D-06 format, D-07 threshold, D-08 governance"
  - "TL;DR: one-paragraph summary of all 12 locked decisions"
  - "Glossary: 17 term definitions (AppContext, Backend, Task, Result, FailurePolicy, Secret, ToolError, ToolTimeout, OutOfScope, AxiomFailure, ConfigError, ScopeError, ChecksumMismatch, AtomicWriter, CompatWriter, Scheduler, Status)"
  - "Reading Order: per-phase navigation guide for Phase 3-12 implementers"
  - "Consequences section: 7 Positive + 5 Negative"
  - "References section: 14 entries including spike files, verify-0002.sh, stdlib links"
  - "Zero [STUB] markers remaining in ADR body"
affects: [phase-03-foundation-kernel, phase-04-subdomains, phase-05-web, phase-06-vulns, phase-07-osint, phase-08-mcp, phase-09-composite-modes, phase-11-installer, phase-12-cutover]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Mermaid graph TD for 12-node system architecture diagram"
    - "D-06 amendment block format (horizontal rule fence + bold key-value pairs)"
    - "D-07 breaking-change threshold (rename/signature/remove/type/semantics)"

key-files:
  created: []
  modified:
    - .planning/decisions/0002-architecture-v2.md

key-decisions:
  - "TL;DR placed between ## Decision and ## §1 for immediate scanability (D-04)"
  - "Glossary covers all 17 terms used in interface signatures and error class names"
  - "Reading Order structured per-phase rather than per-section for implementer usability"
  - "§12 Amendment Log includes both D-06 format AND D-07 threshold in one section"
  - "Consequences Negative list explicitly names koanf mandated over viper as a contributor cost"

patterns-established:
  - "Amendment log placed at END of ADR file, never inline (D-06 enforcement)"
  - "Breaking-change threshold table: rename/signature/remove/type/semantics = amendment required; additive = not required (D-07)"

requirements-completed:
  - ARCH-01

# Metrics
duration: 4min
completed: 2026-05-28
---

# Phase 02 Plan 06: ADR Integration Pass Summary

**Integration pass for 0002-architecture-v2.md: §1 Mermaid diagram + §11 pre-sign gate docs + §12 amendment log + TL;DR + Glossary + Reading Order + Consequences — zero [STUB] markers remain, ADR ready for Wave 4 pre-sign gate.**

## Performance

- **Duration:** 4 min
- **Started:** 2026-05-28T12:16:14Z
- **Completed:** 2026-05-28T12:20:38Z
- **Tasks:** 2 / 2
- **Files modified:** 1

## Accomplishments

### Task 1: §1 System Overview, §11 Pre-Sign Gate, §12 Amendment Log

Replaced three stub sections:

- **§1 Overview & System Diagram** — §1.1: Mermaid `graph TD` with all 12 nodes (CLI, CFG, KERNEL, SCHED, TOOLS, OUTPUT, COMPAT, CHECKPOINT, MODULES, ERRORS, LOG, EXTERNAL) and all 15 directed edges. §1.2: ASCII project structure tree mapping each `internal/core/` sub-package to its ARCH-NN requirement. §1.3: Contract Map table linking each §-section to its ARCH-NN requirement, Phase 3 implementation package, and downstream phase consumer.

- **§11 Pre-Sign Verification Gate** — Prose documentation of all 4 checks in `verify-0002.sh`: Check 1 (ARCH-NN grep coverage), Check 2 (TOML block parse via `tomljson`), Check 3 (`go build ./interfaces_check/...`), Check 4 (glossary term grep). Includes the `tomljson` install note and the run-from-repo-root command.

- **§12 Amendment Log** — D-06 amendment block format (horizontal-rule fence, bold key-value pairs), D-08 governance note (solo same-day, matching original sign-off), D-07 breaking-change threshold table (amendment REQUIRED for rename/signature/remove/type/semantics; NOT REQUIRED for additive changes), and an empty `### Amendments` placeholder.

**Commit:** ff58acce

### Task 2: TL;DR, Glossary, Reading Order, Consequences, References

Added three new sections at the top of the ADR body (between `## Decision` and `## §1`) and populated two existing stub sections:

- **TL;DR** — One paragraph (~30 lines) summarizing all 12 §-sections, one sentence per section. Covers: TOML schema scope, output tree semantics, compat layer lifetime, BINDING interfaces, 7-class error hierarchy, failure_policy model, CLI subcommand surface + deprecation timeline, four test rings, two-layer secret redaction, pre-sign gate, amendment governance.

- **Glossary** — 17 alphabetical term definitions covering every new type, interface, and concept used in interface signatures: AppContext, AtomicWriter, AxiomFailure, Backend, ChecksumMismatch, CompatWriter, ConfigError, failure_policy, FailurePolicy, OutOfScope, Result, ScopeError, Scheduler, Secret, Status, Task, ToolError, ToolTimeout.

- **Reading Order** — Per-phase guide: Phase 3 (§2,3,4,5,10,6,9), Phase 4-7 (§5,7,6,3), Phase 8 (§5,8), Phase 9 (§8,7), Phase 11 (§2, §2.4), Phase 12 (§4,8).

- **Consequences** — `### Positive` (7 items: single ADR, BINDING signatures, locked validation rules, failure_policy replaces bash implicit, Secret type compile-time, compat layer migration window, SQLite checkpoint atomicity) and `### Negative` (5 items: reading investment, amendment overhead, koanf config complexity, test infrastructure dependency, koanf vs viper contributor ramp).

- **References** — 14 entries: REQUIREMENTS.md, ROADMAP.md, 02-CONTEXT.md, 02-RESEARCH.md, 0001-language.md, ARCHITECTURE.md, STACK.md, PITFALLS.md, spike files (proc.go, atomic.go, passive.go), verify-0002.sh, interfaces_check/main.go, slog LogValuer stdlib example, errgroup docs, cobra MarkDeprecated docs.

**Commit:** 490d1e4e

## Verification Results

All success criteria confirmed before commit:

| Check | Result |
|-------|--------|
| `grep '## §1 Overview'` | PASS |
| ` ```mermaid ` block present | PASS |
| KERNEL / SCHED / TOOLS / OUTPUT nodes in diagram | PASS |
| `internal/core/` in project structure | PASS |
| `grep '## §11 Pre-Sign'` | PASS |
| `grep 'verify-0002.sh'` | PASS |
| `grep '## §12 Amendment'` | PASS |
| `grep 'Amendment REQUIRED'` | PASS |
| `grep 'TL;DR'` | PASS |
| `grep 'Glossary'` | PASS |
| `grep 'Reading Order'` | PASS |
| `grep '**AppContext**'` | PASS |
| `grep '**Secret**'` | PASS |
| `grep '### Positive'` | PASS |
| `grep '### Negative'` | PASS |
| `grep 'spike/go/internal/proc/proc.go'` (in References) | PASS |
| Zero `[STUB` markers remaining | PASS (0 found) |
| ADR line count >= 400 | PASS (2734 lines) |
| verify-0002.sh Check 1 (all 12 ARCH-NN present) | PASS |

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None — zero `[STUB]` markers remain anywhere in the ADR body.

## Threat Flags

None — this plan adds only documentation content to an existing planning-phase file
(`.planning/decisions/0002-architecture-v2.md`). No new network endpoints, auth paths,
file access patterns, or schema changes at trust boundaries were introduced.

## Self-Check: PASSED

- `.planning/decisions/0002-architecture-v2.md` — FOUND (2734 lines)
- Task 1 commit ff58acce — exists in git log
- Task 2 commit 490d1e4e — exists in git log
- Zero `[STUB]` markers — confirmed
