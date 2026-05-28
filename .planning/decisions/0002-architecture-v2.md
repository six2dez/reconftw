# 0002 — Architecture v2 Design for reconFTW

* Status: Proposed
* Date:
* Deciders: six2dez (solo maintainer, project owner)
* Tags: architecture, v2.0, go, toml, interfaces, output-tree, cli, testing, logging

## Context

Phase 2 locks every contract the rest of the v2.0 rewrite depends on. This document is
the source of truth for all architecture decisions that Phase 3 (Foundation Kernel) and
every subsequent phase will build against. Language is locked as Go per ADR 0001
(`.planning/decisions/0001-language.md`, Status: Accepted). Requirements ARCH-01 through
ARCH-12 defined in `.planning/REQUIREMENTS.md` §"Architecture v2 Design (Deliverable #2)"
are all addressed here: TOML config schema (ARCH-02), output tree layout (ARCH-03), compat
symlink layer (ARCH-04), `Task` / `Backend` / `AppContext` interface signatures (ARCH-05,
ARCH-06, ARCH-07), 7-class error hierarchy (ARCH-08), failure isolation policy (ARCH-09),
CLI surface (ARCH-10), test ring policy (ARCH-11), and logging policy with type-level
secret tagging (ARCH-12). After sign-off this document is BINDING per D-05; amendments
require an inline amendment block per D-06.

## Decision

The v2.0 architecture for reconFTW is specified in 12 numbered sections (§1 through §12)
below. Each section addresses one or more ARCH-NN requirements and provides Go interface
or type snippets, TOML samples, and validation rules sufficient for Phase 3 to begin
implementation without additional design decisions. After sign-off these contracts are
BINDING (D-05): interface signatures (`Task` / `Backend` / `AppContext`) and the error
class hierarchy are fixed. Breaking changes require an inline amendment block in this file
following the format: `Amended: YYYY-MM-DD | Section: §N | Reason: …` (D-06). Non-breaking
additions (new methods, new error types, new AppContext fields) do not require an amendment.

## §1 Overview & System Diagram

<!-- ARCH-01 -->

[STUB — populated in Wave 2]

This section will contain: TL;DR summary of every locked decision, glossary of all new
terms (AppContext, Backend, Task, Tool, FailurePolicy, Secret, ToolError, ToolTimeout,
OutOfScope, AxiomFailure, ConfigError, ScopeError, ChecksumMismatch), suggested reading
order for Phase 3 implementers, and a top-level Mermaid system architecture diagram.

## §2 TOML Configuration Schema

<!-- ARCH-02 -->

[STUB — populated in Wave 2]

This section will contain: the full v2 TOML schema hierarchy, `[legacy]` alias table for
all ~323 v1 reconftw.cfg flags (D-09, D-10), per-key validation rules (type, range, regex,
required/optional, default, mutex groups per D-12), and migrator drop-list for untranslatable
bash-specific globals (D-11).

## §3 Output Tree Layout

<!-- ARCH-03 -->

[STUB — populated in Wave 2]

This section will contain: the canonical `workspaces/<target-id>/` directory structure,
all 6 SQLite databases (checkpoints.db, state.db, artefacts.db, results.db, audit.db,
cache.db), JSONL artefact file layout, and the AtomicWriter pattern (tempfile + fsync +
rename + parent dir fsync).

## §4 Compat Symlink Layer

<!-- ARCH-04 -->

[STUB — populated in Wave 2]

This section will contain: the compat-writer design that maintains `Recon/<domain>/` as a
symlink farm pointing into `workspaces/<target-id>/`, lifecycle of symlinks (created on
task-end via OnEnd hook), 6-month post-cutover deletion timeline, and representative
mapping examples.

## §5 Interface Signatures

<!-- ARCH-05, ARCH-06, ARCH-07 -->

[STUB — populated in Wave 2]

This section will contain: the `Task` interface signature (Name / Module / Enabled(cfg) /
DependsOn() / Run(ctx, app) → Result), the `Backend` interface signature (Exec / Stream /
HealthCheck / Capacity), the `AppContext` struct shape (Log, Cfg, Scheduler, Tools, Tree,
Checkpoint, Notify, Target, UI — no package-level state), and Go godoc-style code blocks
for each. All signatures are BINDING after sign-off (D-05).

## §6 Error Class Hierarchy

<!-- ARCH-08 -->

[STUB — populated in Wave 2]

This section will contain: the 7-class typed error hierarchy (ToolError, ToolTimeout,
OutOfScope, AxiomFailure, ConfigError, ScopeError, ChecksumMismatch), Go type definitions
with fields and Error() string implementations, error wrapping conventions, and the rule
that ConfigError.Message must never include raw Secret field values.

## §7 Failure Policy Model

<!-- ARCH-09 -->

[STUB — populated in Wave 2]

This section will contain: the `failure_policy` enum (fail_fast vs best_effort) per module
group, scheduler enforcement via errgroup.SetLimit(PARALLEL_MAX_JOBS=4), how failure_policy
interacts with the compat layer and checkpoint store, and the spine vs OSINT/vulns posture
distinction.

## §8 CLI Surface

<!-- ARCH-10 -->

[STUB — populated in Wave 2]

This section will contain: the v2 cobra subcommand surface (reconftw run / subs / web /
vulns / osint / mcp / health / migrate), all v1 short-flag deprecated aliases with 2-minor-
version sunset, the `MarkDeprecated()` cobra pattern, and the `--dry-run` / `--verbose` /
`--quiet` / `--output` universal flags.

## §9 Test Ring Policy

<!-- ARCH-11 -->

[STUB — populated in Wave 2]

This section will contain: the 4-ring test ring policy (unit / integration / smoke /
property-based), CI gate assignments per ring, what belongs in each ring, go-test invocation
patterns, goroutine leak detection via go.uber.org/goleak in every TestMain, and the CI
budget split (unit+smoke per-push vs integration-full weekly cron).

## §10 Logging Policy & Secret Redaction

<!-- ARCH-12 -->

[STUB — populated in Wave 2]

This section will contain: the slog-based logging architecture, the `Secret` type
implementing `slog.LogValuer` for type-level secret tagging, the RedactingHandler sink
pattern, the rule that secrets must be registered BEFORE the first log line that could
reference them, and sink-level redaction as a defense-in-depth backstop.

## §11 Pre-Sign Verification Gate

<!-- ARCH-01 — process -->

[STUB — populated in Wave 2]

This section will contain: the 4-step programmatic pre-sign verification gate (D-14):
(1) ARCH-NN requirement grep coverage check, (2) TOML block parse validation via tomljson,
(3) Go interface snippet compile via `go build ./interfaces_check/...`, and (4) glossary
term completeness check. The gate script is at `.planning/decisions/verify-0002.sh`.

## §12 Amendment Log

<!-- D-06 -->

[STUB — populated in Wave 2]

This section will contain: an ordered log of all inline amendments to this ADR after
sign-off. Each amendment entry follows the format:
`Amended: YYYY-MM-DD | Section: §N | Reason: … | SHA: <git-sha>`.
Amendments are append-only; original text is struck through but not removed.

## Consequences

### Positive

[STUB — populated in Wave 3]

### Negative

[STUB — populated in Wave 3]

## References

- `.planning/REQUIREMENTS.md` — ARCH-01 through ARCH-12 requirements (source of contract scope)
- `.planning/ROADMAP.md` — Phase 2: Architecture v2 Design section (goal + success criteria)
- `.planning/research/ARCHITECTURE.md` — 15-section architecture research synthesis (primary input for §3-§12)
- `.planning/research/STACK.md` — 14-dimension library stack with verified versions (cobra, koanf, slog, errgroup, modernc-sqlite)
- `.planning/decisions/0001-language.md` — ADR 0001 (Status: Accepted); language locked as Go
- `.planning/phases/02-architecture-v2-design/02-RESEARCH.md` — Phase 2 research (interface patterns, TOML schema, error hierarchy, test rings, logging, CLI deprecation)

## Signed

**Signed by:** six2dez (single maintainer, project owner)
**Date:** [to be filled at sign-off]
**Git SHA (this ADR):** <see git log -- .planning/decisions/0002-architecture-v2.md>
