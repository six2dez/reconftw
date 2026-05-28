---
phase: 02-architecture-v2-design
plan: "05"
subsystem: adr
tags: [architecture, cli, testing, logging, secret-redaction, cobra, slog]
dependency_graph:
  requires: ["02-01", "02-02", "02-03", "02-04"]
  provides: ["§8 CLI Surface in ADR 0002", "§9 Test Ring Policy in ADR 0002", "§10 Logging Policy in ADR 0002"]
  affects: ["Phase 3 Foundation Kernel", "Phase 4-7 Module ports", "Phase 8 MCP server"]
tech_stack:
  added: []
  patterns:
    - "cobra.MarkDeprecated() for v1 flag deprecation (ARCH-10)"
    - "slog.LogValuer via Secret type for type-level redaction (ARCH-12)"
    - "RedactingHandler sink for substring redaction (ARCH-12)"
    - "pgregory.net/rapid for property-based testing (ARCH-11)"
    - "go.uber.org/goleak in every TestMain (ARCH-11)"
key_files:
  created: []
  modified:
    - ".planning/decisions/0002-architecture-v2.md"
decisions:
  - "Deprecated v1 flags removed at v2.2.0 (release count, not calendar time)"
  - "Both Secret type (Layer 1) and RedactingHandler (Layer 2) are required; neither alone is sufficient"
  - "Redactor.Register() MUST be called after config load and BEFORE any task or module runs"
  - "Smoke ring gated behind //go:build smoke build tag (excluded from normal go test ./...)"
  - "MockBackend/MockCheckpoint/MockOutputTree must be created as Wave 0 before Phase 3 task implementations"
metrics:
  duration: "~5 minutes"
  completed: "2026-05-28T14:10:25+02:00"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 1
  lines_added: 522
---

# Phase 2 Plan 5: CLI Surface, Test Ring Policy, and Logging Policy Summary

ADR 0002 sections §8, §9, and §10 fully populated with Go snippets, policy tables, and
cross-cutting enforcement requirements satisfying ARCH-10, ARCH-11, and ARCH-12.

## What Was Built

### §8 CLI Surface (ARCH-10)

**§8.1 Subcommand Surface:** 14-row table mapping every v2 subcommand to its v1 long-flag
equivalent and v1 short-flag deprecated alias. Covers: `recon`, `all`, `passive`, `subs`,
`web`, `vulns`, `osint`, `zen`, `deep`, `monitor`, `report`, `mcp`, `migrate`, `install`,
`health-check`.

**§8.2 Persistent Global Flags:** 11 flags with alias annotations, including the `-d`/`-l`
target/list deprecated aliases and the `-v`/`--vps` axiom rename.

**§8.3 Cobra Deprecation Pattern:** Complete Go snippet showing `rootCmd.PersistentFlags().BoolP()` +
`MarkDeprecated()` for all v1 mode flags and target flags. Includes exact stderr warning
format: `Flag --recon has been deprecated, use subcommand 'recon' instead: ...`

**§8.4 Removal Timeline:** v2.2.0 is the binding removal version. "2 minor versions after
v2.0.0 GA" measured in release count (not calendar time). Unit test specification for
warning-emitted-once assertion.

### §9 Test Ring Policy (ARCH-11)

**§9.1 Four-Ring Table:** Complete ring policy with Ring, What Counts, Go Tooling, CI
Cadence, and Max Duration columns. Includes `go test` invocation patterns for each ring
and the `goleak.VerifyNone()` TestMain pattern.

**§9.2 Ring Membership Examples:** Concrete test examples for each of the four rings:
- Unit: 7 named tests including `Secret.LogValue() returns "***"` and scheduler topological sort
- Integration: 5 named tests including crash-reopen checkpoint verification and notifier redaction check
- Smoke: 2 named mode tests against `hackerone.com` in Docker
- Property: 3 rapid generators (scope filter, config validator, scheduler deadlock)

**§9.3 Foundation Wave 0 Requirements:** Package specs for `MockBackend`, `MockCheckpoint`,
`MockOutputTree` in `internal/core/testutil/`. CI YAML fragment for unit/integration/smoke
job split. Smoke build tag convention (`//go:build smoke`).

### §10 Logging Policy & Secret Redaction (ARCH-12)

**Two-layer defense overview paragraph** explaining why both layers are required.

**§10.1 Secret Type** (`internal/core/log/secret.go`): Complete Go block with `type Secret string`,
`LogValue() slog.Value` returning `"***"`, BINDING note against adding `String()`, and
`NotificationsConfig` struct showing `log.Secret` field usage with koanf/validate tags.
Phase 3 golangci-lint rule specification for `*Key/*Token/*Password/*Secret` fields.

**§10.2 RedactingHandler** (`internal/core/log/redacting_handler.go`): Complete Go block
with `Redactor` struct (mutex-protected), `Register()`/`Redact()` methods, `RedactingHandler`
struct implementing all 4 `slog.Handler` interface methods, `redactAttr` helper.

**§10.3 Build-Order Requirement** (`cmd/reconftw/main.go`): 4-step init order Go snippet
with CRITICAL annotations. `ConfigError.Message` must-not-include-raw-value caveat.
Cross-referenced to RESEARCH.md Pitfall 2.

**§10.4 CI Gate (XCUT-07)**: Sentinel-value integration test specification: fake key
`test_sentinel_value_not_a_real_key_abc123`, log capture, zero-leakage assertion. Runs on
every commit; blocks merge on failure.

**v1 parity note:** `redact_secrets()` / `register_secret()` in `lib/common.sh` are the
direct bash predecessors of `Redactor.Redact()` / `Redactor.Register()`.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| Task 1: §8 + §9 | `3e2821ef` | docs(02-05): populate §8 CLI Surface and §9 Test Ring Policy in ADR 0002 |
| Task 2: §10 | `1a67ef39` | docs(02-05): populate §10 Logging Policy & Secret Redaction in ADR 0002 |

## Deviations from Plan

None — plan executed exactly as written.

## Requirements Satisfied

| Requirement | Status |
|-------------|--------|
| ARCH-10 | Satisfied — §8 complete with cobra deprecation pattern and v2.2.0 removal |
| ARCH-11 | Satisfied — §9 complete with four-ring table, ring examples, Wave 0 foundation spec |
| ARCH-12 | Satisfied — §10 complete with Secret type, RedactingHandler, build-order, CI gate |

## Key Decisions Made

1. **v2.2.0 removal binding:** "2 minor versions" is release count, not calendar. The ADR
   binds to the version number v2.2.0; timeline is approximately 4-8 months at current
   cadence but the commitment is the version.

2. **Both layers required (Secret + RedactingHandler):** Neither layer alone is sufficient.
   Layer 1 (type-level) handles structured attributes; Layer 2 (sink-level) catches secrets
   that escape through error chains, fmt.Sprintf, or third-party log calls. The ADR makes
   both mandatory.

3. **Secret.String() deliberately absent:** No `String()` method on `Secret` type forces
   callers who need the raw value to use the explicit cast `string(mySecret)`, making
   security-sensitive code visible at review. This is the T-02-05-02 threat mitigation.

4. **MockBackend Wave 0 gating:** MockBackend/MockCheckpoint/MockOutputTree must exist
   as Phase 3's first commit; all task tests import them. This prevents Phase 3 from
   writing tasks without test infrastructure.

5. **Smoke ring build-tag isolation:** `//go:build smoke` fully excludes smoke tests from
   `go test ./...` and `go test -short ./...`. Only explicit `-tags smoke` activates them,
   matching the CI budget constraint from CLAUDE.md (integration-full weekly cron).

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced.
This plan modified only the ADR documentation file. No new threat surface.

## Self-Check

### Created files exist
- `.planning/decisions/0002-architecture-v2.md` — modified (pre-existing): FOUND

### Commits exist

- `3e2821ef` — FOUND
- `1a67ef39` — FOUND

## Self-Check: PASSED
