# Phase 3: Foundation Kernel - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-28
**Phase:** 3-foundation-kernel
**Areas discussed:** CLI subcommand stub scope

---

## Area Selection

| Option | Description | Selected |
|--------|-------------|----------|
| Plan decomposition | How to split 20 REQ-IDs / ~16 build steps into plans. Phase 1 had 5, Phase 2 had 7. By ARCH-NN groups ≈ 5-6 plans; finer per FOUND-NN cluster ≈ 8-10. | |
| CLI subcommand stub scope | At Phase 3 close, what shows in `reconftw --help`? Just `run` vs every v2 subcommand stubbed. | ✓ |
| Spike code disposition | Phase 1 D-03 collapsed research files but punted spike code. Delete `spike/python/` + `spike/go/`? Keep `spike/go/` as live reference? Archive? Keep permanently? | |
| End-of-Phase-3 demo shape | Bare kernel writing only `manifest.json` vs hardcoded-stub `noop.demo` Task proving Scheduler+Backend+Tree+Checkpoint end-to-end with fixture line in `artefacts/demo.jsonl`. | |

**User's choice:** CLI subcommand stub scope (single area selected)
**Notes:** The other 3 candidate areas defaulted to planner discretion. Plus a 5th area surfaced inline (AxiomBackend coverage in Phase 3) — also deferred to planner.

---

## CLI Subcommand Stub Scope

### Question 1: CLI surface scope

| Option | Description | Selected |
|--------|-------------|----------|
| Minimum: `run` only (Recommended) | Just `reconftw run` + standard cobra (`help`, `completion`, `--version`). Smallest surface area. | |
| All v2 subcommands stubbed | Every future subcommand wired now: `subs/web/vulns/osint/monitor/report/install/mcp/migrate/health-check` all show in `--help` with descriptions and return 'not yet implemented (Phase N)'. | ✓ |
| Tiered: kernel-needed subcommands working + rest stubbed | `run` + `health-check` + `version` + `migrate` (stub) work end-to-end; `subs/web/vulns/osint/monitor/report/install/mcp` stubbed. | |

**User's choice:** All v2 subcommands stubbed
**Notes:** Counter-intuitive vs the "recommended" minimum option — user wants the full CLI grammar visible in Phase 3 binary so Phase 4-12 implementers + v1 users see the future shape immediately. Phase 3 ships 15 subcommands per ADR §8.1 (`recon`, `all`, `passive`, `subs`, `web`, `vulns`, `osint`, `zen`, `deep`, `monitor`, `report`, `mcp`, `migrate`, `install`, `health-check`).

---

### Question 2: Stub message format

| Option | Description | Selected |
|--------|-------------|----------|
| Phase-pointer message + exit 64 (EX_USAGE) (Recommended) | `'reconftw subs' is not yet implemented — ships in Phase 4 (Subdomains E2E + Axiom). See ROADMAP for status.` Returns exit code 64 (sysexits.h EX_USAGE). Subcommand `--help` still works and shows the planned flag list. | ✓ |
| Plain message + exit 1 | `'reconftw subs': not yet implemented` — terse, generic. Exit code 1. | |
| Working `--help` only, error on action | Subcommand's `--help` works fully; any action attempt exits with 'not yet implemented' + Phase pointer. | |

**User's choice:** Phase-pointer message + exit 64 (EX_USAGE)
**Notes:** Makes the "not implemented" state machine-detectable for CI / scripted users; humans get the phase pointer; `--help` is free with cobra (no extra work). Phase 3 ships a helper `func stubNotImplemented(cmd *cobra.Command, phase string, phaseName string) error`.

---

### Question 3: v1 deprecated alias coverage

| Option | Description | Selected |
|--------|-------------|----------|
| Wire all v1 aliases in Phase 3 (Recommended) | Long-flag aliases (`--recon`/`--all`/`--passive`/`--subdomains`/`--web`/`--vulns`/`--osint`/`--monitor`/`--health-check`) + short-flag aliases (`-r/-a/-p/-s/-w/-n/-z/-y/-d/-l/-v`) all wired with `cobra.MarkDeprecated()` warning. Each dispatches to the corresponding v2 stub. MODE-09 unit test fits naturally with Phase 3's CLI test ring. | ✓ |
| Phase 3 long aliases only; short flags wait | Long flags wired; short flags deferred to Phase 9. Reduces cobra flag-vs-subcommand parsing ambiguity in Phase 3. | |
| Defer all v1 aliases to Phase 9 | Phase 3 ships clean v2-only subcommand surface; Phase 9 adds the full alias layer atop. | |

**User's choice:** Wire all v1 aliases in Phase 3
**Notes:** v1 users running `reconftw -r --target X` see a coherent migration message from day 1 of v2 binary. MODE-09 work shifts from Phase 9 to Phase 3 mostly — Phase 9 keeps only the composite-modes behavior implementation. Removal at v2.2.0 per ADR §8.4.

---

### Question 4: Operational subcommand depth

| Option | Description | Selected |
|--------|-------------|----------|
| Both work fully in Phase 3 (Recommended) | `reconftw version` prints binary version + commit SHA + build date + Go version + platform. `reconftw health-check` runs LocalBackend.HealthCheck() + iterates ToolRegistry + verifies config parseable. | ✓ |
| `version` works; `health-check` stubbed | `version` trivial. `health-check` deferred to Phase 11 (Installer). | |
| Both stubbed (uniform with module subcommands) | Uniform behavior: every non-`run` subcommand returns 'not yet implemented'. | |

**User's choice:** Both work fully in Phase 3
**Notes:** Phase 3 kernel binary can self-check from day 1. `reconftw health-check` after `reconftw install` (Phase 11) gives the smoke test for free. CI integration tests in Phase 3 use `reconftw health-check` as the kernel sanity gate. Output uses dot-fill format ported from `lib/ui.sh`. ToolRegistry empty in Phase 3 → passes trivially; Phase 4-7 register tools and they appear in health-check automatically.

---

### Question 5: Wrap-up / continuation

| Option | Description | Selected |
|--------|-------------|----------|
| Decide `run` vs ADR §8 now | Resolve the inconsistency: is `run` an implicit alias for one of the 15 ADR §8 subcommands, a separate Phase-3-only kernel-demo command, or just shorthand in ROADMAP? | |
| Move to wrap-up (Recommended) | Capture the inconsistency as a planner-discretion item in CONTEXT.md with ADR §8 marked canonical. | ✓ |
| More questions about CLI scope | Another round (e.g., color-coded deprecation warnings via UI module, TOML `[legacy]` table interaction with deprecated flags). | |

**User's choice:** Move to wrap-up
**Notes:** `reconftw run` vs ADR §8 inconsistency captured as deferred / planner-discretion item.

---

### Question 6: Ready for context?

| Option | Description | Selected |
|--------|-------------|----------|
| Ready for context (Recommended) | Write CONTEXT.md with the CLI stub-scope decisions captured as locked; deferred items recorded as planner-discretion with sensible defaults grounded in ADR 0002. | ✓ |
| Explore more gray areas | Add another area to discuss — e.g., AxiomBackend depth, spike disposition, end-of-phase demo shape, or plan decomposition. | |

**User's choice:** Ready for context
**Notes:** Single area discussion complete; CONTEXT.md captures D-01 through D-04 as locked + 9 deferred / planner-discretion items.

---

## Claude's Discretion

The following gray areas were identified but not discussed in detail — Claude/researcher/planner resolve with sensible defaults grounded in ADR 0002, REQUIREMENTS.md, the spike code, and the codebase maps:

- **`reconftw run` vs ADR §8 inconsistency** — Default: treat ROADMAP "run" as shorthand for "any subcommand invocation"; ADR §8 is canonical.
- **Plan decomposition strategy** — Default: ~5-6 plans grouped by ARCH-NN domain (matches Phase 2's 7-plan cadence).
- **Spike code disposition** — Default: delete `spike/python/` in Phase 3 plan-01 + keep `spike/go/` until Phase 4 ports first module.
- **End-of-Phase-3 demo shape** — Default: hardcoded-stub `noop.demo` Task proving Scheduler+Backend+Tree+Checkpoint end-to-end.
- **AxiomBackend coverage in Phase 3** — Default: compile-only stub returning `*AxiomFailure` with `ErrAxiomNotImplemented`.
- **Tools.lock seeding** — Default: seed 5-10 tools Phase 4 needs (subfinder, httpx, crt, dnsx, puredns, gotator, anew, asnmap, s3scanner, subzy).
- **Notifier stub depth** — Default: LogSink only + Slack/Telegram/Discord return nil.
- **CI matrix scope** — Default: single-platform (ubuntu-latest amd64) per ADR §9.3 yaml.
- **`interfaces_check/main.go` disposition** — Default: keep until end of Phase 3 as delta detector; delete in Phase 4 plan-01.
- **Performance baseline timing for XCUT-01** — Default: synthetic micro-benchmarks in Phase 3; real bash-v1 baseline deferred to Phase 4.

## Deferred Ideas

All deferred ideas are captured in CONTEXT.md `<deferred>` section. No scope creep redirected during this discussion (user kept tightly focused on CLI subcommand stub scope).
