# Phase 9: Composite Modes - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-11
**Phase:** 9-Composite Modes
**Areas discussed:** Composite orchestration model, zen/deep config derivation, Stateful modes scope, Batch + v1 alias dispatch + passive guarantee, XCUT-07 todo fold

---

## Todo Cross-Reference

| Option | Description | Selected |
|--------|-------------|----------|
| Fold into Phase 9 | XCUT-07 L2 redactor no-op on dry-run/quiet/piped paths; Phase 9 dry-run prints subprocess args that can contain secrets | ✓ |
| Leave deferred | Keep as standalone backlog item | |

**User's choice:** Fold into Phase 9 → captured as D-10.

---

## Composite orchestration model

| Option | Description | Selected |
|--------|-------------|----------|
| Boot-once composite handler | Extract boot vs run-stages seam; one AppContext/scheduler/workspace/checkpoint/summary per composite run; PARALLEL_MAX_JOBS honored across the whole run | ✓ |
| Sequential re-call of RunXAsync | recon = call RunSubsAsync→RunWebAsync→RunOSINTAsync; minimal new code but re-loads config N×, fresh scheduler per pipeline, N summaries | |
| You decide | Defer to research/planning | |

**User's choice:** Boot-once composite handler → D-01.
**Notes:** Requires extracting the inlined stage loop + afterBoot wiring from the four runXCmd/RunXAsync into a run-stages-on-booted-app function. Per-pipeline stage order + best_effort policy preserved verbatim.

---

## zen/deep config derivation

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory override functions | applyZenProfile/applyDeepProfile pure transforms after load, before Boot; composable; no new TOML surface | ✓ |
| Named TOML profile presets | Embedded reconftw_zen.toml/reconftw_deep.toml preset layers in the loader chain | |
| Reuse PerfProfile only | zen→perf_profile=low, deep→max+Deep=true; simplest but under-delivers stealth | |

**User's choice:** In-memory override functions → D-02.

**Follow-up — precedence (zen vs explicit user config):**

| Option | Description | Selected |
|--------|-------------|----------|
| Mode overrides win | zen forces low rates/opsec regardless of file config; stealth is a guarantee | ✓ |
| User file config wins | Mode overrides act as defaults only; explicit user values respected | |

**User's choice:** Mode overrides win → D-03.

---

## Stateful modes scope

| Option | Description | Selected |
|--------|-------------|----------|
| gen-resolvers + refresh-cache full; quick-rescan thin | gen-resolvers + refresh-cache self-contained; quick-rescan force-refresh re-run, diff reporting → Phase 10 | ✓ |
| Build all three fully now | Phase 9 also implements incremental diff vs last full scan; duplicates Phase 10 diff engine | |
| gen-resolvers only; defer cache+rescan to Phase 10 | Tightest scope but leaves MODE-06/07 unfulfilled (roadmap change) | |

**User's choice:** gen-resolvers + refresh-cache full; quick-rescan thin → D-04/D-05/D-06.
**Notes:** quick-rescan's "new artefacts only" diff reporting is an explicit cross-phase dependency on Phase 10's diff engine.

---

## Batch + v1 alias dispatch + passive guarantee

**Q1 — --list batch semantics:**

| Option | Description | Selected |
|--------|-------------|----------|
| Sequential, isolated workspace per target, continue-on-error | One target at a time; per-target failure logs + continues; non-zero exit if any failed; per-target summary | ✓ |
| Sequential, fail-fast | Abort whole batch on first failure | |
| Concurrent targets | Parallel targets under shared ceiling; heavier than single-operator model | |

**User's choice:** Sequential, isolated, continue-on-error → D-07.

**Q2 — v1 alias dispatch + passive guarantee:**

| Option | Description | Selected |
|--------|-------------|----------|
| Pre-cobra translation + passive hard-guard | Arg-rewrite layer translates v1 forms→v2 invocations before cobra; MarkDeprecated warning kept; passive backend-level hard-guard blocks active exec | ✓ |
| Root RunE dispatch + passive by composition only | Dispatch in root RunE; passive relies on task-subset selection alone | |

**User's choice:** Pre-cobra translation + passive hard-guard → D-08/D-09.

---

## Claude's Discretion

- Name/signature of the extracted stage-runner seam and composite handler.
- Exact cfg fields applyZenProfile/applyDeepProfile each touch.
- Composite unified-summary format + cross-pipeline progress UI composition.
- refresh-cache cache-key/storage mechanism + covered entries.
- Per-target batch summary table format + exit-code aggregation.

## Deferred Ideas

- Findings-diff engine / "new artefacts only" reporting → Phase 10 (MON-*/REPORT-*).
- Monitor loop / incremental re-run engine → Phase 10.
