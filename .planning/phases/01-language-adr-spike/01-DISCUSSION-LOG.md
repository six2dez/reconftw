# Phase 1: Language ADR & Spike - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-27
**Phase:** 1-language-adr-spike
**Areas discussed:** Timebox, Sign-off, Post-ADR cleanup

---

## Area Selection

The orchestrator presented 4 gray areas for Phase 1. The user selected one.

| Gray Area | Description | Selected for discussion |
|---|---|---|
| Slice exact composition | Passive source count, httpx probe depth, kill-tree test setup (mock vs real) | (deferred to planner / researcher) |
| Comparison metrics & tie-breaker | Per-metric weighting, killer-feature overrides, honest dev-velocity measurement | (deferred to planner) |
| Spike harness & repo layout | Directory structure, shared test corpus, comparison runner | (deferred to planner) |
| Timebox, sign-off, post-ADR | Hard timebox or open-ended, sign-off scope, STACK/ARCHITECTURE collapse strategy | ✓ |

User's note: deferred areas are acceptable for downstream agents to resolve with sensible defaults grounded in DEC-01 through DEC-05 + research files.

---

## Timebox

| Option | Description | Selected |
|--------|-------------|----------|
| Tight: 1 week per lang | ~1 calendar week per lang (2 weeks total). Forces discipline; spike is NOT the implementation, only viability + ergonomics. If undone in window, stop and use what's built. Recommended for keeping focus. | ✓ |
| Standard: 2 weeks per lang | ~2 weeks per lang (4 weeks total). Margin for tests + benchmarks + polish. Risk: scope creep → spike becomes partial implementation. | |
| Soft total: 4 weeks | 4 weeks total, divide as needed — one lang can take more if the other moved faster. More flexible but less comparable (one lang might receive more attention). | |
| Open-ended: until clear | No timebox — work until the comparison is conclusive. Pro: maximum depth. Contra: spike can consume 2-3 months unnoticed (known PITFALL in rewrites). | |

**User's choice:** Tight — 1 week per lang (2 weeks total)
**Notes:** Hard limit. If either language isn't done in its 1-week window, stop and use what was built. Spike-scope-creep is a known failure mode in rewrites; tight gate at this phase prevents milestone drift.

---

## Sign-off

| Option | Description | Selected |
|--------|-------------|----------|
| Solo, same day | User signs the ADR after the spike. No community review. Fast (1-2 hours writing the ADR post-spike). Recommended for solo-maintainer project with tight timebox. | ✓ |
| Solo + post-ADR community announce | User signs (decision made) then publishes the ADR as GitHub Discussion / Release note after, opening a feedback channel without blocking. Telegraphs the decision + provides context. | |
| GitHub Discussion pre-sign | Post draft ADR + spike numbers as GitHub Discussion. 1-week feedback window, then sign (could change decision if a strong argument surfaces). Pro: community buy-in early. Contra: bikeshed risk. | |
| ADR PR + self-review | Open PR with the ADR against `rewrite/v2`; wait N days for comments; self-merge. Provides visible audit trail in GitHub UI but no real review gate (sole approver is the maintainer). | |

**User's choice:** Solo, same day
**Notes:** Single-maintainer project. Pre-sign community review adds bikeshed risk that conflicts with the tight timebox already chosen. Optionally publish ADR post-decision as a Release note for community visibility, but not gated.

---

## Post-ADR Cleanup (DEC-05 operationalization)

| Option | Description | Selected |
|--------|-------------|----------|
| Archive loser, delete in main | Move loser-lang sections to `.planning/research.archive/0001-language-spike-{loser}/` (preserving comparison work); edit STACK/ARCHITECTURE/SUMMARY in-place to show only winner. Consistent with how v1.0 was archived. Recommended. | |
| Delete loser permanently | Delete all loser content from research files. Clean but loses spike evidence (LoC counts, metrics, decision rationale) — ADR is sole source of historical truth. | ✓ |
| Keep both with banner | Edit SUMMARY.md to single-lang but keep STACK/ARCHITECTURE with both langs + a "CHOSEN: X, Y kept for reference" banner. More noise but zero loss. Risk: confusion for new readers. | |
| Hybrid: SUMMARY collapsed, files archived | Rewrite SUMMARY.md from scratch with winner (concise). Archive full STACK/ARCHITECTURE to `research.archive/`. Write new STACK/ARCHITECTURE in-place with only winner. More work but cleanest output. | |

**User's choice:** Delete loser permanently
**Notes:** ADR is the single source of historical truth. The spike code under `spike/{loser}/` is a separate decision (left to planner) — D-03 only covers research files.

---

## Claude's Discretion

The user explicitly deferred these gray areas to downstream agents (researcher / planner). Defaults must be grounded in REQUIREMENTS.md DEC-01 through DEC-05 + the research files.

- **Slice exact composition** — Researcher surfaces the tradeoffs in `01-RESEARCH.md` (which passive sources, how many; httpx depth; kill-tree test setup); planner locks the answer in `01-PLAN.md`.
- **Comparison metrics weighting + tie-breaker precision** — Planner defines per-metric rubric and any killer-feature overrides in `01-PLAN.md`, grounded in DEC-03 (5 metrics) + DEC-04 (default Go-wins-25%-noise tie-breaker).
- **Spike harness / repo layout** — Planner designs `spike/{lang}/` structure, shared test corpus (target list + expected outputs), and comparison runner script (Makefile / bash / Python) in `01-PLAN.md`.

## Deferred Ideas

Ideas surfaced during discussion that belong outside Phase 1.

- **Spike-code cleanup (`spike/{loser}/`)** — Whether to delete or archive the losing language's spike code is a planner-level decision; not part of D-03 (which only covers research files). Resolve in `01-PLAN.md`.
- **MCP library availability cross-check** — During the spike, researcher must verify both langs have a usable MCP library (Phase 8 dependency). If one lang has materially worse MCP support, that's a tie-breaker signal beyond the default 25% noise band. Surface this in `01-RESEARCH.md` before spike implementation.
- **Public ADR announcement** — Posting the signed ADR as a GitHub Release note for community visibility is OPTIONAL and orthogonal to Phase 1 sign-off. Decide closer to Phase 12 cutover comms.

---

*Discussion conducted: 2026-05-27 via `/gsd:discuss-phase 1` (default interactive mode)*
*Areas presented: 4 — areas selected by user: 1 — gray areas deferred to downstream: 3*
