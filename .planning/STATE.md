---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Complete Core Migration
status: planning
stopped_at: Phase 1 context gathered
last_updated: "2026-05-27T10:31:44.274Z"
last_activity: 2026-05-27 — Roadmap created (12 phases, 197 REQ-IDs mapped)
progress:
  total_phases: 12
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-27)

**Core value:** Run one command, get a complete recon picture of a target — passive, active, and vulnerability layers — with resumable checkpoints, structured output, and zero-touch tool orchestration.
**Current focus:** Milestone v2.0 — Complete Core Migration (Bash → Go/Python). Roadmap created (12 phases, 197 REQ-IDs mapped 100%); next step is planning Phase 1 (Language ADR & Spike).

## Current Position

Phase: Phase 1 — Language ADR & Spike (not started; awaiting plan-phase)
Plan: —
Status: Roadmap complete, awaiting phase planning
Last activity: 2026-05-27 — Roadmap created (12 phases, 197 REQ-IDs mapped)

## Performance Metrics

**v2.0 milestone (active):**

- Phases planned: 12 (coarse granularity; parallelization enabled within phases)
- Total REQ-IDs: 197 (100% mapped to phases)
- Total plans completed: 0
- Total execution time: 0.0 hours

**v2.0 phase status:**

| Phase | Name | Plans Complete | Status | Completed |
|-------|------|----------------|--------|-----------|
| 1 | Language ADR & Spike | 0/? | Not started | - |
| 2 | Architecture v2 Design | 0/? | Not started | - |
| 3 | Foundation Kernel | 0/? | Not started | - |
| 4 | Subdomains E2E + Axiom Integration | 0/? | Not started | - |
| 5 | Web Pipeline E2E | 0/? | Not started | - |
| 6 | Vulnerability Scanning E2E | 0/? | Not started | - |
| 7 | OSINT E2E | 0/? | Not started | - |
| 8 | MCP Server | 0/? | Not started | - |
| 9 | Composite Modes | 0/? | Not started | - |
| 10 | Monitor Mode + Reporting + Notifications | 0/? | Not started | - |
| 11 | Installer + Cross-Platform + Docker | 0/? | Not started | - |
| 12 | Cutover & Migration | 0/? | Not started | - |

**v1.0 milestone (archived 2026-05-27):**

- Phases shipped: 2 of 5 (Phase 1 Resilience, Phase 2 Security Quoting). Phases 3-5 superseded by v2.0 migration.
- Plans shipped: 8 (5 in Phase 1, 3 in Phase 2). Archived at `.planning/phases.archive/v1.0-audit-hardening/`.

**Recent Trend:**

- Last activity: v2.0 milestone initialized, requirements defined (197 REQ-IDs across 17 deliverables), roadmap created (12 phases, 100% coverage)
- Trend: Closed v1.0 early; opened v2.0 (full rewrite); roadmap ready to begin planning

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting v2.0 work:

- v2.0 init: Migrate complete reconFTW from bash to Go/Python — robustez/concurrencia/packaging/onboarding no se resuelven incrementalmente en bash sin esfuerzo desproporcionado
- v2.0 init: Single mega-milestone (no v2.0→v2.5 staging) — usuario priorizó coherencia arquitectural sobre entregables intermedios
- v2.0 init: Lenguaje vía spike paralelo Go vs Python — no decidir hasta tener PoC comparativa en ambos (Phase 1)
- v2.0 init: Rediseñar libremente CLI/config/output tree — migrador opcional para usuarios actuales
- v2.0 init: Bash en `main` frozen — sólo bugfixes críticos/seguridad hasta cutover
- v2.0 init: Rama larga `rewrite/v2` desde `dev` HEAD — mantiene planning + bash de referencia
- v2.0 init: MCP server INCLUIDO como deliverable #17 (opt-in en config, default off)
- v2.0 init: Config migrator REQUIRED + 20-corpus test gate bloqueando cutover
- v2.0 roadmap: 12-phase structure derived from 17 deliverables and 197 REQ-IDs; coarse granularity per config.json; parallelization enabled within phases
- v2.0 roadmap: ADR (Phase 1) and Architecture Design (Phase 2) gate all production code; Foundation (Phase 3) ships kernel; Subdomains+Axiom (Phase 4) is canonical reference port
- v2.0 roadmap: Cutover (Phase 12) explicitly blocked by CUT-04 (migrator corpus) and CUT-12 (sign-off criteria including parity test + beta period)
- v1.0 close: Phases 3-5 (PERF-01, FIX-02, TEST-01/02/03, DOCS-01/02) superseded by v2.0 — los issues se resuelven by design en el rewrite

### Pending Todos

None yet. Next action: run `/gsd:plan-phase 1` to plan Phase 1 (Language ADR & Spike).

### Blockers/Concerns

- **Decisión de lenguaje pendiente** — Phase 1 (Language ADR & Spike) firmará el ADR. Hasta entonces, todas las decisiones de arquitectura (config TOML schema, scheduler API, test framework, packaging) están en standby — Phase 2 las locked.
- **Roadmap calendar risk** — 12 phases over 12-18 months sin entregable shippable intermedio (decisión consciente). Los phases SON los checkpoints reales; sustainability via `/gsd:transition` y `/gsd:complete-milestone` ceremonies.
- **Cross-cutting placement assumptions** — XCUT-01 (perf benchmark) baseline lives in Foundation but final validation is Phase 12; XCUT-03 (test coverage) gate established Phase 3 but final ≥90%-on-critical-paths assertion in Phase 12. Per-phase progress must validate these continuously, not defer all to cutover.
- **Phase 11 Docker base image choice (DOCK-02)** — distroless vs minimal Ubuntu; locked when Phase 11 plans are written (depends partially on Phase 1 ADR outcome — Go favors distroless, Python may prefer ubuntu).

## v2 Architecture Considerations (from v1.0 deferred backlog)

Items captured durante v1.0 que deben informar el diseño de arquitectura v2 (no son requirements directos — son input al design phase):

| Category | Item | Application to v2 |
|----------|------|-------------------|
| Architecture | Old ARCH-01: split `modules/web.sh` (2965 lines) | v2 module boundaries deben ser <500 LOC por módulo desde el inicio; web pipeline split en sub-módulos (probe, fuzz, JS, screenshots, sourcemaps) |
| Architecture | Old ARCH-02: file-based secret handling | v2 NUNCA pasar secrets como CLI args; siempre via env, file flag, o stdin. Diseñar API de tools wrapper para forzarlo. |
| Scaling | Old SCALE-01: memory-aware permutation throttling | v2 scheduler debe tener back-pressure: limitar input al subproceso si la RAM disponible cae bajo umbral (now SUBD-03) |
| Scaling | Old SCALE-02: resolver-file health gate for puredns | v2 debe pre-validar resolvers antes de pasarlos a puredns; abort si <N resolvers funcionan (now SUBD-02) |
| Observability | Old OBS-01: surface venv health in startup summary | v2 (si elige Python) debe verificar venv health al startup; (si Go) compilación elimina el problema (now FOUND-08) |
| Observability | Old OBS-02: structured JSONL events at every module boundary by default | v2 estructurado por defecto desde el día 1, no opt-in (now FOUND-02 / XCUT-09) |

## Session Continuity

Last session: 2026-05-27T10:31:44.268Z
Stopped at: Phase 1 context gathered
Resume file: .planning/phases/01-language-adr-spike/01-CONTEXT.md
