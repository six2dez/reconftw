---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Complete Core Migration
status: planning
last_updated: "2026-05-27T08:53:24.897Z"
last_activity: 2026-05-27
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-27)

**Core value:** Run one command, get a complete recon picture of a target — passive, active, and vulnerability layers — with resumable checkpoints, structured output, and zero-touch tool orchestration.
**Current focus:** Milestone v2.0 — Complete Core Migration (Bash → Go/Python). Defining requirements after milestone init.

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-05-27 — Milestone v2.0 started

## Performance Metrics

**v2.0 milestone (active):**

- Total plans completed: 0
- Phases planned: TBD (roadmapper assigns)
- Total execution time: 0.0 hours

**v1.0 milestone (archived 2026-05-27):**

- Phases shipped: 2 of 5 (Phase 1 Resilience, Phase 2 Security Quoting). Phases 3-5 superseded by v2.0 migration.
- Plans shipped: 8 (5 in Phase 1, 3 in Phase 2). Archived at `.planning/phases.archive/v1.0-audit-hardening/`.

**Recent Trend:**

- Last 5 plans: v1.0 audit hardening — shipped reliability + security fixes to bash before rewrite
- Trend: Closed v1.0 early; opened v2.0 (full rewrite)

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting v2.0 work:

- v2.0 init: Migrate complete reconFTW from bash to Go/Python — robustez/concurrencia/packaging/onboarding no se resuelven incrementalmente en bash sin esfuerzo desproporcionado
- v2.0 init: Single mega-milestone (no v2.0→v2.5 staging) — usuario priorizó coherencia arquitectural sobre entregables intermedios
- v2.0 init: Lenguaje vía spike paralelo Go vs Python — no decidir hasta tener PoC comparativa en ambos
- v2.0 init: Rediseñar libremente CLI/config/output tree — migrador opcional para usuarios actuales
- v2.0 init: Bash en `main` frozen — sólo bugfixes críticos/seguridad hasta cutover
- v2.0 init: Rama larga `rewrite/v2` desde `dev` HEAD — mantiene planning + bash de referencia
- v1.0 close: Phases 3-5 (PERF-01, FIX-02, TEST-01/02/03, DOCS-01/02) superseded by v2.0 — los issues se resuelven by design en el rewrite

### Pending Todos

None yet.

### Blockers/Concerns

- **Decisión de lenguaje pendiente** — Hasta firmar el ADR del spike Go vs Python, todas las decisiones de arquitectura están bloqueadas (config format, scheduler API, test framework, packaging). El ADR es el primer phase del milestone.

## v2 Architecture Considerations (from v1.0 deferred backlog)

Items captured durante v1.0 que deben informar el diseño de arquitectura v2 (no son requirements directos — son input al design phase):

| Category | Item | Application to v2 |
|----------|------|-------------------|
| Architecture | Old ARCH-01: split `modules/web.sh` (2965 lines) | v2 module boundaries deben ser <500 LOC por módulo desde el inicio; web pipeline split en sub-módulos (probe, fuzz, JS, screenshots, sourcemaps) |
| Architecture | Old ARCH-02: file-based secret handling | v2 NUNCA pasar secrets como CLI args; siempre via env, file flag, o stdin. Diseñar API de tools wrapper para forzarlo. |
| Scaling | Old SCALE-01: memory-aware permutation throttling | v2 scheduler debe tener back-pressure: limitar input al subproceso si la RAM disponible cae bajo umbral |
| Scaling | Old SCALE-02: resolver-file health gate for puredns | v2 debe pre-validar resolvers antes de pasarlos a puredns; abort si <N resolvers funcionan |
| Observability | Old OBS-01: surface venv health in startup summary | v2 (si elige Python) debe verificar venv health al startup; (si Go) compilación elimina el problema |
| Observability | Old OBS-02: structured JSONL events at every module boundary by default | v2 estructurado por defecto desde el día 1, no opt-in |

## Session Continuity

Last session: 2026-05-27 — Milestone v2.0 initialized
Stopped at: Defining requirements (post milestone setup)
Resume file: .planning/PROJECT.md + .planning/REQUIREMENTS.md (to be written)
