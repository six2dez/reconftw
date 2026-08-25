---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: milestone
status: executing
stopped_at: Phase 14 context gathered
last_updated: "2026-08-18T11:03:36.273Z"
last_activity: 2026-08-18 -- Phase 15 planning complete
progress:
  total_phases: 15
  completed_phases: 12
  total_plans: 117
  completed_plans: 105
  percent: 80
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-27)

**Core value:** Run one command, get a complete recon picture of a target — passive, active, and vulnerability layers — with resumable checkpoints, structured output, and zero-touch tool orchestration.
**Current focus:** Phase 15 — Release Gates: Run Isolation & Store Integrity

## Current Position

Phase: 15 (Release Gates: Run Isolation & Store Integrity) — EXECUTED, NOT SIGNED OFF
Plan: 18 of 18 complete (5 waves)
Status: Gates 1-10 and 12 PASS. Gate 11 SKIPPED (docker not runnable locally; enforced in CI). One regression-guard step FAILS: govulncheck under a local go1.26.1 toolchain while go.mod pins 1.25.13 — toolchain divergence, recorded as a phase decision, module-level vulns all UNREACHABLE.
NEXT: `bash scripts/release-gates.sh` is the cutover gate and currently exits non-zero by design. To sign off Phase 14: (1) resolve the govulncheck toolchain divergence, (2) run gate 11 on real or emulated ARM64 (CI job `docker`, step `Verify image health (linux/arm64)`), (3) triage `.planning/phases/15-release-gates-run-isolation-store-integrity/deferred-items.md` (15 items, one needing a RELEASE NOTE about monitor re-alerting once after upgrade).
KNOWN LIMITATION carried into gate 3a: `hosts` is not emptied on a subs-only/passive run, because `web/httpx.go` owns the empty publish and does not run there. Giving `subdomains/geo.go` the publish would erase web hosts no producer in that run examined — worse.
BLOCKED BEHIND 15: Phase 14 — Cutover & Migration. Its MIGRATION.md must absorb the 8-item deferral ledger from 13-PARITY-AUDIT.md, plus phase-15 path-contract changes (`reports/<target-slug>/<scan-id>/`, slug-named workspaces with one-time legacy adoption).
Last activity: 2026-08-18 -- Phase 15 planning complete

## Performance Metrics

**v2.0 milestone (active):**

- Phases planned: 12 (coarse granularity; parallelization enabled within phases)
- Total REQ-IDs: 197 (100% mapped to phases)
- Total plans completed: 57
- Total execution time: 0.0 hours

**v2.0 phase status:**

| Phase | Name | Plans Complete | Status | Completed |
|-------|------|----------------|--------|-----------|
| 1 | Language ADR & Spike | 5/5 | Complete | 2026-05-28 |
| 2 | Architecture v2 Design | 7/7 | Complete | 2026-05-28 |
| 3 | Foundation Kernel | 0/? | Not started | - |
| 4 | Subdomains E2E + Axiom Integration | 0/? | Not started | - |
| 5 | Web Pipeline E2E | 0/? | Not started | - |
| 6 | Vulnerability Scanning E2E | 0/? | Not started | - |
| 7 | OSINT E2E | 7/7 | Complete | 2026-06-10 |
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
| Phase 04-subdomains-e2e-axiom-integration P00 | 3 | 2 tasks | 4 files |
| Phase 04 P01 | 10m | 2 tasks | 9 files |
| Phase 04 P03 | 15 | 2 tasks | 8 files |
| Phase 04 P04 | 12 | 2 tasks | 8 files |
| Phase 04-subdomains-e2e-axiom-integration P05 | 7 | 2 tasks | 7 files |
| Phase 05-web-pipeline-e2e P01 | 30 | 2 tasks | 8 files |
| Phase 05-web-pipeline-e2e P02 | 35 | 2 tasks | 3 files |
| Phase 06 P01 | 30m | 2 tasks | 9 files |
| Phase 06 P04 | 15m | 2 tasks | 2 files |
| Phase 06 P07 | 20 | 2 tasks | 4 files |
| Phase 06-vulnerability-scanning-e2e P08 | 20m | 2 tasks | 7 files |
| Phase 07 P03 | ~10m | 2 tasks | 10 files |
| Phase 07 P04 | 25m | 2 tasks | 6 files |
| Phase 07 P05 | 6m | 2 tasks | 9 files |
| Phase 07 P07 | 25m | 2 tasks | 4 files |
| Phase 08-mcp-server P02 | 18 | 2 tasks | 6 files |
| Phase 08-mcp-server P03 | 120 | 2 tasks | 7 files |
| Phase 08-mcp-server P04 | 45 | 2 tasks | 11 files |
| Phase 10 P02 | 35 | 2 tasks | 10 files |
| Phase 10 P04 | 25m | 2 tasks | 7 files |
| Phase 13 P03 | ~35m | 2 tasks | 2 files |
| Phase 13 P04 | ~40m | 3 tasks | 4 files |
| Phase 13 P05 | ~35m | 3 tasks | 6 files |
| Phase 13 P06 | ~30m | 1 task (TDD) | 3 files |
| Phase 13 P07 | ~40m | 2 tasks | 6 files |
| Phase 13 P08 | ~55m | 2 tasks | 8 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting v2.0 work:

- Phase 1 ADR (2026-05-28): Chose **Go** per ADR 0001 — 6-metric spike comparison; noise band within 25% → tie-breaker DEC-04 invoked (single-binary distribution wins); measurements at spike/measurement-worksheet.md
- v2.0 init: Migrate complete reconFTW from bash to Go — robustez/concurrencia/packaging/onboarding no se resuelven incrementalmente en bash sin esfuerzo desproporcionado
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
- [Phase ?]: 04-00: csprecon added as 26th tools.lock entry to resolve plan count ambiguity
- [Phase ?]: D-02 pure-transform extractor API: Extract(rawOutput, domain) in internal/extract/{favicon,js,analytics} — no internal/core imports, Phase 5 reuse contract
- [Phase ?]: TakeoverSubzyTask and TakeoverDNSTakeTask write to separate staging files (B2 fix — OutputTree.Append REPLACE semantics prevent concurrent findings writes)
- [Phase ?]: ZoneTransferTask in-Run gate returns StatusSkipped when ZoneTransfer.Enabled==false (REVIEWS #4 fix)
- [Phase ?]: existing config field, not a separate cfg.Web.Fuzz.ThreadsMax
- [Phase ?]: 07-05: identity/fingerprint cluster (OSINT-11 msftrecon, OSINT-12 CMSeeK+favirecon, OSINT-13 gqlspection, OSINT-14 cewler, OSINT-15 xnldorker) + D-O10 metadata fold ported; CMSeeK/favirecon/gqlspection/cewler/metadata are D-O2 opportunistic (read workspace hosts/URLs/docs IF present, log-skip StatusSkipped when absent); xnldorker key-gated D-O8; msftrecon preserves osint/azure_tenant_domains.txt single-writer (D-O5)
- [Phase 7]: 07-07: Phase 7 (OSINT E2E) ACCEPTED 2026-06-10 — DoD-2 real dev-Mac E2E (`scripts/osint-smoke.sh hackerone.com`) maintainer-reproduced VERDICT PASS: 8 osint-class findings (whois×1, third_party_misconfig×6, postman-leak×1) via the multi-writer staging contract; XCUT-07 secret-leak guard CLEAN (1 `value_redacted="***"`, no raw secret); category-presence soft gate evaluates PRESENCE only, counts NOT gated (D-O6); Tree.Append fixed (`19efc4a5`) to admit company-seeded `class=="osint"` records lacking host/url (D-O1) while preserving the strict host/url gate for web/vulns findings; zonetransfer EXCLUDED as relocation-not-regression (D-O10, → MIGRATION.md Phase 12)
- [Phase ?]: MCP session registry concurrency pattern
- [Phase ?]: Auth at correct HTTP layer per RESEARCH Pitfall 1

### Roadmap Evolution

- Phase 15 added (2026-08-14): **Release Gates: Run Isolation & Store Integrity** — remediation of the
  fifth pre-cutover audit. 19 findings independently re-verified against `dev-go` @ `4cedba9` with
  file:line evidence, grouped into 5 workstreams (target identity/run isolation/dry-run purity;
  stream error contract; store integrity + report scoping; MCP correctness; build/supply-chain/CI
  gates). Audit finding #17 (untracked production code) was already resolved by commits `855b6b5`/
  `e602a6e`/`4cedba9` — do not re-open. Full detail and the 12 acceptance gates:
  `.planning/phases/15-release-gates-run-isolation-store-integrity/15-CONTEXT.md`.
  **This phase blocks Phase 14 cutover sign-off.**

### Pending Todos

Next action: run `/gsd-plan-phase 15` (Release Gates: Run Isolation & Store Integrity).

### Blockers/Concerns

- **Roadmap calendar risk** — 12 phases over 12-18 months sin entregable shippable intermedio (decisión consciente). Los phases SON los checkpoints reales; sustainability via `/gsd:transition` y `/gsd:complete-milestone` ceremonies.
- **Cross-cutting placement assumptions** — XCUT-01 (perf benchmark) baseline lives in Foundation but final validation is Phase 12; XCUT-03 (test coverage) gate established Phase 3 but final ≥90%-on-critical-paths assertion in Phase 12. Per-phase progress must validate these continuously, not defer all to cutover.
- **Phase 11 Docker base image choice (DOCK-02)** — distroless vs minimal Ubuntu; locked when Phase 11 plans are written. Go (ADR 0001) favors distroless.
- **Spike code disposition pending Phase 2 plan** — decide whether to delete `spike/python/` tree, archive in a tarball, or leave in git history only — Phase 2 planner decides.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260602-config-explicit-path-warn | Config loader: WARN to WarnSink on explicit --config/--secrets pointing at a missing file (silent-skip→nil preserved) | 2026-06-02 | staged (maintainer) | [260602-config-explicit-path-warn](./quick/260602-config-explicit-path-warn/) |
| 260806-dsp-repo-hygiene-regression-guard-composite | Regression-guard composite passive-merge placement (bug #2, mutation-proven) + gitignore the stray 26MB reconftw-web build binary | 2026-08-06 | working tree (maintainer) | [260806-dsp-repo-hygiene-regression-guard-composite](./quick/260806-dsp-repo-hygiene-regression-guard-composite/) |
| 260806-qxt-vulns-nilres-panic-fix | Fix all-mode `reconftw all` nil-pointer panic (testssl/llm/websocket/fray missing res==nil guard); found by live reconbox3 cutover validation, mutation-proven test, live re-run rc=0 | 2026-08-06 | working tree (maintainer) | [260806-vulns-nilres-panic-fix](./quick/260806-vulns-nilres-panic-fix/) |
| 260810-enq-urls-corpus-double-join | Fix vulns URL-corpus path double-join (readURLsJSONL) — 11 URL-consuming tasks were dead in all/deep ("no URL corpus" despite populated urls.jsonl); mutation-proven test; live re-run rc=0 w/ second_order engaging 1274 targets | 2026-08-10 | working tree (maintainer) | [260810-urls-corpus-double-join](./quick/260810-urls-corpus-double-join/) |
| 260810-pnj-axiom-distribution-fix | PARTIAL: 4 correct+unit-tested --axiom fixes (Exec output read-back RC-A, input detection RC-B, brute→local RC-C, failover wrap) — but live re-test STILL shows brute=0s under --axiom; blocked by a --log-level-debug no-op. Resume in fresh session (see memory RESUME HERE) | 2026-08-10 | working tree (maintainer) | [260810-axiom-distribution-fix](./quick/260810-axiom-distribution-fix/) |
| 260820-uby-resolver-acquisition-cutover-blocker | CUTOVER BLOCKER fix: v2 could not complete a default recon — Paths.Resolvers defaulted to "" so puredns ran `-r "" -rt ""` and aborted the only fail-fast group. Boot-time resolver acquisition (v1 parity), resolvers.health now aborts instead of SKIP, deterministic point-of-use guard in SubActiveTask (the health task was never a barrier — subs-resolve is fully concurrent), + `parity-full.sh --v2-only` to reuse the banked 10h v1 baseline. 24 new tests, each mutation-proven. Parity re-run NOT yet executed | 2026-08-20 | working tree (maintainer) | [260820-uby-resolver-acquisition-cutover-blocker](./quick/260820-uby-resolver-acquisition-cutover-blocker/) |

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

Last session: 2026-07-16T07:51:09.273Z
Stopped at: Phase 14 context gathered
Resume file: .planning/phases/14-cutover-and-migration/14-CONTEXT.md
