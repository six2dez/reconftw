# reconFTW

## What This Is

reconFTW is a comprehensive bash-based reconnaissance automation framework used by bug bounty hunters, penetration testers, and security researchers. It orchestrates 70+ external security tools (Go, Python, Rust) across subdomain enumeration, web probing, OSINT, and vulnerability scanning, producing structured per-target output trees with optional Axiom distributed execution, AI reporting, monitor/incremental mode, and Slack/Telegram/Discord notifications.

## Core Value

Run one command, get a complete recon picture of a target — passive, active, and vulnerability layers — with resumable checkpoints, structured output, and zero-touch tool orchestration.

## Current Milestone: v2.0 — Complete Core Migration (Bash → Go)

**Language: Go** — Decided: ADR 0001 (signed 2026-05-28). Spike measured 6 metrics (M1-M6 + MCP); noise band within 25% → tie-breaker DEC-04 invoked (single-binary distribution advantage). See `.planning/decisions/0001-language.md`.

**Goal:** Reescribir reconFTW completo de bash a Go, preservando 100% de la funcionalidad existente, las 70+ herramientas orquestadas, todos los modos, integraciones, y comportamiento observable. Termina cuando el nuevo reconFTW es funcionalmente equivalente o superior al actual y puede sustituirlo en `main`.

**Por qué migrar:** Cuatro dolores estructurales del bash actual motivan el rewrite:
1. **Robustez & refactor** — Sin tipos, sin tests sólidos a nivel de unidad lógica, vars globales por todos lados; refactorizar 30+ módulos es ruleta rusa.
2. **Concurrencia & estado** — `parallel_funcs` + globals compartidos + checkpoints + axiom = estado frágil con race conditions sutiles y debugging brutal.
3. **Packaging & cross-platform** — Bash 4.3+, GNU coreutils en macOS, install.sh enorme, dependencias no pineadas, BSD vs GNU diff sin parar.
4. **Onboarding & velocidad de cambio** — Pocas personas leen 3000 líneas de bash con globals y source guards a gusto; cada cambio se siente arriesgado.

**Target features (17 deliverables — el roadmapper los desglosa en ~14-18 phases internas):**

1. **ADR de lenguaje** — Research + spike paralelo Go vs Python (mismo PoC en ambos) + comparativa medible + decisión firmada
2. **Arquitectura v2** — Diseño completo: módulos como unidades primera clase, scheduler paralelo, checkpoint engine, config TOML, output tree rediseñado, plugin/tool registry, observability, test strategy, packaging
3. **Foundation/scaffolding** — CLI con paridad de flags, config loader, scheduler con throttle+heartbeat+timeout, checkpoint engine, validators/sanitizers, structured logging con redaction de secrets, output tree writer, test framework, CI inicial
4. **`--subdomains` E2E** — Passive + brute + permutations + dnsx + scope filter + takeover + s3buckets + geo_info + ASN mapping, **paridad medible** contra bash
5. **`--web` E2E** — Probe + screenshots + fuzz + JS analysis + nuclei + WAF detection + sourcemaps + favicon recon + ~20 funciones, **paridad medible** contra bash
6. **`--vulns` E2E** — XSS (dalfox), SQLi (sqlmap/ghauri), SSRF, LFI, SSTI, CRLF, smuggling, command injection, nuclei DAST, cache poisoning, fuzz params
7. **`--osint` E2E** — Domain info, IP info, emails, GitHub dorks/leaks/actions audit, cloud enum (AWS/GCP/Azure), Postman leaks, Spoofy, msftrecon, CMSeeK
8. **Modos compuestos** — `-r/--recon`, `-a/--all`, `-p/--passive`, `--zen`, `--deep`, `--quick-rescan`, `--refresh-cache`, `--gen-resolvers`
9. **Axiom integration** — `axiom_launch`, `axiom_shutdown`, `axiom_selected`, `resolvers_update`, `axiom-exec`, failover wrapper, fleet sizing
10. **Monitor mode** — `--monitor`, `--monitor-interval`, `--monitor-cycles`, `--incremental`, diff detection, notification triggers
11. **Reporting** — JSON/HTML/CSV reports, AI report (opt-in vía OpenAI/Anthropic), Faraday export, hotlist risk scoring
12. **Notifications** — Slack/Telegram/Discord vía `notify`, secret redaction en logs y mensajes
13. **Installer & deps** — Reemplazo de `install.sh`: instalación de 70+ herramientas externas (Go tools, Python tools, system deps, Rust toolchain)
14. **Cross-platform** — Linux (Debian/Ubuntu/RHEL/Arch) + macOS (Apple Silicon + Intel) — single binary (Go) o paquete uv (Python)
15. **Docker** — Imagen Docker actualizada con el nuevo binario/paquete
16. **Cutover & migración** — Plan de cutover con bug-bug parity test + 1-2m beta period, packaging final, MIGRATION.md, migrador REQUERIDO `reconftw.cfg` → TOML con corpus testing de 20+ configs reales bloqueando cutover, 6 meses de compat symlinks `Recon/<domain>/`
17. **MCP server** *(añadido 2026-05-27 por decisión del usuario)* — Model Context Protocol server (`reconftw mcp serve`) que expone los modos de recon como tools MCP; auth por API key con redaction de secrets; resource limits via scheduler global; SARIF-compatible findings; OpenAPI schema; opt-in en config (default off). Promueve EMG-15 OpenAPI schema (requerido por MCP) a v2.0.

**Working model:**
- **Branch:** `rewrite/v2` desde `dev` HEAD — rama larga; sustituye `main` al hacer cutover
- **`main` policy:** Frozen — sólo bugfixes críticos/seguridad. Todo lo nuevo va a `rewrite/v2`.
- **Compatibilidad:** Rediseñar con libertad — nueva CLI, nueva config (TOML), nuevo output tree; migrador opcional para usuarios actuales
- **Cadencia:** Sin entregables intermedios shippables. El nuevo reconFTW no es utilizable hasta que todos los modos están portados. Decisión consciente.
- **Tamaño estimado:** 12-18 meses trabajando en solitario; los phases internos del roadmap son los checkpoints reales de pivot/parada.

## Requirements

### Validated

<!-- Shipped capabilities verified in the existing codebase. -->

- ✓ **Multi-mode entry** — `recon`, `passive`, `subs`, `web`, `osint`, `vulns`, `all`, `zen`, `monitor`, `deep` modes via getopt CLI (`reconftw.sh`)
- ✓ **Subdomain enumeration** — Passive sources, brute force, permutations, takeover detection, zone transfer, scope filtering (`modules/subdomains.sh`)
- ✓ **Web analysis pipeline** — Probing, screenshots, fuzzing, JS analysis, nuclei templates, WAF detection, source-map extraction (`modules/web.sh`)
- ✓ **Vulnerability scanning** — XSS (dalfox), SQLi (sqlmap/ghauri), SSRF, LFI, SSTI, CRLF, smuggling, nuclei DAST (`modules/vulns.sh`)
- ✓ **OSINT collection** — Domain info, emails, GitHub leaks, GitHub Actions audit, cloud bucket enumeration, dorking (`modules/osint.sh`)
- ✓ **Axiom distributed mode** — Fleet provisioning, transparent dispatch via `axiom-scan`, axiom→local failover wrapper (`modules/axiom.sh`)
- ✓ **Parallel execution** — `parallel_funcs` job manager with throttling, heartbeat, configurable log modes (`lib/parallel.sh`)
- ✓ **Checkpoint resumability** — Per-function `.called_fn/.funcname` sentinels skip completed work on resume
- ✓ **Output verbosity controls** — `OUTPUT_VERBOSITY` 0/1/2, `--quiet`/`--verbose`, `PARALLEL_LOG_MODE` summary|tail|full
- ✓ **Structured reporting** — JSON/HTML/CSV reports, AI report (opt-in), Faraday export, hotlist risk-scoring, incremental diff
- ✓ **Notifications** — `notify` integration for Slack/Telegram/Discord with secret redaction
- ✓ **Input safety** — `lib/validation.sh` sanitizers reject shell metacharacters in all user-supplied domains/IPs/list entries
- ✓ **Config layering** — `reconftw.cfg` defaults + `secrets.cfg` overlay + `$CUSTOM_CONFIG` + CLI overrides re-applied post-config
- ✓ **Cross-platform** — Linux (Debian/Ubuntu/RHEL/Arch) and macOS (auto re-exec under Homebrew Bash 4+)
- ✓ **Docker support** — `Docker/Dockerfile` Ubuntu 24.04 base with full toolchain
- ✓ **Test suite** — 351 bats tests (246 unit + 71 integration + 34 security) across 35 files
- ✓ **CI integration** — GitHub Actions: shellcheck, unit-fast, integration-smoke per push; weekly integration-full
- ✓ **Pre-commit hygiene** — shellcheck + shfmt + semgrep enforced via hooks
- ✓ **Comprehensive audit (2026-03)** — CLI override pattern unified, XSS in HTML report fixed, dead code removed, scope filter sed-escape, parallel-safe timing, transfer() opt-in gate
- ✓ **UI overhaul** — Dot-fill status format, silent `start_func`, single-line dependency summaries, parallel group rebalancing
- ✓ **Resilience: interrupted-run recovery** — `.inprogress_*` sentinel at `start_func`, rename to checkpoint at `end_func`, gated `_RECON_CLEAN_EXIT` clean-exit semantics so SIGINT/SIGTERM preserves the indicator (Phase 1 / RESIL-01 / 2026-05-13)
- ✓ **Resilience: mid-run disk-full detection** — Boundary-only `df` check at `start_func`/`end_func` + `_abort_disk_full` with structured ENOSPC error (Phase 1 / RESIL-02 / 2026-05-13)
- ✓ **Resilience: per-job timeout in `parallel_funcs`** — `PARALLEL_JOB_TIMEOUT_SECONDS` enforcement decoupled from verbosity gate; `_kill_tree` walks `pgrep -P` children-first so the underlying tool dies, not just the wrapper (Phase 1 / RESIL-03 / 2026-05-13)
- ✓ **Perf: DNS timeout defaults** — `DNS_BRUTE_TIMEOUT=6h`, `DNS_RESOLVE_TIMEOUT=4h` defaults shipped in `reconftw.cfg`; `_run_dns_with_heartbeat` honors them (Phase 1 / PERF-02 / 2026-05-13)
- ✓ **Security: `safe_count()` eval vector removed** — `safe_count()` helper deleted from `lib/common.sh` (17-line block including `eval` branch); 3 bats tests dropped; 5 doc files updated; `count_lines()`/`count_lines_stdin()` are now the canonical line-count helpers (Phase 2 / SEC-01 / 2026-05-13)
- ✓ **Security: notification curl quoting hardened** — `sendToNotify()` in `modules/core.sh` fully-quoted (every `$1`, `$NOTIFY_CONFIG`, `$discord_url`, `$slack_channel`, `$slack_auth`, telegram URL, `-F` pair); `shellcheck --severity=error` clean (Phase 2 / SEC-02 / 2026-05-13)
- ✓ **Security: `AXIOM_EXTRA_ARGS` array refactor** — Global `AXIOM_EXTRA_ARGS_ARR` parsed once in `reconftw.sh` (early + post-config); 21 sites in `modules/subdomains.sh` + 17 sites in `modules/web.sh` migrated to `"${AXIOM_EXTRA_ARGS_ARR[@]}"`; explicit tokenisation, no word-splitting (Phase 2 / SEC-03 / 2026-05-13)
- ✓ **Security: installer SHA256 verification + tools.lock** — `verify_sha256()` gates rustup/uv bootstrappers (opt-in via `RUSTUP_INSTALLER_SHA256` / `UV_INSTALLER_SHA256` env vars); `tools.lock` manifest pins 11 stability-critical Go tools (nuclei, httpx, ffuf, puredns, subfinder + dalfox, katana, dnsx, naabu, interactsh-client, tlsx); `install_tools()` reads it before each `go install` (Phase 2 / SEC-04 / 2026-05-13)
- ✓ **Fix: axiom-exec mantra path case** — `Brosck/mantra` → `brosck/mantra` at `modules/web.sh:2331`; local `install.sh:gotools` and remote `modules/web.sh:axiom-exec` paths now agree on lowercase (Phase 2 / FIX-01 / 2026-05-13)

### Active

<!-- v2.0 Complete Core Migration deliverables — driven through phases in ROADMAP.md. -->

- [x] **Language ADR** — Spike paralelo Go vs Python + comparativa medible + decisión firmada. **Go chosen** (ADR 0001, 2026-05-28)
- [x] **Architecture v2** — Diseño de módulos, scheduler, checkpoint engine, config TOML, output tree, plugin/tool registry, observability, test strategy. **Locked in ADR 0002, signed 2026-05-28.**
- [ ] **Foundation/scaffolding** — CLI, config loader, scheduler paralelo, checkpoint engine, validators, structured logging con redaction, output tree writer, test framework, CI
- [ ] **`--subdomains` E2E ported** — Passive + brute + permutations + dnsx + scope + takeover + s3buckets + geo_info + ASN, paridad bash medida
- [ ] **`--web` E2E ported** — Probe + screenshots + fuzz + JS + nuclei + WAF + sourcemaps + favicon + 20 funciones, paridad bash medida
- [ ] **`--vulns` E2E ported** — XSS, SQLi, SSRF, LFI, SSTI, CRLF, smuggling, command injection, nuclei DAST, cache poisoning, fuzz params
- [ ] **`--osint` E2E ported** — Domain/IP info, emails, GitHub dorks/leaks/actions audit, cloud enum, Postman leaks, Spoofy, msftrecon, CMSeeK
- [x] **Composite modes** — `-r/--recon`, `-a/--all`, `-p/--passive`, `--zen`, `--deep`, `--quick-rescan`, `--refresh-cache`, `--gen-resolvers`. Validated in Phase 9: Composite Modes (2026-06-11)
- [ ] **Axiom integration** — Launch/shutdown/selected, resolvers update, axiom-exec, failover wrapper, fleet sizing
- [ ] **Monitor mode** — `--monitor`, `--monitor-interval`, `--monitor-cycles`, `--incremental`, diff detection, notification triggers
- [ ] **Reporting** — JSON/HTML/CSV reports, AI report (OpenAI/Anthropic), Faraday export, hotlist risk scoring
- [ ] **Notifications** — Slack/Telegram/Discord vía notify-equivalent, secret redaction en logs y mensajes
- [ ] **Installer & deps** — Reemplazo de `install.sh`: 70+ herramientas externas (Go tools, Python tools, system deps, Rust toolchain)
- [ ] **Cross-platform** — Linux (Debian/Ubuntu/RHEL/Arch) + macOS (Apple Silicon + Intel)
- [ ] **Docker** — Imagen Docker actualizada con el nuevo binario/paquete
- [ ] **Cutover & migration** — Plan de cutover (bug-bug parity test + beta 1-2m + community sign-off), packaging final, MIGRATION.md, migrador REQUERIDO `reconftw.cfg` → TOML con corpus testing de 20+ configs reales, 6 meses compat symlinks
- [ ] **MCP server** — Model Context Protocol server (`reconftw mcp serve`); expone modos recon como tools MCP; auth por API key + redaction; SARIF-compat findings; OpenAPI schema; opt-in en config

### Out of Scope

<!-- Explicit boundaries to prevent scope creep. -->

- **Active exploitation / payload delivery** — reconFTW maps attack surface and flags candidate vulns; weaponized exploitation belongs in user-driven tooling
- **GUI / web dashboard** — CLI-first by design; report HTML is read-only output, not an interactive UI. (Nota: dirs `reconftw-web/` y `web/` en working tree son experimentación separada, no parte de v2.0)
- **Real-time streaming results** — Output is file-based and post-run; live dashboards would require a fundamentally different architecture
- **Multi-user collaboration** — Single-operator CLI tool; team workflows handled by external systems (Faraday, custom report aggregation)
- **Cloud SaaS hosting** — Self-hosted CLI by design; Axiom is opt-in distributed execution, not managed hosting
- **Replacing individual tools** — Wraps existing best-of-breed tools rather than re-implementing subfinder/nuclei/httpx/etc. (Aplica a v2.0 también — las 70+ herramientas siguen siendo binarios externos invocados vía subprocess)
- **Drop-in CLI compat con bash** — v2 rediseña libremente CLI/config/output tree; migrador opcional cubre usuarios actuales pero no se garantiza paridad de flags exacta
- **Backporting v2 features a bash** — Bash en `main` queda frozen; mejoras del rewrite no se portan atrás
- **bash v1.0 audit phases 3-5 (PERF-01, FIX-02, TEST-01/02/03, DOCS-01/02)** — Superseded por v2.0 migration; los issues se resuelven by design en el rewrite (single scope impl, tipos en scheduler, tests en framework nuevo, config nueva)
- **bash refactor/cleanup activos previos** (thread-count caps, test coverage del bash, docs hidden tunables, scope-check unification) — Superseded por v2.0 migration: el rewrite tiene esos problemas resueltos by design

## Context

**Project lineage** — Long-running open-source fork maintained by six2dez at `github.com/six2dez/reconftw`, used widely in bug bounty / pentesting communities. Active issue tracker, PR flow, weekly integration tests.

**Recent trajectory:**
- 2026-03: Comprehensive audit — CLI override unification, dead-code removal (`parallel_run`, `parallel_vulns_full`, `parallel_subdomains_full`), security hardening (XSS in HTML report, scope filter sed-escape, transfer() opt-in gate), parallel-safe timing in `start_func`/`end_func`, pushd/popd → subshell migration
- UI overhaul — Dot-fill status format, single-line dependency summaries, parallel group rebalancing (zonetransfer + favicon parallel), removal of redundant `resolvers_update_quick_*` calls
- 2026-05: Codebase mapped via `/gsd-map-codebase` (`.planning/codebase/*`)
- 2026-05: v1.0 audit milestone partially shipped — Phase 1 (Resilience) + Phase 2 (Security Quoting) merged. Phases 3-5 (Concurrency Caps, Test Coverage, Docs Alignment) **superseded** by v2.0 migration.
- 2026-05-27: **v2.0 milestone initialized** — Decision to migrate the framework completely from bash to Go/Python via language spike + complete rewrite on `rewrite/v2` branch. 4 parallel research agents (Stack, Features, Architecture, Pitfalls) + synthesizer produced `.planning/research/` foundation. Requirements defined: 17 deliverables, ~120 REQ-IDs, MCP server added as #17 per user decision.

**Existing intel** — `.planning/codebase/ARCHITECTURE.md`, `STACK.md`, `STRUCTURE.md`, `CONVENTIONS.md`, `TESTING.md`, `CONCERNS.md`, `INTEGRATIONS.md` are the authoritative source for system behaviour. The CONCERNS.md inventory is the primary driver for the Active requirements above.

**Technical environment** — Bash 4.3+ (macOS auto re-execs under Homebrew bash), Go ≥ 1.21, Python ≥ 3.7, `uv` package manager, optional Rust/Cargo for `smugglex`. ~5GB disk, ~1GB RAM minimum. bats-core for testing, shellcheck + shfmt + semgrep for hygiene.

## Constraints

- **Tech stack**: Bash 4.3+ — Required for `wait -n`, `mapfile`, associative arrays. macOS users must have Homebrew bash; auto re-exec is best-effort.
- **External tools**: 70+ runtime dependencies — Most install via `go install @latest` (no version pinning), which is convenient but a known supply-chain risk.
- **Single process**: All modules sourced into one shell — No subshell isolation between modules; all state shared via globals. Workflow functions must save/restore globals they override (see `passive()` pattern).
- **Resume semantics**: Checkpoint files are touch-once at `end_func` — Interrupted functions re-run from scratch on next invocation; partial outputs are not detected.
- **Single-operator**: Designed for one user per target run — No locking, no multi-user state, no concurrent runs against the same target dir.
- **Output stability**: `Recon/<domain>/` tree is a public contract — Subdirectory names and filenames are consumed by downstream pipelines, scripts, and parsers; renames are breaking changes.
- **macOS compatibility**: GNU coreutils + GNU sed + GNU getopt required — System BSD versions are not supported.
- **CI budget**: Integration-full is weekly cron — Unit + smoke are per-push; adding heavy integration tests must respect this split.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Brownfield GSD initialization | Codebase is mature, mapped, and actively maintained — questioning-driven greenfield setup would discard known context | ✓ Good |
| CONCERNS.md drove v1.0 audit Active requirements | Audit inventory already classified severity and provided remediation guidance — used it as the backlog instead of re-deriving | ⚠️ Superseded — v2.0 migration resuelve los mismos issues de raíz; phases 3-5 del audit no se ejecutan |
| Audit-mode milestone first (not features) | The 2026-03 audit surfaced concrete reliability/security gaps that blocked confident feature work | ✓ Good — Phase 1+2 entregaron las mejoras críticas (resilience, security quoting, supply-chain hygiene) en bash antes del rewrite |
| Skip domain research (for v1.0) | Bash recon tooling is the maintainer's own domain; codebase already documents stack/architecture; further research would not change v1.0 requirements | ✓ Good |
| Coarse granularity / parallel execution | Few, broader phases align with single-maintainer cadence; parallel plans inside a phase reduce calendar time | ✓ Good |
| **2026-05-28 — v2.0 architecture: ADR 0002** | All v2 contracts locked in a signed architecture doc: TOML schema (~290-310 v1 flags 1:1 + `[legacy]` aliases + per-key validation), `workspaces/<target-id>/` output tree + 6mo compat symlinks, BINDING `Task` / `Backend` / `AppContext` interfaces, 7-class error hierarchy, `failure_policy` per module group, cobra CLI with v1 short-flag aliases deprecated to v2.2.0, 4-ring test policy, type-level `Secret` + sink-level `RedactingHandler` logging. Pre-sign gate (4 checks: ARCH-NN coverage, TOML parse, Go compile, glossary) passes. See `.planning/decisions/0002-architecture-v2.md`. | ✓ Decided |
| **2026-05-28 — v2.0 language: Go** (ADR 0001) | Spike measured 6 metrics vs Python; noise band within 25% → tie-breaker DEC-04 invoked (single-binary distribution wins). ADR signed by six2dez. See `.planning/decisions/0001-language.md` + `spike/measurement-worksheet.md` | ✓ Decided |
| **v2.0 — Complete migration of reconFTW from bash to Go** | Cuatro dolores estructurales (robustez, concurrencia, packaging, onboarding) no se resuelven incrementalmente en bash sin un esfuerzo desproporcionado; un rewrite con tipos + concurrencia nativa + packaging único es la solución de raíz | — Pending |
| **Single mega-milestone v2.0 (no v2.0→v2.5 staging)** | User priorizó "migrar todo" sobre "ship en fases" — milestone único acepta el riesgo (12-18m sin entregable shippable) a cambio de coherencia arquitectural y evitar arrastrar bash+nuevo lang en paralelo más tiempo del necesario | — Pending |
| **Lenguaje elegido vía spike paralelo Go vs Python** | No comprometerse a un lenguaje antes de medirlo en el problema real; el spike PoC del mismo slice en ambos lenguajes da evidencia comparable de ergonomía/concurrencia/packaging/dev velocity | ✓ Go — ADR 0001 signed 2026-05-28 |
| **Rediseñar libremente CLI/config/output tree** | La oportunidad de arreglar lo que en bash no se podía cambiar sin romper usuarios; migrador opcional cubre la transición de configs | — Pending |
| **Bash en `main` frozen durante la migración** | Evita arrastrar paralelamente bash+nuevo lang más tiempo del necesario; sólo bugfixes críticos/security en `main` hasta cutover de `rewrite/v2` | — Pending |
| **Branch larga `rewrite/v2` desde `dev` HEAD** | Mantiene planning artifacts y v1.0 audit shipped accessible; rewrite construye desde el último estado conocido bueno del bash | — Pending |
| **CLI surface: subcommands primary + v1 short flags como deprecated aliases** | Convención 2026 (ProjectDiscovery, Amass, recon-ng); preserva muscle memory v1 con warning de deprecación por 2 minor versions para migración suave | — Pending |
| **Config migrator REQUIRED + corpus testing de 20+ configs reales bloqueando cutover** | Pitfall top-5: "usuario pierde customizaciones" = rewrite muerto al arrancar. Corpus testing es el único escudo creíble; unknown keys producen warnings ruidosos, NUNCA silent drop | — Pending |
| **MCP server INCLUIDO en v2.0 como deliverable #17 (mandatory, opt-in via config)** | Decisión proactiva por dirección AI 2026+; expande deliverables 16→17; promueve OpenAPI schema (EMG-15) de v2.1+ a v2.0 porque MCP lo necesita; opt-in en config (default off) preserva opcionalidad para usuarios hostiles a IA | — Pending |
| **Cutover criterion: bug-bug parity test + 1-2 mes beta period + community sign-off** | Equilibra rigor (parity automated test contra 3-5 canonical targets) con realismo (no 100% match imposible por ordering/timing); beta period detecta lo que tests automáticos no ven | — Pending |
| **Output tree: nuevo `workspaces/<target-id>/` + 6 meses compat symlinks `Recon/<domain>/`** | Permite rediseño limpio (tipos JSONL, atomic writes, schema versioning) sin romper scripts downstream de usuarios; ventana de 6m forzada por compat symlink writer | — Pending |
| **Installer: rewrite completo en el lenguaje elegido, NO bootstrap shell** | El bash `install.sh` v1 es uno de los pain points en Constraints; rewrite con `tools.lock` + SHA-256 verification es uno de los wins más claros del milestone | — Pending |
| **Performance acceptance: within 10% bash v1 throughput en canonical benchmark** | Orchestration es I/O-bound — ambos langs deberían matchear bash en throughput; 10% margin acepta overhead de tipos sin permitir regresión silenciosa | — Pending |
| **Resource budget: Go binary <50MB OR Python uv tool <500MB; RSS <2GB en typical load** | Establece techo medible; previene scope creep en dependencias | — Pending |
| **Test parity: feature-parity coverage de 351 bats scenarios + branch coverage gate** | NO line-for-line port (bats no traduce 1:1); cubre los escenarios funcionales con framework nativo nuevo | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-27 after milestone v2.0 (Complete Core Migration) initialization + requirements definition (17 deliverables including MCP server)*
