---
phase: 05-web-pipeline-e2e
plan: "01"
subsystem: web-pipeline
tags: [web, httpx, tools-lock, scaffold, dag-root, cli]
dependency_graph:
  requires: [04-subdomains-e2e-axiom-integration]
  provides: [internal/modules/web, web.httpx Task, tools.lock Phase-5 entries, web subcommand RunE]
  affects: [cmd/reconftw, internal/core/backend/tools.lock, .planning/REQUIREMENTS.md]
tech_stack:
  added: [internal/modules/web package, CtxWithHostsFile context key pattern]
  patterns: [Per-Tool Task init() registration, best_effort pipeline, D-W10 input boundary, context-key flag passing]
key_files:
  created:
    - internal/modules/web/doc.go
    - internal/modules/web/httpx.go
    - internal/modules/web/merge.go
  modified:
    - internal/core/backend/tools.lock
    - cmd/reconftw/modules.go
    - cmd/reconftw/stub_subcommands.go
    - cmd/reconftw/root_test.go
    - .planning/REQUIREMENTS.md
decisions:
  - "D-W4 applied: WEB-02 wording in REQUIREMENTS.md updated from gowitness/killshot to nuclei -headless -id screenshot"
  - "D-W10 input boundary: implemented via context key (CtxWithHostsFile) rather than ExtraFlags (AppContext has no ExtraFlags field)"
  - "D-W12: all web stages are best_effort — runWebCmd logs and continues on stage failures"
  - "T-05-01 mitigation: validateHostsPath rejects paths with .. traversal and verifies file is readable"
metrics:
  duration_minutes: 30
  completed: "2026-06-02T14:27:00Z"
  tasks_completed: 2
  files_changed: 8
---

# Phase 05 Plan 01: Housekeeping + Web Package Scaffold + HTTPXTask + tools.lock Summary

Web pipeline foundation established: REQUIREMENTS.md WEB-02 wording corrected to nuclei-headless (D-W4), 17 Phase-5 tool entries added to tools.lock (D-W13), `internal/modules/web` package created with HTTPXTask as the DAG root (D-W12), MergeStage helper for web artefacts, and `web` subcommand RunE replacing the D-02 stub.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Housekeeping + tools.lock expansion | 321d32c | .planning/REQUIREMENTS.md, internal/core/backend/tools.lock |
| 2 | web package scaffold + HTTPXTask + merge.go + web cmd RunE | c59260da | internal/modules/web/{doc,httpx,merge}.go, cmd/reconftw/{modules,stub_subcommands,root_test}.go |

## What Was Built

### Task 1: Housekeeping

- **REQUIREMENTS.md WEB-02**: Replaced "Screenshots via `gowitness` or `killshot`" with "Screenshots via `nuclei -headless -id screenshot`" per D-W4 (v1 web.sh:327 actually uses nuclei-headless; the requirement was stale).
- **tools.lock**: Appended 17 new Phase-5 tool entries with `# Phase 5 additions (Web Pipeline E2E)` header. Entries cover: katana, nuclei, ffuf, wafw00f, cdncheck, hakoriginfinder, VhostFinder, shortscan, nomore403 (go_clone), mantra, sourcemapper, waymore, urless, p1radup, Gxss, arjun, JSA (python_venv). All `critical=false`.

### Task 2: Web Package Scaffold

**internal/modules/web/doc.go**: Package declaration + staging contract comment documenting best_effort policy (D-W12), DAG root (D-W10 input boundary), and artefact schemas (D-W11). Mirrors subdomains/doc.go shape (D-W2).

**internal/modules/web/httpx.go**: HTTPXTask — the web pipeline DAG root.
- `DependsOn()` returns nil (DAG root per D-W12)
- D-W10 input boundary: checks ctx-carried `--hosts` file → `artefacts/hosts.jsonl` → `artefacts/subdomains.jsonl` → fail-fast error
- Arg vector matches RESEARCH §httpx verbatim: `-follow-host-redirects -random-agent -status-code -p <ports> -threads <n> -rl <n> -timeout <n> -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o <file> -l <input>`
- Parses JSONL output to D-W11 HostRecord schema: `{host, url, scheme, port, status, title, tech[], content_length, ip, cdn}`
- Scope-filters via `app.Tree.InScope()` before `app.Tree.Append("hosts", records)`
- T-05-01: `validateHostsPath` rejects `..` traversal and non-regular files
- `CtxWithHostsFile` context key pattern (no AppContext modification needed)

**internal/modules/web/merge.go**: MergeStage helper for web artefact merge phases. Reads `inputs/<stage>.*.jsonl` staging files, deduplicates by raw JSON line content, calls `app.Tree.Append(stage, records)` once. Also provides `MergeAllWebArtefacts` for post-pipeline consolidation.

**cmd/reconftw/stub_subcommands.go**: Real `newWebCmd()`/`runWebCmd()` replacing the `newStubCmd("web"...)` stub:
- Mirrors `runSubsCmd` structure exactly
- `--hosts string` flag wired via `web.CtxWithHostsFile(ctx, hostsFlag)`
- 4 sequential best_effort stages: probe (httpx), analysis (nuclei/screenshot/ffuf/wafw00f/cdncheck/favirecon/VhostFinder/hakoriginfinder/csprecon), url-discovery (katana/urlfinder/waymore/urldedup/subjs/jsluice/mantra/jsa/sourcemapper), bypass (nomore403/shortscan/gxss/arjun)
- `printWebSummary` and `printWebDryRun` helpers

**cmd/reconftw/modules.go**: Added blank import `_ "github.com/six2dez/reconftw/internal/modules/web"` to trigger HTTPXTask init() registration.

**cmd/reconftw/root_test.go**: Removed "web" from `TestEveryStubReturnsExit64` stubs list (mirrors Phase 4's removal of "subs").

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed TestEveryStubReturnsExit64 test**
- **Found during:** Task 2 `go test ./cmd/reconftw/...`
- **Issue:** The test included "web" in the stubs list, but replacing the stub with a real RunE means web no longer returns *exitCodeError{code:64}
- **Fix:** Removed "web" from the stubs list in root_test.go, added comment mirroring the Phase 4 pattern (how "subs" was removed)
- **Files modified:** cmd/reconftw/root_test.go
- **Commit:** c59260da (included in Task 2 commit)

**2. [Rule 2 - Missing] Context-key pattern instead of ExtraFlags**
- **Found during:** Task 2 implementation
- **Issue:** The plan suggested `app.ExtraFlags["hosts"]` to pass the --hosts flag to HTTPXTask, but AppContext has no ExtraFlags field (would require core modification)
- **Fix:** Used `context.WithValue` pattern via `CtxWithHostsFile(ctx, hostsFlag)` / `hostsFileFromCtx(ctx)` — zero-core-change, idiomatic Go, avoids ADR amendment
- **Files modified:** internal/modules/web/httpx.go (CtxWithHostsFile exported), cmd/reconftw/stub_subcommands.go (call site)

**3. [Rule 2 - Missing] Checkpoint interface has no Mark() method**
- **Found during:** Task 2 implementation
- **Issue:** The plan mentioned `app.Checkpoint.Mark(ctx, t.Name(), inputHash)` but the Interface only has `Begin/Complete/Done`. The scheduler handles checkpointing automatically
- **Fix:** Omitted explicit checkpoint call from HTTPXTask.Run (scheduler owns checkpointing per Phase 3 design). Input hash is logged at Debug level for observability.

## Known Stubs

- `HostRecord.CDN` field is always `""` in HTTPXTask output. This is intentional and documented: the cdncheck Task (Phase 5 plan-03) populates this field. Not a blocking stub — the artefact schema is correct; the field is populated in a later plan.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| T-05-01 mitigated | internal/modules/web/httpx.go | `validateHostsPath` implements file-readable check + path-traversal rejection for user-supplied `--hosts` FILE |
| T-05-02 mitigated | internal/modules/web/httpx.go | httpx stdout routed to run.log via `app.Tools.Run` (GAP-3 pattern); never logged at INFO terminal |

## Self-Check: PASSED

Files verified:
- FOUND: internal/modules/web/doc.go
- FOUND: internal/modules/web/httpx.go
- FOUND: internal/modules/web/merge.go
- FOUND: internal/core/backend/tools.lock

Commits verified:
- FOUND: 321d32c (Task 1)
- FOUND: c59260d (Task 2)

Test gate: go test ./... → all pass (0 failures)
