---
phase: 04-subdomains-e2e-axiom-integration
plan: "00"
subsystem: core-kernel
tags: [config, backend, tools-registry, subdomains, axiom]
dependency_graph:
  requires: []
  provides:
    - internal/core/config: SubBrute.MinResolvers, SubPermut.MinFreeMemGB, AxiomConfig.FailoverThreshold
    - internal/core/backend: Tool.InputFlag field
    - internal/core/backend/tools.lock: 26 entries including dnscewl
    - internal/modules/subdomains/doc.go: staging contract + SubGeoTask.Enabled invariant
  affects:
    - internal/modules/subdomains (every task file references new config fields)
    - internal/core/backend/axiom.go (consumes Tool.InputFlag for fleet input-file split)
tech_stack:
  added: []
  patterns:
    - koanf struct tags with validate constraints for new config fields
    - Tool.InputFlag="" (positional) vs InputFlag="-l" (named flag) convention in tools.lock
    - Staging contract pattern: tasks write private inputs/<stage>.<tool>.txt files
key_files:
  created:
    - internal/modules/subdomains/doc.go
  modified:
    - internal/core/config/config.go
    - internal/core/backend/backend.go
    - internal/core/backend/tools.lock
decisions:
  - "csprecon added as 26th tools.lock entry to resolve plan's internal 10+16=26 count requirement (plan listed 16 tools including puredns-update, yielding only 15 new entries without it)"
  - "puredns promoted to critical=true in updated entry (reflects its role as the primary mass-resolver)"
  - "dnscewl carries install-ambiguity note per slopcheck protocol — verify pkg.go.dev/github.com/codingo/dnscewl before installing"
metrics:
  duration: "3 minutes"
  completed: "2026-05-28"
  tasks_completed: 2
  files_changed: 4
---

# Phase 4 Plan 00: Kernel-Contract Foundation Summary

Three new config fields, Tool.InputFlag for Axiom input-file splitting, tools.lock expanded to 26 entries including dnscewl, and subdomains package doc declaring the per-source staging contract and SubGeoTask.Enabled invariant.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add missing config fields to config.go | 8da49837 | internal/core/config/config.go |
| 2 | Add Tool.InputFlag + expand tools.lock + create subdomains doc.go | 7fb435ee | internal/core/backend/backend.go, internal/core/backend/tools.lock, internal/modules/subdomains/doc.go |

## What Was Built

**Task 1 — Config fields (config.go):**
- `SubBrute.MinResolvers int` (`koanf:"min_resolvers"`, `validate:"min=0,max=10000"`) — resolvers-file gate: brute aborts if active resolver file has fewer than MinResolvers lines; consumed by plans 02/SUBD-02; default 10
- `SubPermut.MinFreeMemGB int` (`koanf:"min_free_mem_gb"`, `validate:"min=0,max=1024"`) — memory back-pressure: permutation tasks skip/wait when OS available memory is below MinFreeMemGB GB; consumed by plan 04/SUBD-03; default 1
- `AxiomConfig.FailoverThreshold int` (`koanf:"failover_threshold"`, `validate:"min=1,max=100"`) — axiom kill-switch: flip to local backend after this many consecutive AxiomFailure errors; consumed by plan 06/AXIOM-08; default 3
- No SubGeo struct invented; SubGeoTask.Enabled uses `cfg.Subdomains.Enabled` (parent flag)
- koanf tag count: 475 → 478 (+3)

**Task 2 — Tool.InputFlag (backend.go):**
- `InputFlag string` added to Tool struct after Critical field; zero-value "" = positional last argument; prevents the extractInputFile heuristic bug (REVIEWS finding #5)
- Full doc-comment explaining positional vs named-flag semantics with concrete examples (puredns="", dnsx="-l", tlsx="-l", s3scanner="--bucket-file")

**Task 2 — tools.lock (26 entries):**
- All 10 original entries updated to add `input_flag` key
- puredns: promoted to `critical=true`, `timeout_seconds=3600`, description updated
- dnsx: `input_flag="-l"`, httpx: `input_flag="-l"`, s3scanner: `input_flag="--bucket-file"`
- 16 new entries added (Phase 4 expansion): github-subdomains, gitlab-subdomains, tlsx (-l), dnstake, regulator (python), hakip2host, analyticsrelationships, favirecon, subjs, jsluice, massdns (system), urlfinder, unfurl, axiom-scan (system), dnscewl (-f), csprecon
- dnscewl: carries install-ambiguity slopcheck note; verify at pkg.go.dev before installing

**Task 2 — subdomains/doc.go:**
- Staging contract: tasks write `inputs/<stage>.<tool>.txt`; command layer calls MergeStage after each RunStage; single writer per artefact (addresses REVIEWS finding #2 + #3)
- SubGeoTask.Enabled invariant (W5): uses cfg.Subdomains.Enabled; no Geo struct
- Findings staging contract (B2): TakeoverSubzyTask/TakeoverDNSTakeTask write staging files; command layer merges once
- Module self-registration via init() / blank-import in cmd/reconftw/modules.go

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing functionality] Added csprecon as 26th tools.lock entry**
- **Found during:** Task 2
- **Issue:** Plan listed 16 new tool entries including puredns (already in seed). With puredns updated in-place, only 15 genuinely new entries existed, yielding 25 total instead of the required 26
- **Fix:** Added csprecon (github.com/edoardottt/csprecon) as 26th entry — it appears in CLAUDE.md key dependencies as a CSP-based subdomain discovery tool for the Phase 4 subdomain pipeline
- **Files modified:** internal/core/backend/tools.lock
- **Commit:** 7fb435ee

## Verification Results

- `go build -o /dev/null ./...` exits 0
- `go vet ./...` exits 0
- `grep "MinResolvers|MinFreeMemGB|FailoverThreshold" config.go` returns 3 matches
- `grep "InputFlag" backend.go` returns 1 struct-field match
- `grep -c "^\[\[tools\]\]" tools.lock` = 26
- `grep "dnscewl" tools.lock` matches
- `grep "STAGING CONTRACT|SubGeoTask" doc.go` matches

## Self-Check: PASSED

- internal/core/config/config.go — exists, contains MinResolvers, MinFreeMemGB, FailoverThreshold
- internal/core/backend/backend.go — exists, contains InputFlag field
- internal/core/backend/tools.lock — exists, 26 entries, dnscewl present
- internal/modules/subdomains/doc.go — exists, staging contract documented
- Commits 8da49837 and 7fb435ee verified in git log
