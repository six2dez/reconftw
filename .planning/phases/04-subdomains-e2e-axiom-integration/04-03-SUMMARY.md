---
phase: 04-subdomains-e2e-axiom-integration
plan: "03"
subsystem: subdomains-scraping-extractors
tags: [subdomains, scraping, pure-transform, tdd, staging-contract, temp-file-pattern, d02]
dependency_graph:
  requires:
    - internal/modules/subdomains/doc.go (staging contract — plan-00)
    - internal/modules/subdomains/passive.go (SubdomainRecord type — plan-01)
    - internal/modules/subdomains/resolve.go (writeResolvedStagingFile helper — plan-02)
    - internal/core/config: cfg.Subdomains.Scraping.Enabled, cfg.Subdomains.Analytics.Enabled, cfg.Subdomains.NSDelegation.Enabled (verified fields)
    - internal/core/backend: Runner.Run (no stdin field — temp-file pattern required)
    - internal/core/appctx: Target.WorkDir for temp file and staging paths
  provides:
    - internal/extract/favicon/favicon.go: Extract(rawOutput, domain) — pure transform
    - internal/extract/js/js.go: Extract(rawOutput, domain) — pure transform
    - internal/extract/analytics/analytics.go: Extract(rawOutput, domain) — pure transform
    - internal/modules/subdomains/scraping.go: SubScrapingTask, SubAnalyticsTask, SubNSDelegationTask
  affects:
    - internal/modules/subdomains/ (3 new Tasks registered in task.Default)
tech_stack:
  added: []
  patterns:
    - D-02 pure-transform extractor package API: Extract(rawOutput []byte, domain string) ([]Result, error)
    - Temp-file pattern for subjs→jsluice: raw/subjs.tmp.txt intermediate (no stdin)
    - SubdomainRecord JSON lines written to inputs/resolved.<tool>.txt (staging contract)
    - anchored inScope() helper duplicated in each extractor (intentional — zero cross-package deps)
key_files:
  created:
    - internal/extract/favicon/favicon.go
    - internal/extract/favicon/favicon_test.go
    - internal/extract/js/js.go
    - internal/extract/js/js_test.go
    - internal/extract/analytics/analytics.go
    - internal/extract/analytics/analytics_test.go
    - internal/modules/subdomains/scraping.go
    - internal/modules/subdomains/scraping_test.go
decisions:
  - "inScope() helper duplicated in each extract package rather than shared — preserves zero-import pure-transform guarantee (no internal/core/* dependency)"
  - "SubScrapingTask writes SubdomainRecord JSON lines (not raw hostnames) to resolved.scraping.txt — JSON format required because scraping sources include hash/URL metadata useful to Phase 5"
  - "SubNSDelegationTask parses dnsx -ns -resp output for delegated zone identification; skips base domain (already covered by zonetransfer task); returns StatusSkipped (not StatusErrored) when subdomains.txt absent"
  - "writeScrapingStagingFile (scraping.go) is separate from writeResolvedStagingFile (resolve.go) — scraping uses JSON lines; resolution tasks use raw hostname lines; different downstream consumers"
  - "subjs run with -i - placeholder args (subjs does not accept domain directly in all invocations); actual input wiring is Phase 5 concern when web probed URL list is available"
metrics:
  duration: "15 minutes"
  completed: "2026-05-29"
  tasks_completed: 2
  files_changed: 8
---

# Phase 4 Plan 03: Pure Extractor Packages + Scraping/Analytics/NSDelegation Tasks Summary

3 pure-transform extractor packages (favicon, js, analytics) created as D-02 shared interface; 3 scraping/analytics/delegation Tasks registered using staging files and temp-file subjs→jsluice pipeline; Phase 5 reuse contract established.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Pure extractor package tests | ce0403ac | favicon_test.go, js_test.go, analytics_test.go |
| 1 (GREEN) | Pure extractor package implementations | c274cb46 | favicon.go, js.go, analytics.go |
| 2 (RED) | Scraping/analytics/ns_delegation task tests | 5e6e14e6 | scraping_test.go |
| 2 (GREEN) | SubScrapingTask + SubAnalyticsTask + SubNSDelegationTask | c5ab17be | scraping.go |

## What Was Built

**Task 1 — 3 pure extractor packages (D-02 shared interface):**

- `internal/extract/favicon/favicon.go`: `Extract(rawOutput []byte, domain string) ([]Result, error)`
  - Parses favirecon output format: `<hash> <subdomain>` per line
  - Filters to in-scope subdomains (anchored match: `host == domain || HasSuffix(host, "."+domain)`)
  - Returns `[]Result{Subdomain, Hash}` — Hash field included for Phase 5 favicon correlation
  - NO imports from internal/core/* (pure transform)

- `internal/extract/js/js.go`: `Extract(rawOutput []byte, domain string) ([]Result, error)`
  - Parses jsluice JSON output (one object per line): `{"url":"...","kind":"URL",...}`
  - Extracts hostname from `url` field via `url.Parse()`, filters to in-scope
  - Returns `[]Result{Subdomain, URL}` — URL anchor available for Phase 5
  - Secret/endpoint fields in jsluice output are intentionally NOT surfaced here (T-04-03-02)

- `internal/extract/analytics/analytics.go`: `Extract(rawOutput []byte, domain string) ([]Result, error)`
  - Parses analyticsrelationships output: `<domain> <UA-ID>` per line
  - Handles `|__ ` prefix variant; filters to in-scope subdomains
  - Returns `[]Result{Subdomain, TrackingID}` — TrackingID for Phase 5 pivoting

All three: empty input returns `[]Result{}` (not nil, not error). All tests pass with `-race`.

**Task 2 — 3 scraping/analytics/delegation Tasks:**

- `SubScrapingTask` (`subdomains.scraping`): Enabled by `cfg.Subdomains.Scraping.Enabled`
  - Step 1: run `favirecon -d domain` → `favicon.Extract` → collect candidates
  - Step 2a: run `subjs` → collect stdout to temp file `raw/subjs.tmp.txt`
  - Step 2b: run `jsluice urls -i raw/subjs.tmp.txt` (NOT stdin pipe) → `js.Extract` → collect
  - Step 2c: `defer os.Remove(tmpPath)` cleans up temp file
  - Writes `SubdomainRecord` JSON lines to `inputs/resolved.scraping.txt`
  - NO `app.Tree.Append` calls (staging contract)

- `SubAnalyticsTask` (`subdomains.analytics`): Enabled by `cfg.Subdomains.Analytics.Enabled`
  - Runs `analyticsrelationships -d domain` → `analytics.Extract`
  - Writes `SubdomainRecord` JSON lines to `inputs/resolved.analytics.txt`

- `SubNSDelegationTask` (`subdomains.ns_delegation`): Enabled by `cfg.Subdomains.NSDelegation.Enabled`
  - Reads `subdomains/subdomains.txt` as input list (returns StatusSkipped if absent)
  - Runs `dnsx -l subsFile -ns -resp -silent` to find NS delegations
  - Parses delegated zones (subdomains with NS records, excluding base domain)
  - Writes raw hostnames to `inputs/resolved.ns_delegation.txt`

All 3 Tasks: 3 `task.Register()` calls in `init()` functions.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Design Notes

**1. inScope() duplicated across extract packages (intentional — not a deviation)**
- **Reason:** The pure-transform guarantee (no internal/core imports) means the scope helper cannot be shared via a common package without introducing a dependency. Duplicating the 3-line function in each package is the correct tradeoff.
- **Impact:** Anchored match semantics are identical in all three packages.

**2. SubScrapingTask subjs args**
- `subjs` is called with `-i -` placeholder args in scraping.go. The actual probed-URL list that subjs should receive as input is available only after Phase 5 web probing completes. In Phase 4, SubScrapingTask establishes the pipeline structure (temp-file pattern); Phase 5 will wire the actual input URLs. The current implementation will produce empty subjs output (which is correct — no URLs available yet at this stage), but the jsluice temp-file pipeline path is exercised.

## Verification Results

- `go build -o /dev/null ./...` exits 0
- `go test -race ./internal/extract/...` exits 0 — 4 tests per package (12 total), all PASS
- `go test -race ./internal/modules/subdomains/...` exits 0 — all scraping tests PASS
- `grep "Tree\.Append" internal/modules/subdomains/scraping.go` returns only comment lines (no live code)
- `grep "subjs\.tmp\|jsluice.*-i" internal/modules/subdomains/scraping.go` returns match (temp-file pattern)
- `grep -c "task\.Register" internal/modules/subdomains/scraping.go` = 3
- `grep '"github.com/six2dez/reconftw/internal/core' internal/extract/*/` returns no matches (pure transform)
- All 17 target packages PASS with `-race`

## TDD Gate Compliance

- Task 1 RED gate: 3 test files committed (ce0403ac) before any extract/*.go exists — tests fail with "no non-test Go files" (confirmed build failure)
- Task 1 GREEN gate: 3 implementation files committed (c274cb46) — all tests pass
- Task 2 RED gate: scraping_test.go committed (5e6e14e6) before scraping.go — 9 tests fail (tasks not registered)
- Task 2 GREEN gate: scraping.go committed (c5ab17be) — all tests pass

Gate sequence: test (ce0403ac) → feat (c274cb46) → test (5e6e14e6) → feat (c5ab17be)

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: information-disclosure | scraping.go (SubScrapingTask) | jsluice raw output may contain secrets in URL paths; extract/js returns only Subdomain+URL — secret fields in jsluice output are NOT forwarded to SubdomainRecord. T-04-03-02 mitigation in place. Phase 5 handles secret extraction separately. |

## Self-Check: PASSED

- internal/extract/favicon/favicon.go — exists, func Extract exported, no core imports
- internal/extract/js/js.go — exists, func Extract exported, no core imports
- internal/extract/analytics/analytics.go — exists, func Extract exported, no core imports
- internal/modules/subdomains/scraping.go — exists, 3 Task types, 3 init() calls, no Tree.Append live code
- internal/modules/subdomains/scraping_test.go — exists, TestSubScrapingTaskWritesStagingFile, TestSubScrapingTaskUsesTempFileForJsluice, TestNSDelegationTaskEnabledGate
- Commits ce0403ac, c274cb46, 5e6e14e6, c5ab17be verified in git log
