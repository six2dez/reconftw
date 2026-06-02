---
phase: 05-web-pipeline-e2e
plan: "06"
subsystem: web-pipeline-testing
tags: [parity, smoke-test, realtools, fixtures, d-w7, dod-1]
dependency_graph:
  requires: [05-02, 05-03, 05-04, 05-05]
  provides: [WEB-16-parity-harness, DoD-1-smoke-coverage]
  affects: [internal/modules/web, internal/core/backend, internal/core/testutil]
tech_stack:
  added: []
  patterns: [frozen-replay-parity, synthetic-fixture, stub-with-skip, d-w9-arg-vector-golden]
key_files:
  created:
    - internal/modules/web/parity_test.go
    - internal/modules/web/testdata/fixtures/httpx/httpx_hackerone.jsonl
    - internal/modules/web/testdata/fixtures/nuclei/nuclei_hackerone.jsonl
    - internal/modules/web/testdata/fixtures/ffuf/ffuf_hackerone.json
    - internal/modules/web/testdata/fixtures/js/jsluice_urls.jsonl
    - internal/modules/web/testdata/fixtures/js/jsluice_secrets.jsonl
    - internal/modules/web/testdata/fixtures/urls/katana_hackerone.txt
    - internal/modules/web/testdata/fixtures/waf/wafw00f_hackerone.txt
    - internal/core/testutil/web_mock.go
  modified:
    - internal/core/backend/smoke_test.go
    - internal/modules/web/csprecon.go
    - internal/modules/web/hakoriginfinder.go
    - internal/modules/web/mantra.go
decisions:
  - "Synthetic fixtures committed for jsluice_secrets and wafw00f (T-05-20: clearly-fake tokens only)"
  - "Stub fixtures use # TODO: header triggering t.Skip per Phase-4 parity_test.go pattern"
  - "D-W9 golden must match installed binary, not RESEARCH assumption — smoke test caught 3 flag-drift bugs"
  - "hakoriginfinder redesigned to use exec.Command with IPs via stdin + -h <url> (actual tool API)"
metrics:
  duration: "~26 minutes"
  completed: "2026-06-02"
  tasks_completed: 2
  tasks_total: 2
  files_created: 9
  files_modified: 4
---

# Phase 5 Plan 06: Frozen-Replay Parity Harness + DoD-1 Smoke Coverage

Implements the CI hard gate (D-W7, WEB-16) and extends the realtools smoke test to cover all 23 Phase-5 tools (DoD-1). Mirrors Phase 4's parity pattern exactly — frozen fixtures drive deterministic parse/redact logic checks; real arg-vector smoke test catches flag drift before it reaches production.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Frozen-replay parity harness + testdata fixtures | 8f610989 | parity_test.go, testdata/fixtures/*, web_mock.go |
| 2 | DoD-1 smoke_test.go — all 23 Phase-5 tool goldens | 6c248cc1 | smoke_test.go, csprecon.go, hakoriginfinder.go, mantra.go |

## What Was Built

### Task 1: Parity Harness (parity_test.go)

Six sub-tests in `internal/modules/web/parity_test.go`:

| Test | Fixture Type | Status |
|------|-------------|--------|
| TestWebParityHTTPX | Stub (# TODO) | SKIP (clean) |
| TestWebParityNuclei | Stub (# TODO) | SKIP (clean) |
| TestWebParityFFUF | Stub (empty results) | SKIP (clean) |
| TestWebParityWAF | SYNTHETIC | PASS |
| TestWebParityJSSecrets | SYNTHETIC | PASS |
| TestWebParityURLDedup | Stub (# TODO) | SKIP (clean) |

**Synthetic fixture design (T-05-20):**
- `jsluice_secrets.jsonl`: 3 entries with `"value":"FAKE_AWS_AAAA0000BBBBCCCC"` (clearly fake); TestWebParityJSSecrets asserts that `Redacted=="***"` for every record and that the fake raw value never appears in any output field.
- `wafw00f_hackerone.txt`: 4 entries (2 Cloudflare, 2 "(None)"); TestWebParityWAF asserts `(None)` lines are excluded and in-scope Cloudflare hosts are detected.

**testutil/web_mock.go:** Adds `NewWebMockBackend(fixturesDir, scenario, capacity)` helper — thin wrapper over `NewMockBackend` with the same signature shape as the subdomains parity harness.

### Task 2: DoD-1 Smoke Coverage (smoke_test.go)

Extended `TestRealToolArgVectors` with 23 Phase-5 probes (plus nomore403/JSA repo-clone probes via os.Stat). All probes match the REAL Task arg vectors per D-W9.

**Coverage:**
- nuclei (scan + screenshot), ffuf, katana, urlfinder, waymore, urless, p1radup
- subjs, jsluice (urls + secrets), mantra, sourcemapper
- wafw00f, cdncheck, hakoriginfinder, csprecon, favirecon
- VhostFinder, shortscan, Gxss, arjun
- nomore403 (go_clone), JSA (python_venv) — os.Stat path lookup, explicit SKIP log when absent

## Deviations from Plan

### Auto-fixed Issues (Rule 1 — bugs caught by D-W9 smoke test)

**1. [Rule 1 - Bug] csprecon: -i flag does not exist**
- **Found during:** Task 2 (smoke test execution)
- **Issue:** `csprecon.go` used `-i <file>` but installed csprecon v0.4.3 uses `-l`/`-list` for file input
- **Fix:** Changed arg from `-i urlsFile` to `-l urlsFile` in csprecon.go
- **Files modified:** `internal/modules/web/csprecon.go`
- **Commit:** 6c248cc1

**2. [Rule 1 - Bug] hakoriginfinder: -i flag does not exist; actual API is stdin + -h <url>**
- **Found during:** Task 2 (smoke test execution)
- **Issue:** `hakoriginfinder.go` used `-i hostsFile` but the installed tool reads IPs from stdin and requires `-h <target_url>` — completely different design than assumed
- **Fix:** Redesigned task to use `exec.Command` with IPs piped via stdin, target URL via `-h`; added `readIPsFromJSONL()` helper to extract IPs from hosts.jsonl
- **Files modified:** `internal/modules/web/hakoriginfinder.go`
- **Commit:** 6c248cc1

**3. [Rule 1 - Bug] mantra: -i flag does not exist; reads from stdin only**
- **Found during:** Task 2 (smoke test execution)
- **Issue:** `mantra.go` used `-i jsURLsFile` but mantra reads JS URLs from stdin only (no -i flag)
- **Fix:** Changed to `exec.Command` with file content piped via `cmd.Stdin`
- **Files modified:** `internal/modules/web/mantra.go`
- **Commit:** 6c248cc1

These are exactly the class of bug D-W9 was designed to catch: ASSUMED flag names (A5/A14/A15 in RESEARCH) that turned out to be wrong. The smoke test ran real tool invocations and found the flag rejection before any recon could fail silently.

## Threat Surface Scan

No new security-relevant surface introduced. Fixture files contain only:
- Clearly-fake synthetic tokens (no real credentials)
- Stub headers (no data)
- Test infrastructure code (no network endpoints)

## Known Stubs

The following fixtures are stubs pending Plan 05-07 population:
- `testdata/fixtures/httpx/httpx_hackerone.jsonl` — triggers TestWebParityHTTPX t.Skip
- `testdata/fixtures/nuclei/nuclei_hackerone.jsonl` — triggers TestWebParityNuclei t.Skip
- `testdata/fixtures/ffuf/ffuf_hackerone.json` — triggers TestWebParityFFUF t.Skip
- `testdata/fixtures/urls/katana_hackerone.txt` — triggers TestWebParityURLDedup t.Skip

These stubs do NOT prevent the plan's goal: TestWebParityWAF and TestWebParityJSSecrets (the hard-gate tests for parse/redact logic) PASS unconditionally. The stub tests will activate when Plan 05-07 drops in real captures.

## Self-Check: PASSED

- parity_test.go exists: FOUND
- web_mock.go exists: FOUND
- smoke_test.go exists: FOUND
- All fixture dirs populated: FOUND
- Commit 8f610989 exists: FOUND
- Commit 6c248cc1 exists: FOUND
- go build ./... exit 0: VERIFIED
- go test ./... exit 0: VERIFIED
- TestWebParityWAF: PASS
- TestWebParityJSSecrets: PASS
- 23+ Phase-5 probes in smoke_test.go: VERIFIED (47 matching lines, 23 unique probes)
- Phase 5 additions comment present: VERIFIED
- go build -tags realtools ./internal/core/backend/...: VERIFIED
