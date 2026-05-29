---
phase: 04-subdomains-e2e-axiom-integration
plan: "07"
subsystem: parity-harness
tags: [parity, fixtures, b4-fix, d-03, d-04, axiom-09, subd-11, tdd, frozen-replay]
dependency_graph:
  requires:
    - internal/modules/subdomains/passive.go (SubfinderTask, CrtTask — plan-01)
    - internal/modules/subdomains/resolve.go (SubActiveTask — plan-02)
    - internal/modules/subdomains/merge.go (MergeStage — plan-01)
    - internal/core/testutil/mock_backend.go (MockBackend — plan 03-07)
    - internal/core/testutil/mock_output_tree.go (MockOutputTree.Lines — plan 03-07)
    - internal/core/backend/failover.go (FailoverBackend — plan-06)
    - internal/core/backend/axiom_test.go (existing axiom tests — plan-06)
  provides:
    - internal/modules/subdomains/parity_test.go: frozen-replay parity harness
    - internal/modules/subdomains/testdata/fixtures/: v1-capture-gated fixture stubs
    - internal/core/backend/axiom_test.go: TestAxiomEquivalence (AXIOM-09)
  affects:
    - Phase 4 acceptance gate: human live sign-off required before marking phase complete
    - CI gate: parity tests SKIP on fixture stubs; flip to PASS after live capture
tech_stack:
  added: []
  patterns:
    - "B4 fix: provenanceCheck rejects fixtures without '# captured-from:' header or containing ct-log/approximated/certificate transparency/synthetic keywords"
    - "D-03: frozen-replay parity via MockBackend + real v1-captured fixtures (stubs now, real data after capture)"
    - "D-04: per-category parity checked — passive (subfinder+crt), resolved (puredns), takeover (dnstake)"
    - "v1ReferenceReducer: reads raw v1 output and produces expected category counts for parity assertion"
    - "AXIOM-09: mockAxiomBackend simulates fleet shard-merge; asserts axiom path == local path from same fixtures"
    - "TestLiveSignoff: PARITY_LIVE=1 manual gate — always skipped in CI"
    - "writeMockFixtureDir: bridges human-readable fixture layout to MockBackend directory structure"
key_files:
  created:
    - internal/modules/subdomains/parity_test.go
    - internal/modules/subdomains/testdata/fixtures/passive/hackerone.com.subfinder.txt
    - internal/modules/subdomains/testdata/fixtures/passive/hackerone.com.crt.txt
    - internal/modules/subdomains/testdata/fixtures/resolved/hackerone.com.puredns.txt
    - internal/modules/subdomains/testdata/fixtures/takeover/hackerone.com.dnstake.jsonl
    - internal/modules/subdomains/testdata/fixtures/passive/tesla.com.subfinder.txt
    - internal/modules/subdomains/testdata/fixtures/passive/tesla.com.crt.txt
    - internal/modules/subdomains/testdata/fixtures/resolved/tesla.com.puredns.txt
    - internal/modules/subdomains/testdata/fixtures/passive/maintainer.subfinder.txt
    - internal/modules/subdomains/testdata/fixtures/resolved/maintainer.puredns.txt
  modified:
    - internal/core/backend/axiom_test.go (TestAxiomEquivalence + TestAxiomEquivalence_FailoverFallback)
decisions:
  - "Fixture stubs use TODO headers — parity tests t.Skip (not t.Fail) until maintainer captures real v1 data"
  - "provenanceCheck first-line-only inspection: header must be on line 1 of the fixture file"
  - "v1ReferenceReducer deduplicates across merged fixture pairs (subfinder+crt) for accurate reference count"
  - "MockOutputTree (testutil) used for parity tests — provides Lines() assertion method (mockTree in scope_crosscheck_test.go lacks Lines())"
  - "TestAxiomEquivalence uses inline fixture data (not testdata/ fixture files) — axiom equivalence tests input invariance, not v1 parity"
  - "AXIOM-09 split into two tests: direct equivalence + FailoverBackend fallback parity"
requirements-completed:
  - SUBD-11
  - AXIOM-09
metrics:
  duration: "12 minutes"
  completed: "2026-05-29"
  tasks_completed: 2
  files_changed: 11
---

# Phase 4 Plan 07: Frozen-Replay Parity Harness + AXIOM-09 Equivalence Test Summary

Parity harness (D-03) with B4-compliant v1-capture-gated fixture stubs and AXIOM-09 output-equivalence test; phase acceptance gated on human live sign-off at the checkpoint.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Parity harness + fixture stubs (B4 fix) | bb8dc38 | parity_test.go, 9 fixture stub files |
| 2 | AXIOM-09 equivalence test + FailoverBackend parity | e20aed1 | axiom_test.go |

## What Was Built

### Frozen-Replay Parity Harness (parity_test.go)

**provenanceCheck (B4 fix):**
- `t.Skip` on empty or `# TODO:` placeholder fixtures
- `t.Fatalf` on missing `# captured-from:` header
- `t.Fatalf` on forbidden source keywords: `ct-log`, `approximated`, `certificate transparency`, `synthetic`
- CT-log data path completely removed — no fallback to any alternative source

**v1ReferenceReducer:**
- `"passive"` / `"resolved"`: unique non-empty non-comment lines (v1 tool output format)
- `"takeover"`: JSONL lines with non-empty `host` field
- Used as expected count — never test-generated expectations (REVIEWS finding fixed)

**TestPassiveParity** (table-driven):
- Targets: hackerone.com, tesla.com, maintainer
- Each subtest: load fixture bytes → provenanceCheck → writeMockFixtureDir → run SubfinderTask + CrtTask + MergeStage → assert v2 count == v1ReferenceReducer count (tolerance=0, deterministic CI)
- v1ReferenceReducerMerged: deduplicates subfinder+crt counts for true reference

**TestResolveParity** (table-driven):
- Targets: hackerone.com, tesla.com, maintainer
- Run SubActiveTask (Stream) + MergeStage("resolved") → assert v2 resolved count == v1 reference

**TestTakeoverParity:**
- Targets: hackerone.com
- provenanceCheck on dnstake JSONL fixture; JSONL count assertion (deferred to after capture)

**TestLiveSignoff** (PARITY_LIVE=1 gate):
- Always skipped in CI
- Manual gate with step-by-step instructions for human comparison (bash v1 vs v2, ±5% per category)

**writeMockFixtureDir:**
- Strips comment lines from fixture content (mirrors real tool stdout)
- Writes to `<tempDir>/<toolName>/<scenario>.txt` for MockBackend resolution

### Fixture Stubs (testdata/fixtures/)

All 9 fixture files are placeholder stubs with `# TODO: capture from:` headers. Correct capture commands documented in parity_test.go header. Parity subtests t.Skip on these stubs — correct CI behavior until maintainer runs live captures.

No CT-log, certificate transparency, synthetic, or hand-authored data committed (B4 compliant).

### AXIOM-09 Equivalence Test (axiom_test.go)

**TestAxiomEquivalence:**
- mockAxiomBackend simulates fleet sharding/merging by delegating to inner MockBackend
- Asserts: axiom-simulated run produces same line set as direct local run from same fixture
- Inline fixture data (5 lines including 1 duplicate) — not testdata/ files (axiom tests input invariance, not v1 parity)

**TestAxiomEquivalence_FailoverFallback:**
- FailoverBackend with Primary=failingPrimary (always AxiomFailure) + Fallback=axiomFixtureBackend
- Asserts: fallback result set == direct local result set (AXIOM-09 fallback path)

**splitLines helper:** splits Exec stdout bytes into non-empty trimmed lines (used by both AXIOM-09 tests).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Design] mockTree lacks Lines() method**
- **Found during:** Task 1 compilation — parity test needed Lines() to count v2 subdomain records
- **Issue:** `mockTree` in scope_crosscheck_test.go has only `appendCalled` + `appendLines` fields; no `Lines() []string` method
- **Fix:** Used `testutil.MockOutputTree` (which has `Lines()`) for parity tests instead of the local `mockTree`
- **Files modified:** parity_test.go

**2. [Rule 1 - Design] Task 2 creates axiom_test.go tests inline (not separate file)**
- **Found during:** Task 2 — axiom_test.go already exists from plan-06 with package `backend_test`
- **Issue:** Plan says "Create internal/core/backend/axiom_test.go" but file already exists with existing tests
- **Fix:** Added TestAxiomEquivalence + helpers to existing axiom_test.go as appended section; no conflicts with plan-06 tests
- **Files modified:** axiom_test.go

## Verification Results

- `go test -race ./internal/modules/subdomains/... -run "TestPassiveParity|TestResolveParity"` — exits 0 (all subtests t.Skip on placeholders — correct behavior)
- `go test -race ./internal/core/backend/... -run "TestAxiomEquivalence"` — exits 0 (PASS)
- `go build ./...` — exits 0
- `go build -o /tmp/reconftw-p4 ./cmd/reconftw` — exits 0
- `go vet ./...` — exits 0
- `grep "provenanceCheck" parity_test.go` — match
- `grep "ct-log.*Fatalf\|t.Fatalf.*provenance" parity_test.go` — match (B4 enforcement)
- `grep "AXIOM-09\|equivalence" axiom_test.go` — match
- `grep "PARITY_LIVE\|TestLiveSignoff" parity_test.go` — match
- No test-helper redeclarations (splitLines is new; axiomFixtureBackend is new; mockAxiomBackend is new)
- All cfg.* fields verified against config.go

## Known Stubs

| File | Stub | Reason |
|------|------|--------|
| testdata/fixtures/passive/hackerone.com.subfinder.txt | `# TODO: capture from: reconftw.sh -d hackerone.com -s` | Requires live bash v1 run; captured by maintainer at sign-off |
| testdata/fixtures/passive/hackerone.com.crt.txt | `# TODO: capture from: crt -d hackerone.com` | Requires live crt tool run |
| testdata/fixtures/resolved/hackerone.com.puredns.txt | `# TODO: capture from: reconftw.sh -d hackerone.com -s` | Requires live bash v1 run |
| testdata/fixtures/takeover/hackerone.com.dnstake.jsonl | `# TODO: capture from: reconftw.sh -d hackerone.com -s` | Requires live bash v1 run |
| testdata/fixtures/passive/tesla.com.subfinder.txt | `# TODO: capture from: reconftw.sh -d tesla.com -s` | Requires live bash v1 run |
| testdata/fixtures/passive/tesla.com.crt.txt | `# TODO: capture from: crt -d tesla.com` | Requires live crt tool run |
| testdata/fixtures/resolved/tesla.com.puredns.txt | `# TODO: capture from: reconftw.sh -d tesla.com -s` | Requires live bash v1 run |
| testdata/fixtures/passive/maintainer.subfinder.txt | `# TODO: capture from: reconftw.sh -d <maintainer-controlled-target> -s` | Maintainer target not yet designated |
| testdata/fixtures/resolved/maintainer.puredns.txt | `# TODO: capture from: reconftw.sh -d <maintainer-controlled-target> -s` | Maintainer target not yet designated |

All stubs cause parity subtests to t.Skip (not t.Fail). Parity tests flip to PASS once maintainer captures and commits real fixture data (replacing TODO headers with `# captured-from:` headers).

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced by this plan. Fixture files contain no credentials or sensitive data (public bug-bounty targets with public subdomain sets).

## Self-Check: PASSED

- internal/modules/subdomains/parity_test.go — exists; provenanceCheck enforces B4; v1ReferenceReducer; TestPassiveParity/TestResolveParity/TestTakeoverParity; TestLiveSignoff PARITY_LIVE gated; writeMockFixtureDir
- testdata/fixtures/ — all 9 fixture stub files exist with TODO headers
- internal/core/backend/axiom_test.go — TestAxiomEquivalence + TestAxiomEquivalence_FailoverFallback added; splitLines helper; axiomFixtureBackend; mockAxiomBackend
- Commits bb8dc38 and e20aed1 verified in git log
- go build ./... exits 0
- go vet ./... exits 0
- All 15 test packages PASS (parity tests SKIP on stubs — correct)
