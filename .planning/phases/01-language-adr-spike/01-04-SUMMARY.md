---
phase: 01-language-adr-spike
plan: 04
subsystem: spike-comparison
tags:
  - spike
  - adr
  - comparison
  - language-decision
  - go
  - python

dependency_graph:
  requires:
    - 01-02: Go spike measurements (M1-M6 Go half, timebox_complete: true)
    - 01-03: Python spike measurements (M1-M6 Python half, timebox_complete: true)
    - 01-01: compare.sh harness
  provides:
    - spike/comparison.json (canonical hackerone.com measurement, all 6 metrics × 2 langs)
    - spike/.rss_measurements.log (3-run M5 RSS variance log)
    - spike/measurement-worksheet.md (scoring algorithm trace, final verdict)
    - .planning/decisions/0001-language.md (ADR DRAFT, Status: Proposed)
  affects:
    - 01-05: sign-off ceremony will commit all 4 files above + flip ADR to Accepted + apply D-03 collapse
    - Phase 3 Foundation: language is Go (from ADR verdict)

tech-stack:
  added: []
  patterns:
    - "Scoring algorithm: max/min ratio < 1.25 → TIED; ≥3 wins of 4 non-tied → CLEAR WINNER; else NOISE BAND → DEC-04 tie-breaker"
    - "Killer-feature gate checked BEFORE noise-band scoring (B2 fix)"
    - "RSS variance: 3-run CoV; > 25% → inconclusive; both langs < 5% CoV here"

key-files:
  created:
    - spike/comparison.json (canonical hackerone.com run)
    - spike/.rss_measurements.log (3-run RSS data)
    - spike/measurement-worksheet.md (full audit trail)
    - .planning/decisions/0001-language.md (ADR draft)
    - .planning/phases/01-language-adr-spike/01-04-SUMMARY.md (this file)
  modified: []

key-decisions:
  - "Language chosen: Go — DEC-04 noise-band tie-breaker invoked (1-1 split on non-tied metrics; M1/M5/M6 TIED)"
  - "M5 RSS: 3-run CoV < 5% for both langs — conclusive (Go mean 222,251 kB, Python mean 225,301 kB; 1.4% diff, TIED)"
  - "M3: Go 3.0 MB vs Python PyInstaller 12.2 MB — 4.2× difference, Go wins clearly"
  - "M2 Python wins hours metric but has learning-effect caveat (Go built first; Python benefited from prior art)"
  - "example.com cross-target run skipped — subfinder -max-time 180 (minutes) too long for spike runner; documented as caveat"
  - "NO git commits in this plan — Plan 01-05 commits all spike artifacts at sign-off (D-02)"

patterns-established:
  - "ADR Verdict MUST be one of two exact patterns per RESEARCH.md to avoid Pitfall 5 ambiguity"
  - "Killer-feature gate evaluated before scoring algorithm (B2 fix)"
  - "Timebox compliance (W6 fix) is a killer-feature gate sourced from upstream plan SUMMARYs"

requirements-completed:
  - DEC-03
  - DEC-04

duration: "~5 hours (wall clock including 3 compare.sh runs + stuck run 3 debugging + example.com attempt)"
completed: "2026-05-27"
---

# Phase 1 Plan 4: Comparison + Worksheet + ADR Draft Summary

**Go chosen via DEC-04 noise-band tie-breaker (1-1 split: Python wins M2 hours, Go wins M3 packaging; M1/M5/M6 TIED) — spike/measurement-worksheet.md + .planning/decisions/0001-language.md (Status: Proposed) authored with real measurement data; NO commits in this plan**

## Performance

- **Duration:** ~5 hours wall clock (3 hackerone.com compare.sh runs; run 3 had initial hang resolved by process kill + retry)
- **Started:** 2026-05-27T16:00:00Z (approximate)
- **Completed:** 2026-05-27T20:45:00Z (approximate)
- **Tasks:** 3/3 (Task 1: compare.sh + measurements; Task 2: worksheet; Task 3: ADR draft)
- **Files created:** 4 (comparison.json, .rss_measurements.log, measurement-worksheet.md, 0001-language.md)

## Accomplishments

- Ran compare.sh 3 times against hackerone.com; captured RSS variance (Go CoV=2.2%, Python CoV=1.6% — both conclusive)
- Applied scoring algorithm: 1-1 split (Python M2, Go M3); M1/M5/M6 TIED → NOISE BAND → DEC-04 invoked → **Go chosen**
- Authored spike/measurement-worksheet.md with full audit trail (raw measurements, killer-feature gates, RSS variance, scoring trace, MCP cross-check, final verdict)
- Drafted .planning/decisions/0001-language.md per MADR-influenced template (Status: Proposed; Plan 01-05 signs)

## Task Commits

Per plan specification: NO git commits in Plan 01-04. Plan 01-05 (sign-off ceremony) commits all spike artifacts.

Files written (not committed):
1. `spike/comparison.json` — canonical hackerone.com measurement (4 runs total; last run at 2026-05-27T20:28:03+02:00)
2. `spike/.rss_measurements.log` — 6 lines (go run_1/2/3 + python run_1/2/3)
3. `spike/measurement-worksheet.md` — full scoring trace
4. `.planning/decisions/0001-language.md` — ADR draft (Status: Proposed)

## Metric Summary

| Metric | Go | Python | Ratio | Winner |
|--------|-----|--------|-------|--------|
| M1 LoC (code-only) | 353 | 405 | 1.147 | TIED |
| M2 Hours | 0.417 h | 0.167 h | 2.497 | Python |
| M3 Binary bytes | 3,046,450 | 12,781,568 | 4.196 | Go |
| M4 Kill-tree | PASS | PASS | — | Both pass |
| M5 RSS mean (kB) | 222,251 | 225,301 | 1.014 | TIED |
| M6 X-platform ordinal | 1 | 1 | — | TIED |
| MCP lib support | 1 | 1 | — | Not a tie-breaker |

**Verdict:** Metrics within 25% noise band: tie-breaker INVOKED per DEC-04, choose Go for single-binary distribution win

**Chosen language: Go**

## Killer-Feature Gate Outcomes

| Gate | Go | Python |
|------|-----|--------|
| M4 kill-tree | PASS | PASS |
| M6 cross-platform | 1 | 1 |
| Timebox compliance | true | true |
| **Disposition** | **kept** | **kept** |

No killer-feature override triggered. Both languages cleared all gates. Noise-band scoring ran normally.

## RSS Variance (3 runs)

| Lang | Run 1 | Run 2 | Run 3 | Mean | StDev | CoV |
|------|-------|-------|-------|------|-------|-----|
| Go | 216,576 | 224,912 | 225,264 | 222,251 | 4,918 | 2.2% |
| Python | 227,744 | 226,912 | 221,248 | 225,301 | 3,535 | 1.6% |

Both CoV < 25% — M5 is conclusive. Used mean in scoring algorithm.

## Deviations from Plan

### Deviation 1: Run 3 initial hang (Rule 3 — Blocking)

- **Found during:** Task 1 (RSS variance measurement run 3)
- **Issue:** Run 3 of compare.sh was started as a background job. The Python spike's httpx phase ran for ~2h 47m against 36 subdomains — a clear hang (not a slow run; 50 threads × 10s timeout should complete in <1min for 36 hosts).
- **Fix:** Killed all stuck processes (httpx PID 26581 + parent chain). Re-ran compare.sh directly with `timeout 600 bash compare.sh hackerone.com` — completed in ~2min. Root cause: likely a specific host with a pathological TCP state causing one httpx goroutine to block, holding up the process (even with -threads 50, if one goroutine hangs on connect, others can still run but the process doesn't exit until all goroutines finish).
- **Files affected:** None (compare.sh run; outcome is spike/.rss_measurements.log + comparison.json)
- **Verified:** Run 3 completed, RSS values logged, comparison.json valid

### Deviation 2: example.com cross-target run skipped (caveat)

- **Found during:** Task 1 (cross-target sanity check)
- **Issue:** subfinder uses `-max-time 180` which is 180 minutes, not 180 seconds. example.com subfinder ran for >40 minutes without returning. The `timeout 600` wrapper couldn't kill it because the Python spike uses `setsid` (new process group) — a feature being tested by M4, ironically preventing the timeout from propagating.
- **Fix:** Killed example.com processes. Documented as SKIP in worksheet. Cross-target sanity is advisory per plan; hackerone.com 3-run data is the canonical measurement.
- **Impact:** Minor — advisory check skipped. No effect on verdict.

---

**Total deviations:** 2 (1 blocking hang resolved, 1 advisory check skipped)
**Impact on plan:** No impact on core measurements or verdict. example.com SKIP documented in worksheet caveats.

## DEC-01 through DEC-05 Self-Review

- **DEC-01:** ADR file exists at `.planning/decisions/0001-language.md` with Status: Proposed; Plan 01-05 signs ✓
- **DEC-02:** ADR §Measurement names the slice: 4 sources (subfinder, crt, github-subdomains, gitlab-subdomains) + httpx probe (locked 8-flag set) + atomic JSONL writes + SIGINT kill-tree test ✓
- **DEC-03:** ADR §Measurement table has all 7 rows (M1-M6 + MCP) with real numeric data ✓
- **DEC-04:** ADR §Tie-breaker says "Invoked: YES" with 1-paragraph rationale referencing noise-band finding ✓
- **DEC-05:** ADR §References + footer note documents Plan 01-05 D-03 collapse responsibility ✓

## Known Stubs

None. All measurement values in worksheet and ADR are real numeric data from actual spike runs.

## Issues Encountered

- Run 3 background job hung (see Deviations). Resolved by killing and re-running.
- tokei not installed on dev machine — M1 LoC uses manual wc-l counts from plan SUMMARYs (documented caveat in worksheet).
- Python .venv gitignored — M3a venv size taken from 01-03-SUMMARY.md (documented caveat in worksheet).
- comparison.json has null for `.go.loc` and `.python.loc` (tokei unavailable) — M1 sourced from SUMMARYs.

## Next Phase Readiness

Plan 01-05 (ADR sign-off ceremony, same-day per D-02) can proceed immediately:
- `.planning/decisions/0001-language.md` at Status: Proposed — ready for sign-off
- `spike/measurement-worksheet.md` complete — source of truth for measurements
- `spike/comparison.json` and `spike/.rss_measurements.log` ready to commit
- D-03 research-file collapse (remove Python from STACK/ARCHITECTURE/SUMMARY/PITFALLS) is Plan 01-05's responsibility

---
*Phase: 01-language-adr-spike*
*Plan: 04*
*Completed: 2026-05-27*
*Note: NO commits made in this plan per plan specification. Plan 01-05 commits all spike artifacts.*
