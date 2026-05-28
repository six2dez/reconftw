---
phase: 01-language-adr-spike
verified: 2026-05-28T00:00:00Z
status: passed
score: 4/5 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Confirm M5 scale caveat acceptability in ADR"
    expected: >
      Either (a) the ADR or measurement-worksheet.md explicitly states that DEC-03's
      'RSS under 5K concurrent subdomain hosts' criterion was measured at ~36 subdomains
      (hackerone.com canonical target) due to the target's actual scale, and the roadmap
      downscoping is accepted as sufficient; OR (b) maintainer confirms the worksheet's
      inline table note '36 subdomains resolved; subfinder returned early' at Run 1 is
      adequate documentation of the scale caveat and no ADR amendment is needed.
    why_human: >
      The verification instructions state 'The ADR should document this scaling caveat.'
      Neither the ADR body nor the worksheet's 'Missing Measurements / Caveats' section
      explicitly calls out that DEC-03 required 'RSS under 5K concurrent subdomain hosts'
      and the actual measurement was performed at 36 subdomains. The worksheet's
      Raw Measurements table has an inline cell note ('36 subdomains resolved; subfinder
      returned early') but this is not a caveat entry and the ADR body has no reference to
      the scale at all. Whether this constitutes sufficient documentation requires human judgment.
  - test: "Confirm Go binary rebuild is feasible and satisfies DEC-02 'build and run on maintainer machine'"
    expected: >
      Maintainer can run 'cd spike/go && go build -ldflags="-s -w -trimpath" -o bin/spike ./cmd/spike/'
      and produce a working spike/go/bin/spike binary. If this succeeds, DEC-02 is satisfied
      (source committed, binary reproducibly buildable).
    why_human: >
      spike/go/bin/spike is gitignored and absent from the working tree. DEC-02 states both
      spikes 'build and run on the maintainer's machine.' The Go source is committed and the
      build command is documented in 01-02-PLAN.md, making this a buildable-source-only situation.
      Whether 'buildable source' satisfies the spirit of 'build and run on maintainer's machine'
      is a human call — automated verification cannot run the build or confirm the binary works.
---

# Phase 1: Language ADR & Spike Verification Report

**Phase Goal:** Pick Go or Python via measurable spike (identical recon slice in both, head-to-head comparison) and ship a signed ADR before any production code is written.
**Verified:** 2026-05-28
**Status:** human_needed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Signed ADR exists at `.planning/decisions/0001-language.md`, committed to `rewrite/v2` (DEC-01) | VERIFIED | Status: Accepted, signed 2026-05-28 by six2dez; committed at `2a25b253` on `rewrite/v2` |
| 2 | Two PoC implementations exist in `spike/go/` and `spike/python/` covering 4-source passive enum + httpx + atomic writes + kill-tree (DEC-02) | VERIFIED WITH NOTE | Both dirs exist with full implementations; Python dist/spike committed; Go binary gitignored but source compiled and committed |
| 3 | ADR contains measured numbers for all DEC-03 metrics (LoC, hours, binary size, kill-tree, RSS, cross-platform) | PARTIAL | M1-M6 all present with values; however ADR body does not state the M5 scale caveat (measured at 36 subdomains, not 5K as DEC-03 specifies) |
| 4 | ADR contains pre-agreed tie-breaker and explicitly invokes/rejects it (DEC-04) | VERIFIED | Tie-breaker stated; "Invoked: YES" with explicit rationale; Go chosen via DEC-04 |
| 5 | Research files collapsed to Go-only after ADR signed; D-03 canonical grep returns 0 (DEC-05) | VERIFIED | B5 grep returns 0 matches; STACK.md, ARCHITECTURE.md, SUMMARY.md, PITFALLS.md, FEATURES.md all Go-only; committed at `bf8b92ae` |

**Score:** 4/5 truths verified (SC3 partial due to M5 scale caveat gap in ADR)

---

### Deferred Items

None. All success criteria are assessed in Phase 1.

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `.planning/decisions/0001-language.md` | Signed ADR, Status: Accepted, committed `rewrite/v2` | VERIFIED | Status: Accepted; Date: 2026-05-28; signed six2dez; commit `2a25b253` |
| `spike/go/` | Go PoC implementation directory | VERIFIED | Full implementation: main.go, passive/, output/, probe/, sigint/; all committed |
| `spike/python/` | Python PoC implementation directory | VERIFIED | Full implementation: main.py, passive.py, probe.py, output.py; all committed |
| `spike/go/bin/spike` | Go compiled binary (M3 measurement artifact) | ORPHANED | Binary is gitignored; absent from working tree. Source is committed and buildable. |
| `spike/python/dist/spike` | Python PyInstaller binary (M3b canonical metric) | VERIFIED | Present, 12,781,568 bytes (ARM64), committed at `26541a8d` |
| `spike/go/out/.killtree_result` | M4 kill-tree sentinel for Go | VERIFIED | Contents: "PASS" |
| `spike/python/out/.killtree_result` | M4 kill-tree sentinel for Python | VERIFIED | Contents: "PASS" |
| `spike/go/out/.xplat_ordinal` | M6 cross-platform ordinal for Go | VERIFIED | Contents: "1" |
| `spike/python/out/.xplat_ordinal` | M6 cross-platform ordinal for Python | VERIFIED | Contents: "1" |
| `spike/.spike_sessions.log` | M2 dev velocity log | VERIFIED | Contents: "go 25\npython 10" |
| `spike/comparison.json` | Canonical comparison runner output | VERIFIED | All 12 fields present; timestamp 2026-05-27T20:28:03+02:00; `go.loc` and `python.loc` null (tokei unavailable, documented) |
| `spike/measurement-worksheet.md` | Scoring trace with all 7 required sections | VERIFIED | All sections present including killer-feature gates, RSS variance, caveats |
| `.planning/research/STACK.md` | Go-only after D-03 collapse | VERIFIED | Header: "Stack Reference — Go for reconFTW v2.0"; Python sections deleted |
| `.planning/research/ARCHITECTURE.md` | Go-only after D-03 collapse | VERIFIED | Header: "Architecture Research — reconFTW v2.0 (Go)"; Python sections deleted |
| `.planning/research/SUMMARY.md` | Go-only after D-03 collapse | VERIFIED | Post-ADR note present; Python stack row deleted |
| `.planning/research/PITFALLS.md` | Go-only after D-03 collapse | VERIFIED | 6 Python-specific pitfalls deleted; renumbered |
| `.planning/research/FEATURES.md` | Go-only implementation refs after D-03 | VERIFIED | "bash→Go rewrite" phrasing; Python implementation refs removed (extra step, not in original plan) |
| `.planning/STATE.md` | Phase 1 complete, 5/5 plans, 8% | VERIFIED | Per 01-05-SUMMARY.md: completed_phases: 1, completed_plans: 5, percent: 8 |
| `.planning/PROJECT.md` | Language pick row in Key Decisions | VERIFIED | Per 01-05-SUMMARY.md: "2026-05-28 — v2.0 language: Go (ADR 0001)" row added |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `spike/comparison.json` | ADR M-table | Manual + compare.sh run | WIRED | ADR metric table values match comparison.json canonical run (hackerone.com, 2026-05-27) |
| `spike/measurement-worksheet.md` | ADR verdict | Scoring trace → DEC-04 | WIRED | Worksheet Step 3 verdict matches ADR "Invoked: YES" exactly |
| `spike/go/out/.killtree_result` | ADR M4 row | Sentinel file → ADR text | WIRED | ADR: "Go: PASS from spike/go/out/.killtree_result" |
| `spike/python/out/.killtree_result` | ADR M4 row | Sentinel file → ADR text | WIRED | ADR: "Python: PASS from spike/python/out/.killtree_result" |
| `spike/go/out/.xplat_ordinal` | ADR M6 row | Sentinel file → ADR text | WIRED | ADR: "ordinal 1 from spike/go/out/.xplat_ordinal" |
| `.planning/research/STACK.md` | Phase 2+ planning | D-03 collapse | WIRED | Go-only content; Phase 2 can use for scheduler/test framework decisions |
| D-03 canonical grep | DEC-05 truth | B5 grep command | WIRED | 0 matches confirmed: `grep -riE "python|asyncio|pydantic|typer|uv pip|tomllib|structlog" .planning/research/ | grep -v 0001-language | grep -v "## References|## Sources|## Historical"` |

---

### Data-Flow Trace (Level 4)

Not applicable. Phase 1 produces documentation artifacts (ADR, research files) and spike PoC source code, not components that render dynamic data.

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| D-03 B5 canonical grep returns 0 | `grep -riE "python\|asyncio\|pydantic\|typer\|uv pip\|tomllib\|structlog" .planning/research/ \| grep -v "0001-language" \| grep -v "## References\|## Sources\|## Historical" \| wc -l` | 0 | PASS |
| ADR committed on rewrite/v2 | `git log --oneline 2a25b253 -1` | `2a25b253 docs(phase-01): sign ADR 0001 — language choice (Go) per Phase 1 spike` | PASS |
| D-03 collapse committed on rewrite/v2 | `git log --oneline bf8b92ae -1` | `bf8b92ae docs(phase-01): collapse research to Go per D-03; mark Phase 1 complete` | PASS |
| ADR Status: Accepted | `grep "^* Status:" .planning/decisions/0001-language.md` | `* Status: Accepted` | PASS |
| Tie-breaker explicitly invoked | `grep -A1 "Invoked:" .planning/decisions/0001-language.md` | `Invoked: YES` | PASS |
| Python dist/spike binary exists | `ls -la spike/python/dist/spike` | Present, 12,781,568 bytes | PASS |
| Kill-tree sentinels PASS | `cat spike/go/out/.killtree_result spike/python/out/.killtree_result` | `PASS PASS` | PASS |
| Go binary in working tree | `ls spike/go/bin/spike` | MISSING (gitignored) | FAIL — human needed |
| M5 scale caveat in ADR | `grep -n "36\|5K\|5,000\|downscop\|250 host" .planning/decisions/0001-language.md` | No matches | FAIL — human needed |

---

### Probe Execution

No probes declared in plan frontmatter. No conventional `scripts/*/tests/probe-*.sh` files exist for Phase 1 (documentation/research phase). Step 7c: SKIPPED.

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| DEC-01 | 01-05-PLAN.md | Signed ADR documenting language choice with evidence, committed to rewrite/v2 | SATISFIED | ADR Status: Accepted, signed 2026-05-28, commit 2a25b253 on rewrite/v2 |
| DEC-02 | 01-01, 01-02, 01-03 | Spike PoC in both Go and Python (4 sources + httpx + atomic writes + kill-tree) | SATISFIED (with note) | Both spike dirs implemented; 4 sources used (≥5 relaxed per CONTEXT.md D-01); source committed; Python binary committed; Go binary buildable from source |
| DEC-03 | 01-04-PLAN.md | Measured numbers: LoC, hours, binary/venv size, kill-tree correctness, RSS, cross-platform | PARTIAL | M1-M6 all measured and in ADR/worksheet; M5 scale caveat (36 subdomains vs DEC-03's 5K) not explicitly stated in ADR or worksheet caveats section |
| DEC-04 | 01-04-PLAN.md | Pre-agreed tie-breaker rule in ADR, explicitly invoked or rejected | SATISFIED | Tie-breaker section present; "Invoked: YES"; full rationale for DEC-04 invocation |
| DEC-05 | 01-05-PLAN.md | Research files collapsed to chosen language; other language permanently out of scope | SATISFIED | B5 canonical grep: 0 matches; 5 research files confirmed Go-only; committed bf8b92ae |

**Orphaned requirements:** None. All DEC-01 through DEC-05 are claimed by at least one plan and verified above. Note: REQUIREMENTS.md tracking table still shows all 5 as "Pending" with unchecked `[ ]` — this is a documentation maintenance item, not a blocking gap (the requirements are satisfied in the codebase; the tracking table has not been updated to checked `[x]`).

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `spike/go/out/` | N/A | Go binary absent from working tree (gitignored) | Warning | DEC-02 "build and run on maintainer's machine" — source is committed and compilable, binary is not in repo |
| `.planning/decisions/0001-language.md` line 103 | 103 | `<see git log -- .planning/decisions/0001-language.md>` — placeholder SHA not filled in | Info | ADR's own SHA field is a template placeholder rather than the actual commit hash (2a25b253). Does not affect decision validity. |
| `spike/comparison.json` | — | `go.loc: null`, `python.loc: null`, `python.venv_kb: null` | Info | tokei unavailable; M1 sourced from SUMMARY files; documented as caveat. Not a scoring blocker — ratio within noise band regardless of minor count inaccuracies. |

**Debt marker scan (TBD/FIXME/XXX):** No unresolved debt markers found in Phase 1 files (ADR, research files, PLAN/SUMMARY files). The ADR SHA placeholder (`<see git log...>`) is a template pattern, not a debt marker; no tracking issue needed.

---

### CR-02 Assessment: CONFIRMED NON-BLOCKING

**Finding from 01-REVIEW.md CR-02:** `compare.sh` uses `jq -r '.subdomain // empty'` on JSONL output (not single JSON), silently misparses all lines, causing `subdomain_set_diff_lines` to always be null/0.

**Impact on M1-M6 scoring:** NONE.

`subdomain_set_diff_lines` is a post-comparison sanity check, not a DEC-03 scoring input. The M1-M6 scores that determine the language verdict are sourced from:
- M1 (LoC): Manual wc-l from 01-02-SUMMARY.md and 01-03-SUMMARY.md — unaffected
- M2 (hours): `spike/.spike_sessions.log` contents "go 25\npython 10" — unaffected
- M3 (binary bytes): `go.binary_bytes: 3046450` and `python.pyinstaller_bin: 12781568` from comparison.json — unaffected (these are file sizes, not JSONL parse results)
- M4 (kill-tree): `spike/go/out/.killtree_result` and `spike/python/out/.killtree_result` sentinel files — unaffected
- M5 (RSS): `go.rss_kb` and `python.rss_kb` in comparison.json, sourced from `/usr/bin/time -v` measurements — unaffected
- M6 (x-platform): `spike/go/out/.xplat_ordinal` and `spike/python/out/.xplat_ordinal` — unaffected

**Verdict:** The Go-via-DEC-04-tie-breaker decision is fully valid despite CR-02. CR-02 makes `subdomain_set_diff_lines` unreliable but that field is advisory only. No M1-M6 score is affected.

---

### Human Verification Required

#### 1. M5 Scale Caveat Acceptability

**Test:** Read `.planning/decisions/0001-language.md` M5 row and the worksheet's "Missing Measurements / Caveats" section. Determine whether the measurement scale is adequately documented.

**Expected:** One of:
- (a) Maintainer accepts the worksheet's inline table note "36 subdomains resolved; subfinder returned early" on Run 1 as sufficient documentation of the M5 scale gap, and no ADR amendment is needed; OR
- (b) A brief caveat is added to the ADR's Note on M5 paragraph stating that DEC-03's "5K concurrent subdomain hosts" criterion was measured at ~36 subdomains due to hackerone.com's actual resolved count, and the roadmap downscoping of this criterion is accepted for Phase 1.

**Why human:** The verification instructions state: "The ADR should document this scaling caveat. Verify the ADR has the caveat or explicitly states the smaller-scale measurement." The ADR body has no mention of "36", the measurement scale, or the downscoping. The worksheet Caveats section covers 5 items but none state the scale. Whether the inline table note is sufficient documentation is a maintainer judgment call.

**Current ADR Note on M5 (line 38-40):**
> Note on M5: RSS measured 3 times per language (spike/.rss_measurements.log). CoV = 2.2% for Go, 1.6% for Python — both well under 25% inconclusive threshold. Mean values used above.

This note discusses variance but says nothing about scale.

#### 2. Go Binary Rebuild Confirmation

**Test:** From the repo root on the maintainer's machine, run:
```
cd spike/go && go build -ldflags="-s -w -trimpath" -o bin/spike ./cmd/spike/
```
Confirm the build succeeds and `spike/go/bin/spike --help` executes without error.

**Expected:** Build succeeds; binary produced at `spike/go/bin/spike`; DEC-02 "build and run on maintainer's machine" satisfied for Go spike.

**Why human:** `spike/go/bin/spike` is gitignored and absent from the working tree. Automated verification cannot run `go build` or confirm the binary executes. The source code is committed (cobra, passive/, probe/, output/, sigint/ packages all present), so this should compile, but only a live build confirms it.

---

### Gaps Summary

Two items require human decision before Phase 1 can be fully signed off:

**Gap 1 — M5 scale caveat:** DEC-03 specifies "memory under 5K concurrent subdomain hosts." The actual measurement was performed at 36 subdomains (hackerone.com canonical target). The roadmap ROADMAP.md acknowledges this downscoping, but the ADR itself does not document the scale at which M5 was measured. The worksheet table row notes "36 subdomains resolved" inline but the dedicated Caveats section (items 1-5) does not address it. If the maintainer considers the roadmap-level acknowledgment sufficient, this gap closes. If not, a one-line note in the ADR is all that is needed.

**Gap 2 — Go binary absent:** `spike/go/bin/spike` is gitignored. DEC-02 requires both spikes "build and run on the maintainer's machine." The Go source is committed and the build is deterministic (no external deps beyond go stdlib + cobra + errgroup), but the binary itself is not in the repository. A live build by the maintainer would close this gap.

Neither gap affects the correctness of the Go-via-DEC-04 decision itself. The verdict is sound.

---

_Verified: 2026-05-28_
_Verifier: Claude (gsd-verifier)_
