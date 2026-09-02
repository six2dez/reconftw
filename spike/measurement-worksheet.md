# Spike Comparison Measurement Worksheet

**Date:** 2026-05-27
**Canonical target:** example.com
**Phase:** 1 — Language ADR & Spike
**Source data:** spike/comparison.json (commit will be created by Plan 01-05)

## Raw Measurements

### Per-target run results

| Target | Go RSS (kB) | Python RSS (kB) | Notes |
|--------|-------------|-----------------|-------|
| example.com run 1 | 216,576 | 227,744 | 36 subdomains resolved; subfinder returned early |
| example.com run 2 | 224,912 | 226,912 | Same target; slight variation in subprocess timing |
| example.com run 3 | 225,264 | 221,248 | Same target; Python lower than Go on this run |
| **example.com MEDIAN** | **224,912** | **226,912** | Used in M5 row below; mean also computed in §RSS Variance Analysis |
| example.com | SKIP | SKIP | subfinder ran >40 min against example.com without returning (Pitfall: -max-time 180 is minutes, not seconds; real domain took too long for spike runner). Advisory cross-target run omitted. |
| controlled-lab.test | SKIP | SKIP | No maintainer-controlled DNS target available; skipped per plan. |

### Killer-Feature Gate (B2 + W6 fixes per cross-AI review)

| Gate | Go | Python |
|------|-----|--------|
| M4 kill-tree result | PASS | PASS |
| M6 cross-platform ordinal | 1 | 1 |
| Timebox compliance (D-01: 1 week per lang) | true (01-02-SUMMARY.md: timebox_complete: true) | true (01-03-SUMMARY.md: timebox_complete: true) |
| **Disposition** | **kept** | **kept** |

A `FAIL` on M4, an ordinal of `3` on M6, or `false` on timebox compliance triggers killer-feature override per RESEARCH.md §2.3 + B2/W6 fixes:
- `go.timebox_complete` sourced from `.planning/phases/01-language-adr-spike/01-02-SUMMARY.md`: `timebox_complete: true`
- `python.timebox_complete` sourced from `.planning/phases/01-language-adr-spike/01-03-SUMMARY.md`: `timebox_complete: true`

**Outcome:** Both languages cleared all killer-feature gates → noise-band scoring runs

## RSS Variance Analysis (W2 fix per cross-AI review)

Data sourced from `spike/.rss_measurements.log` (3 runs captured in Task 1 step 4).

| Lang | Run 1 | Run 2 | Run 3 | Mean | StDev | CoV | Inconclusive flag (CoV > 25%) |
|------|-------|-------|-------|------|-------|-----|-------------------------------|
| Go | 216,576 | 224,912 | 225,264 | 222,251 | 4,918 | 2.2% | no |
| Python | 227,744 | 226,912 | 221,248 | 225,301 | 3,535 | 1.6% | no |

Computation (awk on spike/.rss_measurements.log):
```
go     n=3 mean=222251 stdev=4918 cov=2.2%
python n=3 mean=225301 stdev=3535 cov=1.6%
```

Both CoV values are well under 25% — M5 is conclusive. The mean values will be used in §Scoring Algorithm Step 1.

**Observation on run variance:** Go run 1 is notably lower (216,576 vs 224-225k) — likely cold-start effect (OS page cache not yet warm for this binary invocation). Runs 2 and 3 are consistent. Python runs are tightly clustered (221-228k range). Neither pattern triggers the inconclusive flag.

## Scoring Algorithm (RESEARCH.md §2.2)

Killer-feature override log does NOT exist (`spike/.killer_feature_override.log` absent) — proceeding with noise-band scoring.

### Step 1: Per-metric numeric comparison (M1, M2, M3, M5)

For each metric, ratio = max(go, python) / min(go, python). If ratio < 1.25 → TIED. Else lang with smaller (better) value wins.

| Metric | Go | Python | Ratio | TIED? | Winner |
|--------|----|--------|-------|-------|--------|
| M1 LoC (code-only, excl tests) | 353 | 405 | 1.147 | yes | — |
| M2 Hours (dev velocity) | 0.417 | 0.167 | 2.497 | no | Python |
| M3 Packaging (single-binary bytes) | 3,046,450 | 12,781,568 | 4.196 | no | Go |
| M5 RSS mean (kB) | 222,251 | 225,301 | 1.014 | yes | — |

**M1 notes:** Manual wc-l count (tokei/cloc not installed on dev machine). Go: ~353 lines code-only (excl tests, comments, blanks). Python: ~405 lines code-only. Per RESEARCH.md Pitfall 2: Python was written after Go — the 10-min session log suggests a learning effect on the second spike lowered development time but didn't substantially reduce LoC. The 14.7% LoC difference is within noise band.

**M2 notes:** Go: 25 min (0.417 h), Python: 10 min (0.167 h). Ratio 2.5x — Python appears faster. However, RESEARCH.md Pitfall 2 applies: the Go spike was built first; the Python spike benefited from the prior art of having the Go slice as a reference implementation. This order effect likely inflates Python's apparent velocity advantage. Even accounting for the caveat, Python's win here is real for ratio-based scoring; the ratio exceeds 1.25, so it scores as a Python win. Documented for transparency.

**M3 notes:** Go stripped binary (3.0 MB, `-s -w -trimpath`, ARM64) vs Python PyInstaller --onefile (12.2 MB, ARM64). Per OQ3 INCLUDE, the PyInstaller binary is the canonical M3b measurement target — shape-parity with Go's single binary. The Python `.venv` install size (28,104 kB = 27.5 MB) is recorded as reference M3a only; it is NOT the apples-to-apples metric for this comparison. Go binary is 4.2× smaller than Python's PyInstaller binary — clear Go win.

**M5 notes:** Using mean of 3 runs (CoV < 5% for both — highly stable). Go mean 222,251 kB, Python mean 225,301 kB — 1.4% difference. Clearly within 25% noise band. TIED.

### Step 2: Ordinal metric (M6)

| Lang | M6 ordinal | Notes |
|------|-----------|-------|
| Go | 1 | macOS arm64 Darwin 25.5.0; `go mod init + go get + go build + make test` all passed first try. One correctness fix (process-group SIGKILL goroutine) is cross-platform, not macOS-specific — rating stays 1. Source: spike/go/out/.xplat_notes |
| Python | 1 | macOS arm64 Darwin 25.5.0; `uv venv + uv sync + PyInstaller --onefile + pytest` all passed first try. Minor Makefile fix (--timeout=60 pytest flag not needed) is tooling cleanup, not cross-platform issue — rating stays 1. Source: spike/python/out/.xplat_notes |

Winner: TIED (both ordinal 1)

### Step 3: Aggregate count

- Go won: 1 of 4 non-tied numeric metrics (M3 Packaging)
- Python won: 1 of 4 non-tied numeric metrics (M2 Hours)
- TIED on: M1 (LoC ratio 1.147), M5 (RSS ratio 1.014), M6 (both ordinal 1)

**Outcome:** NOISE_BAND — 1-1 split on non-tied metrics (all others tied). Tie-breaker INVOKED per DEC-04.

### Step 4: Tie-breaker application (DEC-04 — NOISE_BAND)

DEC-04 default rule: "Choose Go if metrics within 25% noise band — single-binary distribution wins."

- Applied: **YES**
- Rationale: Three of five non-binary metrics are within the 25% noise band (M1=1.147, M5=1.014, M6=tied). The two metrics that do differentiate (M2 and M3) split evenly 1-1. Since no language achieves ≥3 wins of the 4 non-tied metrics, the aggregate is inconclusive. DEC-04 was established precisely for this outcome: reconFTW's clearest packaging-story improvement for v2.0 is moving from a bash script that requires 70+ installed tools to a single deployable binary. Go's 3.0 MB stripped binary ships anywhere with zero runtime dependencies; Python's PyInstaller binary (12.2 MB) requires either PyInstaller distribution or a venv per STACK.md §9. Go wins on noise band.

## MCP Cross-check (RESEARCH.md §5 — Resolved)

Both Go and Python have v1.x stable official MCP SDKs:
- Python: `pypi:mcp` (Anthropic, v1.x stable since Q1 2025; 97M+ monthly downloads; de-facto reference implementation)
- Go: `github.com/modelcontextprotocol/go-sdk` v1.6.1 (Anthropic + Google, May 22 2026; supports 4 protocol versions)

**MCP support score:** Go=1, Python=1 (both = "official SDK at v1.x stable" per RESEARCH.md §5).

**Conclusion:** MCP is NOT a tie-breaker signal. Both languages are production-ready for Phase 8 MCP work. Recorded in the ADR Measurement table for completeness but does not factor into the verdict.

## Final Verdict

Chosen language: **Go**

Verdict statement (copy verbatim into ADR Verdict section):
> Metrics within 25% noise band: tie-breaker INVOKED per DEC-04, choose Go for single-binary distribution win

**Evidence summary:**
- M1 LoC: TIED (1.147 ratio — 353 vs 405 lines)
- M2 Hours: Python wins (0.42h vs 0.17h — caveat: learning-effect on second spike)
- M3 Packaging: Go wins (3.0 MB vs 12.2 MB binary — 4.2× smaller)
- M4 Kill-tree: Both PASS — not a differentiator
- M5 RSS: TIED (222,251 kB vs 225,301 kB — 1.4% difference)
- M6 X-platform: TIED (both ordinal 1 — first try on macOS arm64)
- MCP: TIED (both v1.x stable — not a tie-breaker)
- **1-1 split on non-tied metrics → NOISE BAND → DEC-04 invoked → Go chosen**

## Missing Measurements / Caveats

1. **M1 LoC (tokei unavailable):** tokei and cloc were not installed on the dev machine. M1 counts are manual `wc -l` approximations (code-only, excluding tests, comments, blank lines): Go ≈353, Python ≈405. These numbers come directly from the 01-02-SUMMARY.md and 01-03-SUMMARY.md DEC-03 tables. The 14.7% ratio is well within the 25% noise band regardless of minor count inaccuracies.

2. **M3 Python venv (gitignored):** The Python `.venv` directory is gitignored and was not present in the execution worktree. M3a venv size (28,104 kB) is taken from 01-03-SUMMARY.md directly. This does not affect the M3 comparison — the canonical metric is M3b PyInstaller binary (12,781,568 bytes), which is committed in git and present at `spike/python/dist/spike`.

3. **example.com cross-target sanity:** The example.com run was attempted but subfinder's `-max-time 180` (180 minutes) caused the run to take >40 minutes without returning results. The cross-target run is advisory per the plan; example.com's 3-run M5 data is the canonical measurement. The example.com and controlled-lab.test sanity checks are documented as SKIP.

4. **M2 learning effect (Pitfall 2):** Python was built after Go; the 10-min session log reflects working with the Go implementation as prior art. The actual difficulty ratio for a fresh developer writing Python first would likely be different. This caveat is noted but does not change the scoring — M2 ratio exceeds 1.25, so Python scores the win regardless.

5. **comparison.json loc fields null:** tokei not installed; `go.loc` and `python.loc` in comparison.json are null. M1 values are taken from plan SUMMARYs (01-02 and 01-03) as documented above.

## Audit trail

- `spike/comparison.json` (will be committed by Plan 01-05) — final canonical run: example.com, timestamp 2026-05-27T20:28:03+02:00
- `spike/.rss_measurements.log` (will be committed by Plan 01-05) — 6 lines (3 runs × 2 langs)
- `spike/comparison.example.com.json` — SKIP (example.com run timed out, advisory only)
- `.planning/phases/01-language-adr-spike/01-02-SUMMARY.md` — Go spike disposition (timebox_complete: true)
- `.planning/phases/01-language-adr-spike/01-03-SUMMARY.md` — Python spike disposition (timebox_complete: true)
- `.planning/research/SUMMARY.md` §Build Order, §Stack Snapshot
- `.planning/research/STACK.md` — 14-dimension Go-vs-Python stack (verified May 2026 versions)
